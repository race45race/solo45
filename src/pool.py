#!/usr/bin/env python3
"""Solo45 Pool - a small solo-mining Stratum v1 pool for one bitcoind.

Standard library only. It builds work from getblocktemplate, checks every
share, and submits found blocks straight to the node. Every new job is also
run through getblocktemplate "proposal" mode, so a malformed coinbase or
merkle tree shows up within seconds instead of on the day a block is found.
"""
import asyncio
import base64
import collections
import hashlib
import hmac
import itertools
import json
import logging
import logging.handlers
import os
import random
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import policy
import stallguard

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("SOLO45_DATA_DIR") or HERE  # config.json, state.json and logs
DIFF1 = 0xFFFF << 208
VERSION_MASK = 0x1FFFE000
MAX_DIFF = 1e9  # same ceiling as the per-miner settings
EN1_SIZE, EN2_SIZE = 4, 8
CHECK_SPK = b"\x00\x20" + bytes(32)  # stand-in payout script for block checks before a payout address is set

DEFAULTS = {
    "stratum_port": 3333,
    "api_port": 3380,
    "rpc_url": "http://127.0.0.1:8332/",
    "rpc_cookie": "~/umbrel/app-data/bitcoin/data/bitcoin/.cookie",
    "rpc_user": "",  # when set, used instead of the cookie file
    "rpc_pass": "",
    "default_address": "",
    "force_default_address": False,  # ignore addresses in miner usernames
    "coinbase_tag": "Solo45",
    "start_diff": 10000,
    "min_diff": 256,
    "share_seconds": 5,  # vardiff aims for one share per miner every N seconds
    "block_poll_ms": 100,
    "template_refresh_s": 30,
    "stall_guard_s": 60,  # disconnect a peer that holds up a new block this long (0 = off)
}

log = logging.getLogger("pool")


# ---------------------------------------------------------------- bitcoin bits

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def script_num(n):
    """CScriptNum encoding, used for the BIP34 height in the coinbase."""
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out and out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def push(data):
    assert len(data) < 76
    return bytes([len(data)]) + data


def bits_to_target(bits):
    return (bits & 0xFFFFFF) << (8 * ((bits >> 24) - 3))


def merkle_branch(txids):
    """Stratum merkle branch for the coinbase (index 0). txids in internal byte order."""
    branch, level = [], [None] + list(txids)
    while len(level) > 1:
        branch.append(level[1])
        if len(level) % 2:
            level.append(level[-1])
        level = [None] + [sha256d(level[i] + level[i + 1]) for i in range(2, len(level), 2)]
    return branch


def stratum_prevhash(prev_internal):
    return b"".join(prev_internal[i:i + 4][::-1] for i in range(0, 32, 4)).hex()


# ------------------------------------------------------------------------- rpc

class RPCError(Exception):
    pass


class RPC:
    def __init__(self, url, cookie_path, user="", password=""):
        self.url = url
        self.cookie_path = os.path.expanduser(cookie_path)
        self.user, self.password = user, password
        self.auth = None

    def _load_auth(self):
        if self.user:
            self.auth = "Basic " + base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
            return
        with open(self.cookie_path) as f:
            self.auth = "Basic " + base64.b64encode(f.read().strip().encode()).decode()

    def call(self, method, *params, timeout=15):
        if self.auth is None:
            self._load_auth()
        body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}).encode()
        for attempt in (0, 1):
            req = urllib.request.Request(self.url, body, {"Content-Type": "text/plain", "Authorization": self.auth})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    reply = json.load(r)
                break
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    self._load_auth()  # bitcoind writes a new cookie on every restart
                    continue
                try:
                    reply = json.load(e)
                except ValueError:
                    raise RPCError("HTTP %d" % e.code)
                break
        if reply.get("error"):
            raise RPCError(reply["error"])
        return reply["result"]


# ------------------------------------------------------------------------- job

class Job:
    def __init__(self, job_id, tpl, tag):
        self.id = job_id
        self.height = tpl["height"]
        self.prev_hex = tpl["previousblockhash"]
        self.prev = bytes.fromhex(self.prev_hex)[::-1]
        self.version = tpl["version"] & 0xFFFFFFFF
        self.bits = int(tpl["bits"], 16)
        self.target = bits_to_target(self.bits)
        self.curtime = tpl["curtime"]
        self.mintime = tpl["mintime"]
        self.value = tpl["coinbasevalue"]
        wc = tpl.get("default_witness_commitment")
        self.witness_commitment = bytes.fromhex(wc) if wc else None
        self.tx_data = [bytes.fromhex(t["data"]) for t in tpl["transactions"]]
        self.fees = sum(t.get("fee", 0) for t in tpl["transactions"])
        self.branch = merkle_branch([bytes.fromhex(t["txid"])[::-1] for t in tpl["transactions"]])
        script = push(script_num(self.height)) + push(tag)
        self.coinb1 = (struct.pack("<I", 2) + b"\x01" + b"\x00" * 32 + b"\xff" * 4
                       + varint(len(script) + 1 + EN1_SIZE + EN2_SIZE) + script
                       + bytes([EN1_SIZE + EN2_SIZE]))
        self._coinb2 = {}
        self.created = time.time()
        self.seen = set()
        self.notify_base = [self.id, stratum_prevhash(self.prev), self.coinb1.hex(), None,
                            [b.hex() for b in self.branch], "%08x" % self.version,
                            "%08x" % self.bits, "%08x" % self.curtime]

    def coinb2(self, spk):
        if spk not in self._coinb2:
            outs = [struct.pack("<q", self.value) + varint(len(spk)) + spk]
            if self.witness_commitment:
                wc = self.witness_commitment
                outs.append(struct.pack("<q", 0) + varint(len(wc)) + wc)
            self._coinb2[spk] = b"\xff" * 4 + varint(len(outs)) + b"".join(outs) + b"\x00" * 4
        return self._coinb2[spk]

    def notify_params(self, spk, clean):
        params = list(self.notify_base)
        params[3] = self.coinb2(spk).hex()
        params.append(clean)
        return params

    def header(self, coinbase, version, ntime, nonce):
        root = sha256d(coinbase)
        for h in self.branch:
            root = sha256d(root + h)
        return struct.pack("<I", version) + self.prev + root + struct.pack("<III", ntime, self.bits, nonce)

    def block(self, header, coinbase):
        if self.witness_commitment:
            # a segwit coinbase carries one witness item: the 32-byte zero reserved value
            coinbase = coinbase[:4] + b"\x00\x01" + coinbase[4:-4] + b"\x01\x20" + b"\x00" * 32 + coinbase[-4:]
        return header + varint(1 + len(self.tx_data)) + coinbase + b"".join(self.tx_data)


# ---------------------------------------------------------------------- worker

class StratumError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def fmt_diff(d):
    for unit, size in (("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if d >= size:
            return "%.3g%s" % (d / size, unit)
    return "%.3g" % d


def hashrate(shares, window, now):
    total = sum(d for t, d in shares if t > now - window)
    return total * 2 ** 32 / window


class Worker:
    """One stratum connection."""

    def __init__(self, pool, reader, writer):
        self.pool, self.reader, self.writer = pool, reader, writer
        peer = writer.get_extra_info("peername") or ("?", 0)
        self.ip = peer[0]
        self.en1 = pool.next_extranonce1()
        self.diff = pool.cfg["start_diff"]
        self.remembered = False  # started at the difficulty remembered from its last connection
        self.job_diff = {}
        self.subscribed = self.authorized = False
        self.user = self.name = self.address = self.agent = ""
        self.spk = None
        self.connected = time.time()
        self.last_share = 0
        self.accepted = 0
        self.rejected = collections.Counter()
        self.best = 0.0
        self.shares = collections.deque()
        self.vd_start, self.vd_count, self.vd_work = time.time(), 0, 0.0

    async def send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await asyncio.wait_for(self.writer.drain(), 10)

    async def run(self):
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), 900)
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if isinstance(msg, dict):
                    await self.handle(msg)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:
            log.exception("worker %s %s crashed", self.ip, self.name)
        finally:
            self.pool.workers.discard(self)
            log.info("disconnected %s %s", self.ip, self.name)
            self.writer.close()

    async def handle(self, msg):
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or []
        after = None
        try:
            result, after = await self.dispatch(method, params)
            await self.send({"id": mid, "result": result, "error": None})
        except StratumError as e:
            await self.send({"id": mid, "result": None, "error": [e.code, e.msg, None]})
        except (ValueError, TypeError, IndexError, KeyError):
            await self.send({"id": mid, "result": None, "error": [20, "Bad request", None]})
        if after:
            await after()

    async def dispatch(self, method, params):
        if method == "mining.subscribe":
            self.subscribed = True
            self.agent = str(params[0])[:60] if params else ""
            sid = self.en1.hex()
            return [[["mining.set_difficulty", sid], ["mining.notify", sid]], self.en1.hex(), EN2_SIZE], None
        if method == "mining.configure":
            exts = params[0] if params else []
            opts = params[1] if len(params) > 1 else {}
            result = {}
            for ext in exts:
                if ext == "version-rolling":
                    mask = VERSION_MASK & int(opts.get("version-rolling.mask", "ffffffff"), 16)
                    result["version-rolling"] = True
                    result["version-rolling.mask"] = "%08x" % mask
                else:
                    result[ext] = False
            return result, None
        if method == "mining.authorize":
            return await self.authorize(params)
        if method == "mining.suggest_difficulty":
            # a fixed difficulty set by the user wins, and so does the difficulty we remembered for this miner
            if not self.override().get("diff") and not self.remembered:
                self.set_diff(float(params[0]))
            return True, (self.send_difficulty if self.authorized else None)
        if method == "mining.submit":
            return await self.submit(params), None
        if method == "mining.extranonce.subscribe":
            return True, None
        if method == "mining.get_transactions":
            return [], None
        raise StratumError(20, "Unknown method")

    async def authorize(self, params):
        pool = self.pool
        self.user = str(params[0])[:120]
        address, _, name = self.user.partition(".")
        spk = None if pool.cfg["force_default_address"] else await pool.script_for(address)
        if spk is None:
            address, spk = pool.cfg["default_address"], pool.default_spk
        if spk is None:
            log.info("refused %s %s: no payout address yet (set one on the dashboard, or put an address in the miner's username)",
                     self.ip, self.user)
            return False, None
        self.address, self.spk = address, spk
        self.name = name or self.ip
        remembered = pool.remembered_diff(self.name)
        if remembered:  # start where this miner left off, instead of the starting difficulty
            self.set_diff(remembered)
            self.remembered = True
        password = str(params[1]) if len(params) > 1 and params[1] else ""
        for part in password.split(","):
            if part.strip().startswith("d="):
                try:
                    self.set_diff(float(part.strip()[2:]))
                except ValueError:
                    pass
        if self.override().get("diff"):
            self.set_diff(self.override()["diff"])
        self.authorized = True
        pool.workers.add(self)
        log.info("authorized %s %s (%s) pays %s", self.ip, self.name, self.agent, address)

        async def first_job():
            await self.send_difficulty()
            if pool.job:
                await self.send_job(pool.job, True)
        return True, first_job

    def set_diff(self, diff):
        self.diff = min(MAX_DIFF, max(self.pool.cfg["min_diff"], diff))
        self.vd_start, self.vd_count, self.vd_work = time.time(), 0, 0.0

    def override(self):
        """User settings for this miner name: {"diff": fixed} or {"share_seconds": target}."""
        return self.pool.state["overrides"].get(self.name) or {}

    async def send_difficulty(self):
        await self.send({"id": None, "method": "mining.set_difficulty", "params": [self.diff]})

    async def send_job(self, job, clean):
        self.job_diff[job.id] = self.diff
        for jid in [j for j in self.job_diff if j not in self.pool.jobs]:
            del self.job_diff[jid]
        await self.send({"id": None, "method": "mining.notify", "params": job.notify_params(self.spk, clean)})

    def reject(self, reason, code, msg):
        log.warning("share rejected from %s (%s): %s", self.name, self.ip, reason)
        self.rejected[reason] += 1
        self.pool.rejected[reason] += 1
        self.pool.log_share(self.name, None, None, reason)
        raise StratumError(code, msg)

    async def submit(self, params):
        pool = self.pool
        if not self.authorized:
            raise StratumError(24, "Unauthorized worker")
        _, job_id, en2_hex, ntime_hex, nonce_hex = params[:5]
        job = pool.jobs.get(job_id)
        if job is None:
            self.reject("stale", 21, "Job not found")
        try:
            en2 = bytes.fromhex(en2_hex)
            ntime, nonce = int(ntime_hex, 16), int(nonce_hex, 16)
            vbits = int(params[5], 16) if len(params) > 5 and params[5] else None
        except ValueError:
            self.reject("malformed", 20, "Malformed share")
        if len(en2) != EN2_SIZE or not 0 <= nonce < 2 ** 32:
            self.reject("malformed", 20, "Malformed share")
        if vbits is None:
            version = job.version
        elif vbits & ~VERSION_MASK:
            self.reject("bad-version", 20, "Invalid version bits")
        else:
            version = (job.version & ~VERSION_MASK) | vbits
        if not job.mintime <= ntime <= time.time() + 7000:
            self.reject("ntime", 20, "ntime out of range")
        key = (self.en1, en2, ntime, nonce, version)
        if key in job.seen:
            self.reject("duplicate", 22, "Duplicate share")
        job.seen.add(key)

        coinbase = job.coinb1 + self.en1 + en2 + job.coinb2(self.spk)
        header = job.header(coinbase, version, ntime, nonce)
        h = int.from_bytes(sha256d(header), "little")
        share_diff = DIFF1 / h if h else float("inf")
        if h <= job.target:
            await pool.found_block(self, job, header, coinbase, share_diff)
        required = min(self.job_diff.get(job.id, self.diff), self.diff)
        if share_diff < required * (1 - 1e-9):
            self.reject("low-diff", 23, "Low difficulty share")
        if job.prev_hex != pool.tip:
            self.reject("stale", 21, "Stale share")

        now = time.time()
        self.accepted += 1
        self.last_share = now
        # Credit the share at the difficulty of the job it was found on: right after a difficulty change the
        # miner still works on the old job, so crediting the (lower) new difficulty undercounts its hashrate.
        credit = self.job_diff.get(job.id, self.diff)
        self.vd_count += 1
        self.vd_work += credit
        self.shares.append((now, credit))
        while self.shares and self.shares[0][0] < now - 3600:
            self.shares.popleft()
        self.best = max(self.best, share_diff)
        pool.share_accepted(self, credit, share_diff, now, block=h <= job.target)
        return True

    def vardiff(self, now):
        o = self.override()
        if o.get("diff"):
            return None
        elapsed = now - self.vd_start
        if self.vd_count < 20 and elapsed < 120:
            return None
        if self.vd_count:
            target = o.get("share_seconds") or self.pool.cfg["share_seconds"]
            ideal = self.vd_work * target / elapsed
        else:
            ideal = self.diff / 4
        ideal = min(max(ideal, self.diff / 8), self.diff * 16)
        ideal = min(MAX_DIFF, max(self.pool.cfg["min_diff"], float("%.3g" % ideal)))
        self.vd_start, self.vd_count, self.vd_work = now, 0, 0.0
        if abs(ideal / self.diff - 1) < 0.3:
            return None
        self.diff = ideal
        return ideal

    def snapshot(self, now):
        return {
            "name": self.name, "ip": self.ip, "agent": self.agent, "address": self.address,
            "diff": self.diff, "accepted": self.accepted, "rejected": dict(self.rejected),
            "best": self.best, "last_share": self.last_share, "connected": self.connected,
            "override": self.override(),
            "hashrate_5m": hashrate(self.shares, min(300, max(now - self.connected, 60)), now),
            "hashrate_1h": hashrate(self.shares, min(3600, max(now - self.connected, 60)), now),
        }


# ------------------------------------------------------------------------ pool

class Pool:
    def __init__(self, cfg, data_dir=DATA_DIR):
        self.cfg = cfg
        self.data_dir = data_dir
        self.rpc = RPC(cfg["rpc_url"], cfg["rpc_cookie"], cfg["rpc_user"], cfg["rpc_pass"])
        self.executor = ThreadPoolExecutor(4)
        self.submit_executor = ThreadPoolExecutor(1)  # found blocks never queue behind other RPCs
        self.tag = cfg["coinbase_tag"].encode()[:40]
        self.jobs = collections.OrderedDict()
        self.job = None
        self.job_ids = itertools.count(random.randrange(1 << 16))
        self.en1_ids = itertools.count(random.randrange(1 << 30))
        self.workers = set()
        self.spk_cache = {}
        self.default_spk = None
        self.tip = None
        self.template_lock = asyncio.Lock()
        self.started = time.time()
        self.accepted = 0
        self.rejected = collections.Counter()
        self.shares = collections.deque()
        self.best = {"diff": 0.0}
        self.window_best = {"diff": 0.0}  # best share since the last 5-minute stats line
        self.stats_mark = (0, 0)
        self.share_log = collections.deque(maxlen=300)  # recent shares for the dashboard's live feed
        self.share_seq = itertools.count(1)
        self.last_switch = None
        self.proposal = {"ok": None}
        self.state_path = os.path.join(data_dir, "state.json")
        try:
            with open(self.state_path) as f:
                self.state = json.load(f)
        except (OSError, ValueError):
            self.state = {}
        self.state.setdefault("best_ever", {"diff": 0.0})
        self.state.setdefault("blocks", [])
        self.state.setdefault("accepted_total", 0)
        self.state.setdefault("overrides", {})
        self.state.setdefault("settings", {})  # changed from the dashboard, kept across restarts
        self.policy_cfg = policy.load_config(self.state.get("policy"))
        self.policy_heights = collections.OrderedDict()  # height -> what the policy did to its last job
        self.policy_fallback_height = None  # a filtered job failed the block check at this height
        self.guard = stallguard.StallGuard(self.state.setdefault("stall_events", []))
        self.last_proposal = 0.0

    def refresh_s(self):
        """Typical interval between job updates (same block, fresh transactions), 1–120 s."""
        return self.state["settings"].get("template_refresh_s", self.cfg["template_refresh_s"])

    async def call(self, method, *params, timeout=15):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: self.rpc.call(method, *params, timeout=timeout))

    def next_extranonce1(self):
        return struct.pack(">I", next(self.en1_ids) & 0xFFFFFFFF)

    async def script_for(self, address):
        if address not in self.spk_cache:
            try:
                r = await self.call("validateaddress", address)
                self.spk_cache[address] = bytes.fromhex(r["scriptPubKey"]) if r.get("isvalid") else None
            except RPCError:
                return None
        return self.spk_cache[address]

    # -- work

    async def update_template(self, clean=False):
        async with self.template_lock:
            t0 = time.time()
            tpl = await self.call("getblocktemplate", {"rules": ["segwit"]})
            new_block = tpl["previousblockhash"] != self.tip
            mode, report, filtered = self.policy_cfg["mode"], None, False
            if mode == "filter":
                report = policy.evaluate(tpl, self.policy_cfg)
                if report["skipped"] and self.policy_fallback_height != tpl["height"]:
                    tpl, filtered = policy.apply(tpl, report), True
            job = Job("%x" % next(self.job_ids), tpl, self.tag)
            job.filtered = filtered
            self.jobs[job.id] = job
            while len(self.jobs) > 40:
                self.jobs.popitem(last=False)
            self.job, self.tip = job, job.prev_hex
            workers = [w for w in self.workers if w.authorized]
            await asyncio.gather(*(w.send_job(job, clean or new_block) for w in workers), return_exceptions=True)
            ms = round((time.time() - t0) * 1000)
            if new_block:
                self.last_switch = {"height": job.height, "ms": ms, "at": time.time(), "workers": len(workers)}
                log.info("new network block %d (%s), now mining %d", job.height - 1, job.prev_hex, job.height)
            log.info("%s job %s for block %d: %.8f BTC, %d txs, %s bytes, fees %.4f BTC (sent to %d workers in %d ms)",
                     "new-block" if new_block else "updated", job.id, job.height, job.value / 1e8, len(job.tx_data),
                     "{:,}".format(sum(len(t) for t in job.tx_data)), job.fees / 1e8, len(workers), ms)
            if mode == "watch":  # only counting, so it runs after the miners already have the job
                report = policy.evaluate(tpl, self.policy_cfg)
            if report is not None:
                self.record_policy(report, mode, filtered)
        # the node fully checks every new block's work; routine refreshes at most every 10 s,
        # so a short refresh interval doesn't keep the node busy validating
        if new_block or time.time() - self.last_proposal >= 10:
            self.last_proposal = time.time()
            asyncio.get_running_loop().create_task(self.check_proposal(job))

    async def check_proposal(self, job):
        """Have bitcoind validate a complete block built from this job (everything except proof of work)."""
        spks = ({w.spk for w in self.workers if w.spk} | {self.default_spk}) - {None} or {CHECK_SPK}
        t0 = time.time()
        for spk in spks:
            coinbase = job.coinb1 + bytes(EN1_SIZE + EN2_SIZE) + job.coinb2(spk)
            header = job.header(coinbase, job.version, job.curtime, 0)
            try:
                res = await self.call("getblocktemplate", {"mode": "proposal", "data": job.block(header, coinbase).hex()}, timeout=60)
            except Exception as e:
                res = "rpc error: %s" % e
            if res == "inconclusive-not-best-prevblk":
                return  # a newer block arrived meanwhile; the next job gets checked
            ok = res is None
            if not ok and getattr(job, "filtered", False):
                log.error("the filtered template for block %d failed the block check (%s); mining the node's own "
                          "template for this block instead", job.height, res)
                self.policy_fallback_height = job.height
                asyncio.get_running_loop().create_task(self.update_template(clean=True))
            if ok:
                log.info("block check OK for %d (job %s, %d txs) in %d ms",
                         job.height, job.id, len(job.tx_data), (time.time() - t0) * 1000)
            self.proposal = {"ok": ok, "result": res, "height": job.height, "at": time.time(), "outputs": len(spks)}
            if not ok:
                log.error("BLOCK PROPOSAL REJECTED at height %d: %s", job.height, res)
                return

    async def found_block(self, worker, job, header, coinbase, share_diff):
        block_hex = job.block(header, coinbase).hex()
        block_hash = sha256d(header)[::-1].hex()
        log.critical("BLOCK FOUND by %s (%s) at height %d: %s", worker.name, worker.ip, job.height, block_hash)
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(self.submit_executor, lambda: self.rpc.call("submitblock", block_hex, timeout=60))
        except Exception as e:
            result = "error: %s" % e
        log.critical("submitblock %s: %r", block_hash, result)
        record = {"height": job.height, "hash": block_hash, "worker": worker.name, "ip": worker.ip,
                  "address": worker.address, "diff": share_diff, "value": job.value,
                  "at": time.time(), "result": result}
        with open(os.path.join(self.data_dir, "blocks_found.jsonl"), "a") as f:
            f.write(json.dumps(dict(record, hex=block_hex)) + "\n")
        self.state["blocks"].append(record)
        self.save_state()
        loop.create_task(self.update_template(clean=True))

    def log_share(self, name, diff, share_diff, rejected=None, block=False):
        """Remember a share for the live feed: in memory only, nothing slow in the share path."""
        self.share_log.append({"seq": next(self.share_seq), "t": time.time(), "worker": name,
                               "diff": diff, "share": share_diff, "rejected": rejected, "block": block})

    def share_accepted(self, worker, diff, share_diff, now, block=False):
        self.log_share(worker.name, diff, share_diff, block=block)
        self.accepted += 1
        self.state["accepted_total"] += 1
        self.shares.append((now, diff))
        while self.shares and self.shares[0][0] < now - 3600:
            self.shares.popleft()
        if share_diff > self.best["diff"]:
            self.best = {"diff": share_diff, "worker": worker.name, "at": now}
        if share_diff > self.window_best["diff"]:
            self.window_best = {"diff": share_diff, "worker": worker.name}
        if share_diff > self.state["best_ever"]["diff"]:
            self.state["best_ever"] = {"diff": share_diff, "worker": worker.name, "at": now}

    def save_state(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.state_path)

    # -- loops

    async def watch_blocks(self):
        while True:
            try:
                if await self.call("getbestblockhash", timeout=5) != self.tip:
                    await self.update_template(clean=True)
            except Exception as e:
                log.warning("block watch: %s", e)
                await asyncio.sleep(2)
            await asyncio.sleep(self.cfg["block_poll_ms"] / 1000)

    def stall_guard_s(self):
        return self.state["settings"].get("stall_guard_s", self.cfg["stall_guard_s"])

    async def stall_guard_loop(self):
        """Every 5 s: is the node stuck on a block one peer won't send? Then drop that peer."""
        while True:
            await asyncio.sleep(5)
            limit = self.stall_guard_s()
            if limit <= 0:
                continue
            try:
                info = await self.call("getblockchaininfo", timeout=10)
                behind = info["headers"] > info["blocks"]
                peers = await self.call("getpeerinfo", timeout=10) if behind else []
                targets, note = self.guard.check(info["blocks"], info["headers"], info["initialblockdownload"],
                                                 peers, time.time(), limit)
                if note:
                    log.warning("stall guard: %s", note)
                for pid, desc in targets:
                    try:
                        await self.call("disconnectnode", "", pid, timeout=10)
                        log.warning("stall guard: block %d was announced over %d s ago but %s still hasn't sent it; "
                                    "disconnected it so the node gets the block from another peer",
                                    info["blocks"] + 1, limit, desc)
                    except RPCError as e:
                        log.warning("stall guard: couldn't disconnect %s: %s", desc, e)
                if targets:
                    self.save_state()
            except RPCError as e:
                if not (isinstance(e.args[0], dict) and e.args[0].get("code") == -28):  # -28: node still starting up
                    log.warning("stall guard: %s", e)
            except Exception as e:
                log.warning("stall guard: %s", e)

    async def refresh_templates(self):
        while True:
            await asyncio.sleep(1)
            if self.job and time.time() - self.job.created >= self.refresh_s():
                try:
                    await self.update_template()
                except Exception as e:
                    log.warning("template refresh: %s", e)

    async def housekeeping(self):
        n = 0
        while True:
            await asyncio.sleep(15)
            now = time.time()
            for w in list(self.workers):
                old = w.diff
                new = w.vardiff(now)
                if new:
                    log.info("%s difficulty %s -> %s (1 share / %g s)", w.name, fmt_diff(old), fmt_diff(new),
                             w.override().get("share_seconds") or self.cfg["share_seconds"])
                    try:
                        await w.send_difficulty()
                    except Exception:
                        pass
            n += 1
            if n % 4 == 0:
                self.remember_diffs(now)
                self.save_state()
            if n % 20 == 0:  # every 5 minutes
                self.log_stats(now)

    def remember_diffs(self, now):
        """Keep each settled miner's automatic difficulty, so it starts there after a restart or update.
        Only while it's still sending shares: a connection left hanging (say during a firmware flash)
        drags its difficulty down, and that low value shouldn't be remembered."""
        memory = self.state.setdefault("last_diff", {})
        for w in self.workers:
            if (w.authorized and not w.override().get("diff") and now - w.connected > 180
                    and now - w.last_share < 60):
                memory[w.name] = [w.diff, now]

    def remembered_diff(self, name):
        entry = self.state.setdefault("last_diff", {}).get(name)
        if entry and time.time() - entry[1] < 7 * 86400:
            return entry[0]
        return None

    def log_stats(self, now):
        accepted = self.accepted - self.stats_mark[0]
        rejected = sum(self.rejected.values()) - self.stats_mark[1]
        best = self.window_best
        log.info("stats: %d workers, %.1f TH/s (5 min), %s shares accepted, %d rejected in 5 min%s",
                 len([w for w in self.workers if w.authorized]),
                 hashrate(self.shares, min(300, max(now - self.started, 60)), now) / 1e12,
                 "{:,}".format(accepted), rejected,
                 ", best %s (%s)" % (fmt_diff(best["diff"]), best["worker"]) if best["diff"] else "")
        self.stats_mark = (self.accepted, sum(self.rejected.values()))
        self.window_best = {"diff": 0.0}

    # -- api

    def snapshot(self):
        now = time.time()
        up = now - self.started
        job = self.job
        return {
            "now": now, "uptime": up,
            "pool": {
                "height": job.height if job else None,
                "prev": self.tip,
                "txs": len(job.tx_data) if job else 0,
                "fees": job.fees if job else 0,
                "reward": job.value if job else 0,
                "network_diff": DIFF1 / job.target if job else 0,
                "template_age": now - job.created if job else None,
                "hashrate_5m": hashrate(self.shares, min(300, max(up, 60)), now),
                "hashrate_1h": hashrate(self.shares, min(3600, max(up, 60)), now),
                "accepted": self.accepted,
                "rejected": dict(self.rejected),
                "best": self.best,
                "policy": self.policy_view(),
                "best_ever": self.state["best_ever"],
                "blocks": self.state["blocks"],
                "last_switch": self.last_switch,
                "proposal": self.proposal,
                "default_address": self.cfg["default_address"],
                "needs_setup": self.default_spk is None,
                "tag": self.cfg["coinbase_tag"],
                "template_refresh_s": self.refresh_s(),
                "stall_guard": {"seconds": self.stall_guard_s(), "events": self.guard.events[-10:]},
            },
            "workers": sorted((w.snapshot(now) for w in self.workers), key=lambda w: w["name"]),
        }

    async def set_override(self, data):
        """Per-miner difficulty settings. Only share difficulty changes, never block odds."""
        name = str(data.get("name") or "")
        if not name:
            return 400, {"error": "name is required"}
        if data.get("diff") is not None:
            diff = float(data["diff"])
            if not self.cfg["min_diff"] <= diff <= 1e9:
                return 400, {"error": "diff must be between %g and 1e9" % self.cfg["min_diff"]}
            override = {"diff": diff}
        elif data.get("share_seconds") is not None:
            secs = float(data["share_seconds"])
            if not 1 <= secs <= 300:
                return 400, {"error": "share_seconds must be between 1 and 300"}
            override = {"share_seconds": secs}
        else:
            override = {}  # back to automatic
        if override:
            self.state["overrides"][name] = override
        else:
            self.state["overrides"].pop(name, None)
        self.save_state()
        for w in [w for w in self.workers if w.name == name]:
            w.set_diff(override.get("diff", w.diff))
            await w.send_difficulty()
        log.info("settings for %s: %s", name, override or "automatic")
        return 200, {"ok": True, "name": name, "override": override}

    def record_policy(self, report, mode, filtered):
        entry = {"height": report["height"], "mode": mode, "filtered": filtered, "txs": report["txs"],
                 "skipped": report["skipped"], "fees": report["fees"], "fees_skipped": report["fees_skipped"],
                 "weight_skipped": report["weight_skipped"], "by_rule": report["by_rule"],
                 "examples": report["examples"], "watched": report["watched"], "fees_watched": report["fees_watched"],
                 "watch_by_rule": report["watch_by_rule"], "at": time.time()}
        self.policy_heights[report["height"]] = entry
        self.policy_heights.move_to_end(report["height"])
        while len(self.policy_heights) > 144:  # about a day of blocks
            self.policy_heights.popitem(last=False)
        why = lambda by_rule: ", ".join("%s %d" % (k, v["txs"]) for k, v in by_rule.items())
        if report["skipped"]:
            text = "%s %d of %d txs for block %d, %s sats in fees (%s)" % (
                "skipped" if filtered else "would skip", report["skipped"], report["txs"], report["height"],
                "{:,}".format(report["fees_skipped"]), why(report["by_rule"]))
            if report["watched"]:
                text += "; watch rules would also skip %d txs, %s sats (%s)" % (
                    report["watched"], "{:,}".format(report["fees_watched"]), why(report["watch_by_rule"]))
        elif report["watched"]:
            text = "would skip %d of %d txs for block %d, %s sats in fees (%s)" % (
                report["watched"], report["txs"], report["height"], "{:,}".format(report["fees_watched"]),
                why(report["watch_by_rule"]))
        else:
            return
        log.info("policy (%s): %s", "filtering" if filtered else "watch-only" if mode == "watch"
                 else "fallback" if report["skipped"] else "watch rules", text)

    def policy_view(self):
        recent = list(self.policy_heights.values())
        done = recent[:-1]  # blocks already found by the network; the last one is still being mined
        totals = {"blocks": len(done), "skipped": sum(e["skipped"] for e in done),
                  "fees_skipped": sum(e["fees_skipped"] for e in done), "by_rule": {},
                  "watched": sum(e.get("watched", 0) for e in done),
                  "fees_watched": sum(e.get("fees_watched", 0) for e in done), "watch_by_rule": {}}
        for e in done:
            for key in ("by_rule", "watch_by_rule"):
                for k, v in e.get(key, {}).items():
                    t = totals[key].setdefault(k, {"txs": 0, "fees": 0})
                    t["txs"] += v["txs"]
                    t["fees"] += v["fees"]
        return {"mode": self.policy_cfg["mode"], "rules": self.policy_cfg["rules"], "names": policy.RULE_NAMES,
                "current": recent[-1] if recent else None, "recent": done[-12:][::-1], "totals": totals,
                "fallback_height": self.policy_fallback_height}

    async def set_policy(self, data):
        cfg, err = policy.check_config(data, self.policy_cfg)
        if err:
            return 400, {"error": err}
        self.policy_cfg = cfg
        self.state["policy"] = cfg
        self.save_state()
        states = {k: policy.rule_state(v) for k, v in cfg["rules"].items()}
        log.info("template policy: mode %s, filter: %s, watch only: %s", cfg["mode"],
                 ", ".join(k for k, s in states.items() if s == "filter") or "none",
                 ", ".join(k for k, s in states.items() if s == "watch") or "none")
        asyncio.get_running_loop().create_task(self.update_template())  # apply it to the next job right away
        return 200, dict(self.policy_view(), ok=True)

    def set_settings(self, data):
        """Pool-wide settings from the dashboard. Takes effect right away, no restart."""
        if "template_refresh_s" not in data and "stall_guard_s" not in data:
            return 400, {"error": "nothing to change"}
        if "template_refresh_s" in data:
            secs = float(data["template_refresh_s"])
            if not 1 <= secs <= 120:
                return 400, {"error": "the job update interval must be between 1 and 120 seconds"}
            self.state["settings"]["template_refresh_s"] = secs
            log.info("job update interval set to %g s", secs)
        if "stall_guard_s" in data:
            guard = float(data["stall_guard_s"])
            if guard != 0 and not 20 <= guard <= 600:
                return 400, {"error": "the stall guard must be 20 to 600 seconds, or 0 for off"}
            self.state["settings"]["stall_guard_s"] = guard
            log.info("stall guard %s", "off" if guard == 0 else "set to %g s" % guard)
        self.save_state()
        return 200, {"ok": True, "template_refresh_s": self.refresh_s(), "stall_guard_s": self.stall_guard_s()}

    async def serve_api(self, reader, writer):
        try:
            method, path = (await asyncio.wait_for(reader.readline(), 5)).decode().split()[:2]
            length, token = 0, ""
            while True:
                line = await asyncio.wait_for(reader.readline(), 5)
                if line in (b"\r\n", b"\n", b""):
                    break
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":")[1])
                elif line.lower().startswith(b"x-solo45-token:"):
                    token = line.split(b":", 1)[1].strip().decode(errors="replace")
            status, reply = 200, None
            if method == "POST" and path in ("/api/worker", "/api/settings", "/api/policy", "/api/payout"):
                # settings changes are only accepted from the Umbrel itself, or from the dashboard with
                # the app's shared secret (the Umbrel app runs the dashboard in its own container)
                secret = os.environ.get("SOLO45_API_TOKEN", "")
                local = (writer.get_extra_info("peername") or ("",))[0] == "127.0.0.1"
                if not (local or (secret and hmac.compare_digest(token, secret))):
                    status, reply = 403, {"error": "settings can only be changed from the Umbrel"}
                else:
                    try:
                        data = json.loads(await asyncio.wait_for(reader.readexactly(min(length, 4096)), 5))
                        if path == "/api/worker":
                            status, reply = await self.set_override(data)
                        elif path == "/api/policy":
                            status, reply = await self.set_policy(data)
                        elif path == "/api/payout":
                            status, reply = await self.set_payout(data)
                        else:
                            status, reply = self.set_settings(data)
                    except (ValueError, TypeError, AttributeError):
                        status, reply = 400, {"error": "bad request"}
            elif method == "GET" and path.startswith("/api/shares"):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
                since = int((query.get("since") or ["0"])[0])
                reply = {"shares": [s for s in self.share_log if s["seq"] > since]}
            elif method == "GET":
                reply = self.snapshot()
            else:
                status, reply = 405, {"error": "method not allowed"}
            body = json.dumps(reply).encode()
            reason = {200: b"OK", 400: b"Bad Request", 403: b"Forbidden", 405: b"Method Not Allowed"}[status]
            writer.write(b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                         b"Access-Control-Allow-Origin: *\r\nConnection: close\r\n"
                         b"Content-Length: %d\r\n\r\n" % (status, reason, len(body)) + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def serve_stratum(self, reader, writer):
        await Worker(self, reader, writer).run()

    async def set_payout(self, data):
        """The payout address for miners that don't put their own address in the username."""
        address = str(data.get("address") or "").strip()
        spk = await self.script_for(address) if address else None
        if spk is None:
            return 400, {"error": "your node says that isn't a valid Bitcoin address"}
        old = self.cfg["default_address"]
        self.cfg["default_address"], self.default_spk = address, spk
        self.state["settings"]["default_address"] = address
        self.save_state()
        for w in self.workers:  # miners that were paying the old default address switch at the next job
            if w.authorized and w.address == old:
                w.address, w.spk = address, spk
        log.info("payout address set to %s", address)
        asyncio.get_running_loop().create_task(self.update_template(clean=True))
        return 200, {"ok": True, "address": address}

    async def start(self):
        saved = self.state["settings"].get("default_address")
        if saved:  # set on the dashboard; wins over config.json
            self.cfg["default_address"] = saved
        address = self.cfg["default_address"]
        self.default_spk = await self.script_for(address) if address else None
        if self.default_spk is None:
            log.warning("no payout address set yet: open the Solo45 dashboard to set one. Until then only miners "
                        "with a Bitcoin address in their username can connect")
        await self.update_template(clean=True)
        await asyncio.start_server(self.serve_stratum, "0.0.0.0", self.cfg["stratum_port"], limit=1 << 16)
        await asyncio.start_server(self.serve_api, "0.0.0.0", self.cfg["api_port"])
        loop = asyncio.get_running_loop()
        self.tasks = [loop.create_task(c) for c in (self.watch_blocks(), self.refresh_templates(), self.housekeeping(),
                                                     self.stall_guard_loop())]
        log.info("stratum on :%d, api on :%d, height %d, pays %s by default",
                 self.cfg["stratum_port"], self.cfg["api_port"], self.job.height, self.cfg["default_address"])


# Environment settings (used by the Umbrel app) win over config.json.
ENV_SETTINGS = (("SOLO45_STRATUM_PORT", "stratum_port", int), ("SOLO45_API_PORT", "api_port", int),
                ("BITCOIN_RPC_URL", "rpc_url", str), ("BITCOIN_RPC_USER", "rpc_user", str),
                ("BITCOIN_RPC_PASS", "rpc_pass", str), ("BITCOIN_RPC_COOKIE", "rpc_cookie", str))


def load_config(path=os.path.join(DATA_DIR, "config.json")):
    cfg = dict(DEFAULTS)
    try:
        with open(path) as f:
            cfg.update(json.load(f))
    except OSError:
        pass
    for var, key, kind in ENV_SETTINGS:
        if os.environ.get(var):
            cfg[key] = kind(os.environ[var])
    return cfg


def setup_logging(path):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(sh)
    log.setLevel(logging.INFO)


async def main():
    setup_logging(os.path.join(DATA_DIR, "pool.log"))
    pool = Pool(load_config())
    await pool.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
