#!/usr/bin/env python3
"""Checks the pool's consensus-critical code against the live node.

Read-only RPC calls, block proposals (validated by bitcoind, never accepted)
and one submitblock with a block that has no proof of work, which bitcoind
rejects as "high-hash". It proves the found-block path produces a block the
node can decode. The stratum test runs a throwaway pool on port 3399 and
mines low-difficulty shares with a separately written miner.
"""
import asyncio
import hashlib
import json
import os
import random
import struct
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pool as P  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print("%s  %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


cfg = P.load_config()
rpc = P.RPC(cfg["rpc_url"], cfg["rpc_cookie"], cfg["rpc_user"], cfg["rpc_pass"])
print("node:", rpc.call("getnetworkinfo")["subversion"])

# 1. header hashing and byte order against the real tip
best = rpc.call("getbestblockhash")
hdr = bytes.fromhex(rpc.call("getblockheader", best, False))
check("header hash matches tip", P.sha256d(hdr)[::-1].hex() == best)

# 2. merkle branch against a real block, and against a naive tree for small sizes
blk = rpc.call("getblock", best, 1)
txids = [bytes.fromhex(t)[::-1] for t in blk["tx"]]
root = txids[0]
for h in P.merkle_branch(txids[1:]):
    root = P.sha256d(root + h)
check("merkle root of real block", root[::-1].hex() == blk["merkleroot"], "(%d txs)" % len(txids))


def naive_root(hs):
    while len(hs) > 1:
        if len(hs) % 2:
            hs = hs + [hs[-1]]
        hs = [dsha(hs[i] + hs[i + 1]) for i in range(0, len(hs), 2)]
    return hs[0]


ok = True
for n in range(1, 40):
    hs = [os.urandom(32) for _ in range(n)]
    r = hs[0]
    for h in P.merkle_branch(hs[1:]):
        r = P.sha256d(r + h)
    ok &= r == naive_root(hs)
check("merkle branch, 1-39 txs vs naive tree", ok)

# 3. BIP34 height encoding matches the real coinbase
cb_script = rpc.call("getblock", best, 2)["tx"][0]["vin"][0]["coinbase"]
check("BIP34 height encoding", cb_script.startswith(P.push(P.script_num(blk["height"])).hex()))
check("script_num edge cases", [P.script_num(x).hex() for x in (1, 127, 128, 255, 256, 32768)]
      == ["01", "7f", "8000", "ff00", "0001", "008000"])

# 4. coinbase contents and a full block proposal
tpl = rpc.call("getblocktemplate", {"rules": ["segwit"]})
spk = bytes.fromhex(rpc.call("validateaddress", cfg["default_address"])["scriptPubKey"])
job = P.Job("t", tpl, cfg["coinbase_tag"].encode())
coinbase = job.coinb1 + bytes(12) + job.coinb2(spk)
dec = rpc.call("decoderawtransaction", coinbase.hex())
check("coinbase pays full reward to payout address",
      round(dec["vout"][0]["value"] * 1e8) == tpl["coinbasevalue"] and dec["vout"][0]["scriptPubKey"]["hex"] == spk.hex(),
      "(%.8f BTC)" % (tpl["coinbasevalue"] / 1e8))
check("coinbase has witness commitment", len(dec["vout"]) == 2 and dec["vout"][1]["scriptPubKey"]["hex"] == tpl.get("default_witness_commitment"))
header = job.header(coinbase, job.version, job.curtime, 0)
res = rpc.call("getblocktemplate", {"mode": "proposal", "data": job.block(header, coinbase).hex()})
check("bitcoind accepts full block proposal", res is None, "(%d txs, result %r)" % (len(job.tx_data) + 1, res))
for n_tx in (0, 1, 2, 3):  # small blocks exercise odd/even merkle edge cases
    # the first n_tx transactions that have no in-template parents
    txs = [t for t in tpl["transactions"] if not t.get("depends")][:n_tx]
    if len(txs) < n_tx:
        break
    small = dict(tpl, transactions=txs, coinbasevalue=tpl["coinbasevalue"] - sum(t["fee"] for t in tpl["transactions"]) + sum(t["fee"] for t in txs))
    small.pop("default_witness_commitment", None)
    # witness commitment for the subset: merkle root of wtxids with the coinbase as zero
    wtx = [bytes(32)] + [bytes.fromhex(t["hash"])[::-1] for t in txs]
    commit = P.sha256d(naive_root(wtx) + bytes(32))
    small["default_witness_commitment"] = "6a24aa21a9ed" + commit.hex()
    small_job = P.Job("s", small, b"x")
    cb = small_job.coinb1 + bytes(12) + small_job.coinb2(spk)
    hd = small_job.header(cb, small_job.version, small_job.curtime, 0)
    r = rpc.call("getblocktemplate", {"mode": "proposal", "data": small_job.block(hd, cb).hex()})
    check("proposal with %d txs" % n_tx, r is None, "(result %r)" % r)


# 4b. template policy: detection on hand-made transactions, and a filtered template the node accepts
import policy


def raw_tx(outputs, witness=None):
    tx = struct.pack("<I", 2) + (b"\x00\x01" if witness else b"") + b"\x01" + bytes(36) + b"\x00" + b"\xff" * 4
    tx += bytes([len(outputs)]) + b"".join(struct.pack("<q", 1000) + bytes([len(s)]) + s for s in outputs)
    if witness:
        tx += bytes([len(witness)]) + b"".join(bytes([len(w)]) + w for w in witness)
    return (tx + bytes(4)).hex()


on = policy.load_config({"rules": {"minfee": {"on": True, "sat_vb": 2}}})["rules"]
p2wpkh = b"\x00\x14" + bytes(20)
leaf = bytes([0x20]) + bytes(32) + b"\xac" + b"\x00\x63" + b"\x03ord" + b"\x51" + b"\x05hello" + b"\x68"
cases = [
    ("plain payment", raw_tx([p2wpkh]), []),
    ("small OP_RETURN (80 bytes)", raw_tx([p2wpkh, b"\x6a\x4c\x4e" + bytes(78)]), []),
    ("large OP_RETURN (100 bytes)", raw_tx([b"\x6a\x4c\x62" + bytes(98)]), ["opreturn"]),
    ("Runes", raw_tx([p2wpkh, b"\x6a\x5d\x03\x14\x02\x00"]), ["runes"]),
    ("bare multisig", raw_tx([b"\x51\x21" + bytes(33) + b"\x51\xae"]), ["baremultisig"]),
    ("inscription", raw_tx([p2wpkh], [bytes(64), leaf, b"\xc0" + bytes(32)]), ["inscriptions"]),
    ("key-path taproot spend", raw_tx([p2wpkh], [bytes(64)]), []),
    ("taproot output whose key ends in ae", raw_tx([b"\x51\x20" + bytes(31) + b"\xae"]), []),
    ("2-of-3 bare multisig", raw_tx([b"\x52" + (b"\x21" + bytes(33)) * 3 + b"\x53\xae"]), ["baremultisig"]),
]
bad = [(name, policy.classify({"data": d, "fee": 10000, "weight": 400}, on)) for name, d, want in cases
       if policy.classify({"data": d, "fee": 10000, "weight": 400}, on) != want]
check("policy spots each kind of transaction", not bad, "(%d cases%s)" % (len(cases), ", wrong: %r" % bad if bad else ""))
def ftx(txid, fee, depends=()):
    return {"data": raw_tx([p2wpkh]), "txid": txid, "fee": fee, "weight": 400, "depends": list(depends)}  # 100 vB


cpfp = {"height": 1, "transactions": [
    ftx("parent 1 sat/vB", 100), ftx("child 20 sat/vB", 2000, [1]),  # the child pays for both: keep
    ftx("parent 1 sat/vB", 100), ftx("child 2 sat/vB", 200, [3]),  # the pair pays 1.5: skip both
    ftx("parent 20 sat/vB", 2000), ftx("child 1 sat/vB", 100, [5]),  # keep the parent, skip the child
    ftx("alone 3 sat/vB", 300), ftx("alone 6 sat/vB", 600)]}
rep = policy.evaluate(cpfp, policy.load_config({"mode": "filter", "rules": {"minfee": {"on": True, "sat_vb": 5}}}))
check("policy fee rule counts child-pays-for-parent packages", sorted(rep["skip"]) == [2, 3, 5, 6],
      "(skipped %s)" % sorted(rep["skip"]))
check("policy witness commitment matches the node's", policy.witness_commitment(tpl["transactions"]).hex()
      == tpl.get("default_witness_commitment"), "(%d txs)" % len(tpl["transactions"]))
fake = {"height": 1, "transactions": [
    {"data": raw_tx([b"\x6a\x5d\x00"]), "txid": "a", "fee": 5, "weight": 400, "depends": []},
    {"data": raw_tx([p2wpkh]), "txid": "b", "fee": 7, "weight": 400, "depends": [1]},
    {"data": raw_tx([p2wpkh]), "txid": "c", "fee": 9, "weight": 400, "depends": []}]}
rep = policy.evaluate(fake, policy.load_config({"mode": "filter"}))
check("policy also skips children of skipped transactions", sorted(rep["skip"]) == [0, 1] and rep["fees_skipped"] == 12)
rep = policy.evaluate(fake, policy.load_config({"mode": "filter", "rules": {"minfee": {"on": True, "watch": True, "sat_vb": 0.1}}}))
check("policy watch rules only count", sorted(rep["skip"]) == [0, 1] and sorted(rep["watch"]) == [2]
      and [t["txid"] for t in policy.apply(dict(fake, coinbasevalue=100), rep)["transactions"]] == ["c"])
rep = policy.evaluate(fake, policy.load_config({"mode": "watch"}))
check("policy watch mode leaves everything in", not rep["skip"] and sorted(rep["watch"]) == [0, 1])
# the node must accept a block built from a filtered template (up to 3 transactions taken out)
free = [n for n, t in enumerate(tpl["transactions"]) if not any(d - 1 == n for u in tpl["transactions"] for d in u.get("depends", []))]
drop = {n: ["runes"] for n in free[:3]}
ftpl = policy.apply(tpl, {"skip": drop, "fees_skipped": sum(tpl["transactions"][n]["fee"] for n in drop)})
fjob = P.Job("f", ftpl, cfg["coinbase_tag"].encode())
fcb = fjob.coinb1 + bytes(12) + fjob.coinb2(spk)
fres = rpc.call("getblocktemplate", {"mode": "proposal", "data": fjob.block(fjob.header(fcb, fjob.version, fjob.curtime, 0), fcb).hex()})
check("node accepts a filtered block proposal", fres is None,
      "(%d of %d txs removed, result %r)" % (len(drop), len(tpl["transactions"]), fres))
# the node must accept a block with the package fee rule applied (parents and children kept together)
feecfg = policy.load_config({"mode": "filter", "rules": dict({k: {"on": False} for k in ("inscriptions", "opreturn", "baremultisig", "runes")},
                                                               minfee={"on": True, "sat_vb": 3})})
frep = policy.evaluate(tpl, feecfg)
fjob = P.Job("g", policy.apply(tpl, frep), cfg["coinbase_tag"].encode())
fcb = fjob.coinb1 + bytes(12) + fjob.coinb2(spk)
fres = rpc.call("getblocktemplate", {"mode": "proposal", "data": fjob.block(fjob.header(fcb, fjob.version, fjob.curtime, 0), fcb).hex()})
check("node accepts a block with the fee rule applied", fres is None,
      "(%d of %d txs below 3 sat/vB left out, result %r)" % (frep["skipped"], len(tpl["transactions"]), fres))


# 4c. stall guard decisions, on made-up node states
import stallguard
g = stallguard.StallGuard([])
stuck = [{"id": 21, "network": "ipv4", "inbound": True, "inflight": [101]}, {"id": 5, "network": "ipv4", "inflight": []}]
steps = [
    ("in sync: nothing", g.check(100, 100, False, stuck, 0, 60)[0] == []),
    ("behind 30 s: still waiting", g.check(100, 101, False, stuck, 1000, 60)[0] == [] and g.check(100, 101, False, stuck, 1030, 60)[0] == []),
    ("behind 60 s: drops the peer holding the block", [p for p, _ in g.check(100, 101, False, stuck, 1061, 60)[0]] == [21]),
    ("cooldown: no second round within 30 s", g.check(100, 101, False, stuck, 1070, 60)[0] == []),
    ("far behind (catching up): stays out", stallguard.StallGuard([]).check(100, 110, False, stuck, 5000, 60)[0] == []),
    ("initial sync: stays out", stallguard.StallGuard([]).check(100, 101, True, stuck, 5000, 60)[0] == []),
    ("switched off: stays out", stallguard.StallGuard([]).check(100, 101, False, stuck, 5000, 0)[0] == []),
]
g2 = stallguard.StallGuard([])
g2.check(100, 101, False, [], 0, 60)
first = g2.check(100, 101, False, [], 61, 60)
steps.append(("no peer has the block: only a note, once", first[0] == [] and first[1] is not None
              and g2.check(100, 101, False, [], 70, 60) == ([], None)))
bad = [name for name, ok in steps if not ok]
check("stall guard decisions", not bad and len(g.events) == 1, "(%d cases%s)" % (len(steps), ", wrong: %r" % bad if bad else ""))


# 4d. remembered difficulty
import types
_m = types.SimpleNamespace(state={"last_diff": {"A": [3000.0, time.time()], "B": [5000.0, time.time() - 8 * 86400]}})
check("remembered difficulty (fresh used, 8-day-old ignored)", P.Pool.remembered_diff(_m, "A") == 3000.0
      and P.Pool.remembered_diff(_m, "B") is None and P.Pool.remembered_diff(_m, "C") is None)


# 4e. template policy totals survive a restart
import tempfile


def fake_report(height, skipped):
    return {"height": height, "txs": 100, "fees": 1000, "skipped": skipped, "fees_skipped": 10 * skipped, "weight_skipped": 0,
            "by_rule": {"minfee": {"txs": skipped, "fees": 10 * skipped}}, "examples": [],
            "watched": 0, "fees_watched": 0, "watch_by_rule": {}}


_pdir = tempfile.mkdtemp(prefix="solo45-policy-")
_p1 = P.Pool(cfg, data_dir=_pdir)
for _h, _n in ((10, 1), (10, 2), (11, 3), (12, 4)):  # block 10 had two jobs; 12 is still being mined
    _p1.record_policy(fake_report(_h, _n), "filter", True)
_v1, _v2 = _p1.policy_view(), P.Pool(cfg, data_dir=_pdir).policy_view()  # the second pool is a restart
check("policy totals survive a restart", _v1["periods"][0]["blocks"] == 2 and _v1["periods"][0]["skipped"] == 5
      and _v1["current"]["height"] == 12 and _v2["periods"][0]["skipped"] == 5 and _v2["current"] is None
      and [e["height"] for e in _v2["recent"]] == [11, 10])


# 4f. vardiff windows: 40 shares or 10 minutes, x1.5 band, a quick drop when shares stop coming
def vd(count, elapsed, diff=1000.0, o=None):
    o = {"share_seconds": 15} if o is None else o
    w = types.SimpleNamespace(diff=diff, vd_start=100.0, vd_count=count, vd_work=count * diff, override=lambda: o,
                              pool=types.SimpleNamespace(cfg={"share_seconds": 5, "min_diff": 1}))
    return P.Worker.vardiff(w, 100.0 + elapsed)


check("vardiff windows and band", vd(10, 150) is None and vd(40, 450) is None and vd(40, 200) == 3000
      and vd(0, 130) is None and vd(0, 185) == 250 and vd(1, 300) is None and vd(40, 200, o={"diff": 500}) is None
      and vd(20, 600) == 500)

# a share counts at the difficulty the miner really used: the job's, until the miner shows it switches at once
_sw = types.SimpleNamespace(diff=1000.0, job_diff={"old": 8000.0, "new": 1000.0}, switches_at_once=False)
_credits = [P.Worker.share_credit(_sw, "old", 9000.0), P.Worker.share_credit(_sw, "old", 1500.0),
            P.Worker.share_credit(_sw, "old", 9000.0), P.Worker.share_credit(_sw, "new", 1200.0)]
_st = types.SimpleNamespace(diff=1000.0, job_diff={"old": 8000.0}, switches_at_once=False)
_steady = [P.Worker.share_credit(_st, "old", d) for d in (8100.0, 20000.0, 8000.0)]
check("share credit follows the difficulty the miner used", _credits == [8000.0, 1000.0, 1000.0, 1000.0]
      and _sw.switches_at_once and _steady == [8000.0] * 3 and not _st.switches_at_once, "(%s, %s)" % (_credits, _steady))


# 4g. settings backup: export from one pool, restore into a fresh one
_a = P.Pool(cfg, data_dir=tempfile.mkdtemp(prefix="solo45-backup-"))
_a.state["overrides"] = {"BitaxeX": {"share_seconds": 12.0}, "S21X": {"diff": 250000.0}}
_a.state["settings"]["template_refresh_s"] = 40.0
_a.policy_cfg = policy.load_config({"mode": "filter", "rules": {"minfee": {"on": True, "sat_vb": 7}}})
_a.state["last_diff"] = {"BitaxeX": [4500.0, time.time()]}
_b = P.Pool(cfg, data_dir=tempfile.mkdtemp(prefix="solo45-restore-"))
_code, _rep = asyncio.run(_b.restore_settings(json.loads(json.dumps(_a.export_settings()))))
check("settings backup restores into a fresh pool", _code == 200 and _rep["ok"] and _b.state["overrides"] == _a.state["overrides"]
      and _b.refresh_s() == 40.0 and _b.policy_cfg["mode"] == "filter" and _b.policy_cfg["rules"]["minfee"]["sat_vb"] == 7
      and _b.remembered_diff("BitaxeX") == 4500.0, "(%s)" % "; ".join(_rep["restored"] + _rep["errors"]))


# 4h. the node's ZMQ block feed, through the built-in ZMTP client (the dashboard's source of new blocks)
import urllib.parse
import zmqsub
_zurl = os.environ.get("BITCOIN_ZMQ_HASHBLOCK") or "tcp://%s:28334" % urllib.parse.urlparse(cfg["rpc_url"]).hostname
try:
    _zh, _zp = _zurl.replace("tcp://", "").rsplit(":", 1)
    zmqsub.ZmqSub(_zh, int(_zp)).close()
    _zok = "ok"
except (OSError, ValueError) as e:
    _zok = str(e)
check("ZMQ block feed handshake with the node", _zok == "ok", "(%s: %s)" % (_zurl, _zok))


# 5. stratum round trip with an independently written miner
def miner_header(notify, en1, en2, ntime, nonce, version):
    jid, prevh, c1, c2, branch, ver, nbits, _, _ = notify
    cb = bytes.fromhex(c1) + en1 + en2 + bytes.fromhex(c2)
    mr = dsha(cb)
    for b in branch:
        mr = dsha(mr + bytes.fromhex(b))
    pv = bytes.fromhex(prevh)
    pv = b"".join(pv[i:i + 4][::-1] for i in range(0, 32, 4))
    return struct.pack("<I", version) + pv + mr + struct.pack("<I", ntime) + bytes.fromhex(nbits)[::-1] + struct.pack("<I", nonce)


def mine(notify, en1, en2, version, diff):
    target = int(int("00000000ffff" + "0" * 52, 16) / diff)
    ntime = int(notify[7], 16)
    for nonce in range(1 << 32):
        if int.from_bytes(dsha(miner_header(notify, en1, en2, ntime, nonce, version)), "little") <= target:
            return ntime, nonce


async def stratum_test():
    import shutil
    data = os.path.join(P.DATA_DIR, "selftest-data")
    os.makedirs(data, exist_ok=True)
    tcfg = dict(cfg, stratum_port=3399, api_port=3398, min_diff=0.0001, start_diff=0.0002)
    pool = P.Pool(tcfg, data_dir=data)
    pool.state = {"best_ever": {"diff": 0.0}, "blocks": [], "accepted_total": 0, "overrides": {}, "settings": {}}
    await pool.start()
    r, w = await asyncio.open_connection("127.0.0.1", 3399)
    inbox = []

    async def rpc_call(mid, method, params):
        w.write((json.dumps({"id": mid, "method": method, "params": params}) + "\n").encode())
        await w.drain()
        while True:
            m = json.loads(await asyncio.wait_for(r.readline(), 30))
            if m.get("id") == mid:
                return m
            inbox.append(m)

    def latest(method):
        return [m["params"] for m in inbox if m.get("method") == method][-1]

    cfg_reply = await rpc_call(1, "mining.configure", [["version-rolling"], {"version-rolling.mask": "ffffffff"}])
    check("configure version rolling", cfg_reply["result"]["version-rolling.mask"] == "1fffe000")
    sub = await rpc_call(2, "mining.subscribe", ["selftest/1.0"])
    en1 = bytes.fromhex(sub["result"][1])
    check("subscribe", sub["result"][2] == 8)
    auth = await rpc_call(3, "mining.authorize", [cfg["default_address"] + ".selftest", "x"])
    check("authorize", auth["result"] is True)
    loop = asyncio.get_running_loop()
    user = cfg["default_address"] + ".selftest"

    async def drain():
        while True:
            try:
                line = await asyncio.wait_for(r.readline(), 0.3)
            except asyncio.TimeoutError:
                return
            inbox.append(json.loads(line))

    async def mine_and_submit(mid, vbits=None):
        # mine on the newest job; retry if a real block makes it stale meanwhile
        for _ in range(3):
            await drain()
            n, d = latest("mining.notify"), latest("mining.set_difficulty")[0]
            v = int(n[5], 16) if vbits is None else (int(n[5], 16) & ~0x1FFFE000) | vbits
            e2 = os.urandom(8)
            nt, no = await loop.run_in_executor(None, mine, n, en1, e2, v, d)
            params = [user, n[0], e2.hex(), "%08x" % nt, "%08x" % no] + ([] if vbits is None else ["%08x" % vbits])
            res = await rpc_call(mid, "mining.submit", params)
            if not (res["error"] and res["error"][0] == 21):
                return res, params, d
            print("      (share went stale, a real block arrived - retrying)")
        return res, params, d

    t0 = time.time()
    res, good, diff = await mine_and_submit(4)
    check("valid share accepted", res["result"] is True, "(mined in %.1fs at diff %g)" % (time.time() - t0, diff))
    res = await rpc_call(5, "mining.submit", good)
    check("duplicate rejected", res["error"] and res["error"][0] == 22)
    bad = good[:4] + ["%08x" % ((int(good[4], 16) + 1) & 0xFFFFFFFF)]
    res = await rpc_call(6, "mining.submit", bad)
    check("low-difficulty share rejected", res["error"] and res["error"][0] == 23)
    res = await rpc_call(7, "mining.submit", [user, "nope"] + good[2:])
    check("unknown job rejected", res["error"] and res["error"][0] == 21)

    res, _, _ = await mine_and_submit(8, vbits=0x00006000)
    check("version-rolled share accepted", res["result"] is True, "(%r)" % res["error"])

    async def found_block_test():
        # pretend the network target is trivial so the next share is a "block"
        for j in pool.jobs.values():
            j.target = 2 ** 256 - 1
        orig_job = P.Job.__init__

        def easy_job(self, *a, **k):  # jobs created during the test are "easy" too
            orig_job(self, *a, **k)
            self.target = 2 ** 256 - 1
        P.Job.__init__ = easy_job
        res, _, _ = await mine_and_submit(9)
        P.Job.__init__ = orig_job
        blocks = pool.state["blocks"]
        check("found-block path submits and node decodes it",
              res["result"] is True and blocks and blocks[-1]["result"] == "high-hash",
              "(submitblock said %r)" % (blocks[-1]["result"] if blocks else None))

    def post(data, path="/api/worker"):
        # the settings endpoints, called the way the dashboard calls them
        req = urllib.request.Request("http://127.0.0.1:3398" + path, json.dumps(data).encode(),
                                     {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    expected_accepted = 2
    if "--no-submit" in sys.argv:  # skip it: each run leaves a high-hash line in debug.log
        print("SKIP  found-block path (--no-submit)")
    else:
        await found_block_test()
        expected_accepted = 3

    st, rep = await loop.run_in_executor(None, post, {"name": "selftest", "diff": 0.0005})
    await drain()
    check("fixed difficulty applied and sent", st == 200 and latest("mining.set_difficulty")[0] == 0.0005, "(%s %r)" % (st, rep))
    st, rep = await loop.run_in_executor(None, post, {"name": "selftest", "diff": 0.00001})
    check("difficulty below minimum refused", st == 400)
    st, rep = await loop.run_in_executor(None, post, {"name": "selftest", "share_seconds": 12})
    check("share-time target saved", st == 200 and pool.state["overrides"]["selftest"] == {"share_seconds": 12.0})
    st, rep = await loop.run_in_executor(None, post, {"name": "selftest"})
    check("back to automatic", st == 200 and "selftest" not in pool.state["overrides"])
    st, rep = await loop.run_in_executor(None, lambda: post({"template_refresh_s": 45}, "/api/settings"))
    check("job update interval saved", st == 200 and pool.refresh_s() == 45)
    st, rep = await loop.run_in_executor(None, lambda: post({"template_refresh_s": 500}, "/api/settings"))
    check("job update interval over 120 s refused", st == 400 and pool.refresh_s() == 45)

    def get_shares(since):
        with urllib.request.urlopen("http://127.0.0.1:3398/api/shares?since=%d" % since, timeout=5) as resp:
            return json.load(resp)["shares"]
    feed = await loop.run_in_executor(None, get_shares, 0)
    ok_n = sum(1 for s in feed if not s["rejected"])
    reasons = sorted({s["rejected"] for s in feed if s["rejected"]})
    later = await loop.run_in_executor(None, get_shares, feed[-1]["seq"] if feed else 0)
    check("live share feed", ok_n == expected_accepted and {"duplicate", "low-diff"} <= set(reasons) and later == [],
          "(%d accepted, rejected: %s)" % (ok_n, ", ".join(reasons)))

    await asyncio.sleep(1)
    snap = pool.snapshot()
    check("api snapshot", snap["workers"] and snap["workers"][0]["accepted"] == expected_accepted,
          "(accepted %s)" % (snap["workers"][0]["accepted"] if snap["workers"] else None))
    for _ in range(40):
        if pool.proposal["ok"] is not None:
            break
        await asyncio.sleep(0.5)
    check("pool's own proposal check", pool.proposal["ok"] is True, "(%r)" % pool.proposal.get("result"))
    w.close()
    shutil.rmtree(data, ignore_errors=True)


asyncio.run(stratum_test())
print("\n%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
