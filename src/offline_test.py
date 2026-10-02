#!/usr/bin/env python3
"""Checks that need no Bitcoin node: run inside the published image on every platform it's built for
(GitHub runs this on real ARM hardware for each release). python offline_test.py -> exit code 0 if all pass.

selftest.py is the full test and needs a live node; this one covers what can be checked without one:
hashing, merkle trees, jobs and blocks, the template policy, vardiff, share credit, the pool's API, share
checks, connection limits, payout switch and stopping, and that every module and the time zone data load on
this platform. It also times the heaviest step (checking a full template).
"""
import asyncio
import hashlib
import json
import os
import platform
import random
import struct
import sys
import tempfile
import time
import types

os.environ.setdefault("SOLO45_DATA_DIR", tempfile.mkdtemp(prefix="solo45-offline-"))
os.environ.setdefault("SOLO45_DASH_DATA", tempfile.mkdtemp(prefix="solo45-dash-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pool as P  # noqa: E402
import policy  # noqa: E402
import logging  # noqa: E402
P.log.addHandler(logging.NullHandler())  # the pool's log lines (rejected test shares...) aren't test output
import stallguard  # noqa: E402,F401
import zmqsub  # noqa: E402,F401

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print("%s  %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


print("platform: %s %s, Python %s" % (platform.system(), platform.machine(), platform.python_version()))

# 1. hashing: the genesis block header must hash to the genesis block
genesis = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27a"
                        "c72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
check("genesis header hash", P.sha256d(genesis)[::-1].hex()
      == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")


# 2. merkle branch against a naive tree, 1 to 39 transactions
def naive_root(hashes):
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


rng = random.Random(45)
bad = 0
for n in range(1, 40):
    txids = [rng.randbytes(32) for _ in range(n)]
    cb = rng.randbytes(32)
    root = cb
    for h in P.merkle_branch(txids):
        root = dsha(root + h)
    bad += root != naive_root([cb] + txids)
check("merkle branch vs naive tree", bad == 0, "(39 sizes)")


# 3. transactions, a template, jobs sharing transaction memory, and the block they build
def raw_tx(outputs, witness=None):
    tx = struct.pack("<I", 2) + (b"\x00\x01" if witness else b"") + b"\x01" + rng.randbytes(32) + b"\x00\x00\x00\x00" + b"\x00" + b"\xff" * 4
    tx += bytes([len(outputs)]) + b"".join(struct.pack("<q", 1000) + bytes([len(s)]) + s for s in outputs)
    if witness:
        tx += bytes([len(witness)]) + b"".join(bytes([len(w)]) + w for w in witness)
    return tx + bytes(4)


def tx_entry(raw, fee, depends=()):
    txid = dsha(raw)[::-1].hex()  # no witness here, so txid == wtxid
    return {"data": raw.hex(), "txid": txid, "hash": txid, "fee": fee, "weight": len(raw) * 4, "depends": list(depends)}


p2wpkh = b"\x00\x14" + bytes(20)
leaf = bytes([0x20]) + bytes(32) + b"\xac" + b"\x00\x63" + b"\x03ord" + b"\x51" + b"\x05hello" + b"\x68"
txs = []
for i in range(3000):
    if i % 10 == 0:
        t = tx_entry(raw_tx([p2wpkh], [bytes(64), leaf, b"\xc0" + bytes(32)]), 2000)  # an inscription
    else:
        t = tx_entry(raw_tx([p2wpkh, p2wpkh]), 150 + i % 3000)
    txs.append(t)
tpl = {"height": 900000, "previousblockhash": "00" * 32, "version": 0x20000000, "bits": "1d00ffff", "curtime": int(time.time()),
       "mintime": int(time.time()) - 600, "coinbasevalue": 312500000 + sum(t["fee"] for t in txs), "transactions": txs}
tpl["default_witness_commitment"] = policy.witness_commitment(txs).hex()

cfg = policy.load_config({"mode": "filter", "rules": {"minfee": {"on": True, "watch": True, "sat_vb": 10}}})
t0 = time.perf_counter()
rep = policy.evaluate(tpl, cfg)
t_eval = (time.perf_counter() - t0) * 1000
check("policy finds the inscriptions", rep["skipped"] == 300 and rep["by_rule"].get("inscriptions", {}).get("txs") == 300,
      "(skipped %d)" % rep["skipped"])
check("policy watch rule only counts", rep["watched"] > 0 and not set(rep["watch"]) & set(rep["skip"]), "(watched %d)" % rep["watched"])
ftpl = policy.apply(tpl, rep)
cache = {}
t0 = time.perf_counter()
job_a = P.Job("a", tpl, b"/Solo45/", cache)
job_b = P.Job("b", ftpl, b"/Solo45/", cache)
t_job = (time.perf_counter() - t0) * 1000
ids = {id(x) for x in job_a.tx_data}
check("jobs share transaction memory", all(id(x) in ids for x in job_b.tx_data), "(%d txs)" % len(job_b.tx_data))
spk = b"\x00\x14" + bytes(20)
coinbase = job_b.coinb1 + bytes(P.EN1_SIZE + P.EN2_SIZE) + job_b.coinb2(spk)
header = job_b.header(coinbase, job_b.version, job_b.curtime, 0)
block = job_b.block(header, coinbase)
root = naive_root([dsha(coinbase)] + [bytes.fromhex(t["txid"])[::-1] for t in ftpl["transactions"]])
check("block header commits to the right merkle root", header[36:68] == root and block[:80] == header,
      "(%d txs, %.2f MB block)" % (len(ftpl["transactions"]), len(block) / 1e6))

# 4. vardiff: windows, band, two windows must agree, big jumps at once
def vd_worker(diff=1000.0):
    return types.SimpleNamespace(diff=diff, vd_pending=None, override=lambda: {"share_seconds": 15},
                                 pool=types.SimpleNamespace(cfg={"share_seconds": 5, "min_diff": 1}))


def vd(count, elapsed, w=None):
    w = w or vd_worker()
    w.vd_start, w.vd_count, w.vd_work = 100.0, count, count * w.diff
    return P.Worker.vardiff(w, 100.0 + elapsed)


_up = vd_worker()
check("vardiff rules", vd(40, 450) is None and [vd(40, 200, _up), vd(40, 200, _up)] == [None, 3000]
      and vd(40, 100) == 6000 and vd(0, 185) == 250)

# 5. share credit follows the difficulty the miner really used
sw = types.SimpleNamespace(diff=1000.0, job_diff={"old": 8000.0}, switches_at_once=False)
check("share credit", [P.Worker.share_credit(sw, "old", 9000.0), P.Worker.share_credit(sw, "old", 1500.0)] == [8000.0, 1000.0])

# 6. the dashboard's modules, the AI module (its library loads only when used) and the time zones
from zoneinfo import ZoneInfo  # noqa: E402
try:
    check("time zone data", ZoneInfo("America/Chicago").key == "America/Chicago")
except Exception as e:
    check("time zone data", False, "(%s)" % e)
import server  # noqa: E402,F401
try:
    import ai
    check("AI module loads without its library", ai.anthropic is None)
except ImportError as e:
    check("AI module loads without its library", False, "(%s)" % e)

# 7. policy details: the quick multisig look, fee packages, and the watch part done after the job
taproot_ae = b"\x51\x20" + bytes(31) + b"\xae"
multisig = b"\x51\x21" + b"\x02" + bytes(32) + b"\x21" + b"\x03" + bytes(32) + b"\x52\xae"
check("bare multisig vs taproot key ending in 0xae", policy.is_bare_multisig(multisig) and not policy.is_bare_multisig(taproot_ae))
fee_txs = [{"fee": 100, "weight": 800}, {"fee": 5000, "weight": 800, "depends": [1]}, {"fee": 100, "weight": 800}]
check("fee rule: child pays for parent, a lone low fee is low", policy.low_fee(fee_txs, {0, 1, 2}, 10) == {2})
split = policy.add_watch(policy.evaluate(tpl, cfg, watch=False), tpl, cfg)
check("watch part after the job gives the same report", split == rep)

# 8. the pool without a node: its API, shares, connection limits, payout switch and stopping


class FakeWriter:
    def __init__(self, ip):
        self.ip, self.out, self.closed = ip, bytearray(), False

    def get_extra_info(self, key):
        return (self.ip, 40000) if key == "peername" else None

    def write(self, b):
        self.out += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def pool_cfg():
    return dict(P.DEFAULTS, rpc_url="http://127.0.0.1:1/", rpc_cookie="/nonexistent")


async def pool_tests():
    pool = P.Pool(pool_cfg(), data_dir=tempfile.mkdtemp(prefix="solo45-pool-"))

    async def api(raw, ip="10.0.0.5"):
        r = asyncio.StreamReader()
        r.feed_data(raw)
        r.feed_eof()
        w = FakeWriter(ip)
        await pool.serve_api(r, w)
        return bytes(w.out)

    os.environ["SOLO45_API_TOKEN"] = "t0ken"
    no_token = await api(b"GET /api HTTP/1.1\r\n\r\n")
    with_token = await api(b"GET /api HTTP/1.1\r\nX-Solo45-Token: t0ken\r\n\r\n")
    garbage = await api(b"POST /api/settings HTTP/1.1\r\nX-Solo45-Token: t0ken\r\nContent-Length: abc\r\n\r\n")
    body = json.dumps({"force_default_address": False}).encode()
    switch = await api(b"POST /api/settings HTTP/1.1\r\nX-Solo45-Token: t0ken\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    switched_off = not pool.force_default()
    del os.environ["SOLO45_API_TOKEN"]
    check("pool API: reads need the token, no CORS, bad requests get 400",
          no_token.startswith(b"HTTP/1.1 403") and with_token.startswith(b"HTTP/1.1 200")
          and b"Access-Control" not in with_token and garbage.startswith(b"HTTP/1.1 400"),
          "(%s / %s / %s)" % (no_token[:12], with_token[:12], garbage[:12]))
    # without a token set, only the machine itself may use it
    lan, v4, v6 = [await api(b"GET /api HTTP/1.1\r\n\r\n", ip=ip) for ip in ("10.0.0.5", "127.0.0.1", "::1")]
    check("pool API without a token: this machine only", lan.startswith(b"HTTP/1.1 403")
          and v4.startswith(b"HTTP/1.1 200") and v6.startswith(b"HTTP/1.1 200"), "(%s / %s / %s)" % (lan[:12], v4[:12], v6[:12]))

    # the node's check of refresh jobs spaces out when it's slow (a Raspberry Pi); the dashboard gets the numbers
    every = [pool.check_every_s()]
    pool.check_times.extend([27] * 5)
    every.append(pool.check_every_s())
    pool.check_times.extend([1000] * 20)
    every.append(pool.check_every_s())
    pool.build_times.extend([150, 140, 160])
    timing = pool.snapshot()["pool"]["timing"]
    check("block checks space out on a slow machine, timings reported", every == [10.0, 10.0, 60.0]
          and timing["check_ms"] == 1000 and timing["build_ms"] == 150, "(%s, %s)" % (every, timing))

    # "Always pay my address": on for a new install, off stays off, and an address must be set for it to apply
    old_dir = tempfile.mkdtemp(prefix="solo45-old-")
    with open(os.path.join(old_dir, "state.json"), "w") as f:
        f.write("{}")
    new_install_on = P.Pool(pool_cfg(), data_dir=tempfile.mkdtemp(prefix="solo45-new-")).force_default()
    older_off = not P.Pool(pool_cfg(), data_dir=old_dir).force_default()
    spk_a, spk_b = b"\x00\x14" + b"\xaa" * 20, b"\x00\x14" + b"\xbb" * 20
    pool.spk_cache["addrB"] = spk_b
    pool.state["settings"]["force_default_address"] = True
    before_setup = await pool.payout_for("addrB.rig")  # switch on, but no payout address yet: the username's works
    pool.cfg["default_address"], pool.default_spk = "addrA", spk_a
    on = await pool.payout_for("addrB.rig")
    pool.state["settings"]["force_default_address"] = False
    off = await pool.payout_for("addrB.rig")
    check("payout switch", switch.startswith(b"HTTP/1.1 200") and switched_off and new_install_on and older_off
          and before_setup == ("addrB", spk_b) and on == ("addrA", spk_a) and off == ("addrB", spk_b),
          "(%s %s %s %s %s)" % (switched_off, new_install_on, older_off, on[0], off[0]))

    # shares: junk that fails the difficulty check isn't remembered; a block share is never called stale
    job = P.Job("j1", tpl, b"/Solo45/", {})
    pool.jobs[job.id], pool.job, pool.tip = job, job, job.prev_hex
    w = P.Worker(pool, asyncio.StreamReader(), FakeWriter("10.0.0.7"))
    w.authorized, w.spk, w.name = True, spk_a, "rig"
    w.job_diff[job.id] = w.diff = 1e6

    def share(nonce):
        return ["rig", job.id, "00" * 8, "%08x" % job.curtime, "%08x" % nonce]

    rejected = 0
    for nonce in range(50):
        try:
            await w.submit(share(nonce))
        except P.StratumError:
            rejected += 1
    after_junk = len(job.seen)
    w.job_diff[job.id] = w.diff = 1e-12
    accepted = await w.submit(share(1000))
    try:
        await w.submit(share(1000))
        duplicate = False
    except P.StratumError as e:
        duplicate = e.code == 22
    calls = []

    async def found(*a):
        calls.append(a)
    pool.found_block, job.target, pool.tip = found, 2 ** 256 - 1, "ff" * 32  # every share a block, on an old tip
    block_ok = await w.submit(share(2000))
    check("shares: low-difficulty ones not remembered, duplicates caught, block shares never stale",
          rejected == 50 and after_junk == 0 and accepted is True and duplicate and block_ok is True and len(calls) == 1,
          "(%d rejected, %d remembered, dup %s, block %s)" % (rejected, after_junk, duplicate, block_ok))

    # connection limits: over the per-address cap is closed at once; a quiet unauthorized connection times out
    pool.conns["10.0.0.9"] = pool.cfg["max_conns_per_ip"]
    capped = FakeWriter("10.0.0.9")
    await pool.serve_stratum(asyncio.StreamReader(), capped)
    idle = P.Worker(pool, asyncio.StreamReader(), FakeWriter("10.0.0.10"))
    idle.connected -= P.AUTH_WINDOW_S + 5
    t0 = time.time()
    await idle.run()
    check("stratum connection limits", capped.closed and pool.conns["10.0.0.9"] == pool.cfg["max_conns_per_ip"]
          and time.time() - t0 < 2, "(idle connection closed after %.1f s)" % (time.time() - t0))

    # stopping (Docker's stop signal) keeps the state
    pool.state["accepted_total"] = 4545
    await pool.stop()
    with open(pool.state_path) as f:
        check("stop saves the state", json.load(f)["accepted_total"] == 4545)


asyncio.run(pool_tests())
server.save_all()
check("dashboard saves everything on the way out", all(os.path.exists(p) for p in (
    server.HISTORY_PATH, server.TEMPS_PATH, server.DAILY_PATH, server.WORK_PATH, server.BLOCKS_PATH)))
import queue  # noqa: E402
stuck = queue.Queue(maxsize=20)  # a closed tab behind the Umbrel proxy: connected, but never reads
server.subscribers.add(stuck)
for _ in range(25):
    server.broadcast("state", {"n": 1})
check("a viewer that stops reading is dropped, not queued for forever", stuck not in server.subscribers and stuck.qsize() == 20)
if platform.system() == "Linux":
    check("memory release (malloc_trim) available", P.malloc_trim is not None and server.malloc_trim is not None)

print("timing: policy check of %d txs %.0f ms, two jobs %.0f ms" % (len(txs), t_eval, t_job))
print("%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
