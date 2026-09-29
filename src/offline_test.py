#!/usr/bin/env python3
"""Checks that need no Bitcoin node: run inside the published image on every platform it's built for
(GitHub runs this on real ARM hardware for each release). python offline_test.py -> exit code 0 if all pass.

selftest.py is the full test and needs a live node; this one covers what can be checked without one:
hashing, merkle trees, jobs and blocks, the template policy, vardiff, share credit, and that every module and
the time zone data load on this platform. It also times the heaviest step (checking a full template).
"""
import hashlib
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

print("timing: policy check of %d txs %.0f ms, two jobs %.0f ms" % (len(txs), t_eval, t_job))
print("%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
