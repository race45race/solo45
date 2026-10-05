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
    check("the pool remembers the block of a miner's latest share", w.snapshot(time.time())["last_height"] == job.height)

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
r1, r2, r3 = {"asic_errors": 100}, {"asic_errors": 160}, {"asic_errors": 5}
server.track_error_rate("test", r1, 1000.0)
server.track_error_rate("test", r2, 1180.0)  # 60 more errors in 3 minutes
server.track_error_rate("test", r3, 1200.0)  # the counter went down: the miner restarted
check("tuning report: chip errors per minute", r1["errors_per_min"] is None and r2["errors_per_min"] == 20.0
      and r3["errors_per_min"] is None, "(%s %s %s)" % (r1.get("errors_per_min"), r2.get("errors_per_min"), r3.get("errors_per_min")))
import urllib.error  # noqa: E402
_real_http = server.http_json


def _fake_http(url, timeout=3, headers=None):
    if url.endswith("/v2/miner/status"):
        return {"ok": True, "data": {"current_hashrate": 3.08e12, "temp_board": 48.1, "temp_vcore": 74.5,
                                     "power_consumption": 33.0, "fan_target_speed": 76, "bestDiff": 1441558099,
                                     "bestSessionDiff": 94421, "shares_accepted": 25, "shares_rejected": 0,
                                     "pool_url": "192.168.1.5", "pool_port": 3333, "pool_worker": "bc1qtest.ThorX1",
                                     "isUsingFallbackStratum": False, "frequency": 460, "coreVoltage": 101,
                                     "chips": [{"temperature": 52.2, "hardware_errors": 7}]}}
    if url.endswith("/v2/device/info"):
        return {"ok": True, "data": {"device_model": "THOR X1", "chip_type": "BM1373", "firmware_version": "1.0.5"}}
    if url.endswith("/v2/device/status"):
        return {"ok": True, "data": {"uptime_seconds": 600, "wifi_rssi": -60}}
    raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # not AxeOS


def _no_cgminer(*a, **k):
    raise ConnectionRefusedError()  # nothing listens on 4028


_real_cgminer = server.cgminer
server.http_json, server.cgminer = _fake_http, _no_cgminer
server.kind_cache.pop("10.9.9.9", None)
_t = server.poll_one("10.9.9.9")  # AxeOS 404, no Braiins API on 4028, then Thor OS answers
server.http_json, server.cgminer = _real_http, _real_cgminer
check("Hammer Thor X1 is read like a Bitaxe", _t["kind"] == "thor" and _t["name"] == "ThorX1"
      and _t["model"] == "Hammer Thor X1" and abs(_t["ths"] - 3.08) < 1e-9 and _t["temp"] == 52.2
      and _t["temp2"] == 74.5 and _t["power"] == 33.0 and _t["core_mv"] == 1010 and _t["hw_errors"] == 7
      and _t["uptime"] >= 600 and server.kind_cache.get("10.9.9.9") == "thor", str({k: _t.get(k) for k in ("kind", "name", "model", "ths", "temp")}))
check("an offline miner isn't asked in every miner language",
      server.unreachable(urllib.error.URLError(TimeoutError())) and not server.unreachable(urllib.error.HTTPError("u", 404, "x", None, None)))
_mara = {
    "summary": {"STATUS": [{"Description": "kaonsu-old-api 1.0.0"}],
                "SUMMARY": [{"GHS 5s": 100055.5, "GHS 30m": 100077.5, "Accepted": 8, "Rejected": 0, "Elapsed": 1649,
                             "Best Share": 3290000, "Hardware Errors": 0}]},
    "stats": {"STATS": [{"BMMiner": "MaraFW rel 3.12_401", "Model": "Antminer S19k Pro"},
                        {"temp_chip1": "49-58", "temp_chip2": "49-56", "temp_chip3": "0-0-0-0", "temp_pcb1": "44-53", "temp_pcb2": "44-51"}]},
    "pools": {"POOLS": [{"URL": "stratum+tcp://192.168.1.5:3333", "Status": "Alive", "Priority": 0, "User": "bc1qtest.S19KPro",
                         "Stratum Active": False, "Getworks": 6},
                        {"URL": "stratum+tcp://solo.example.com:3333", "Status": "Dead", "Priority": 1, "User": "x.y"}]},
}
_braiins_summary = {"STATUS": [{"Description": "BOSer"}], "SUMMARY": [{"MHS 5s": 1.2e8}]}
server.cgminer = lambda ip, cmd, timeout=3: (_mara if ip == "10.9.9.10" else {"summary": _braiins_summary})[cmd]
server.http_json = _fake_http
server.kind_cache.pop("10.9.9.10", None)
_m = server.poll_one("10.9.9.10")  # AxeOS 404, then MARA answers
_not_mara = None
try:
    server.poll_mara("10.9.9.11")
except ValueError:
    _not_mara = True
server.http_json, server.cgminer = _real_http, _real_cgminer
check("MARA firmware is read in TH/s with its name, pool and temperatures", _m["kind"] == "mara" and _m["name"] == "S19KPro"
      and abs(_m["ths"] - 100.0555) < 1e-6 and abs(_m["ths_long"] - 100.0775) < 1e-6 and _m["temp"] == 58 and _m["temp2"] == 53
      and _m["pool"] == "Solo45" and _m["on_fallback"] is False and _m["power"] is None and _not_mara,
      str({k: _m.get(k) for k in ("kind", "name", "ths", "temp", "temp2", "pool")}))
_s17 = {
    "version": {"VERSION": [{"BMMiner": "1.0.0", "API": "3.1", "Miner": "19.10.1.3", "Type": "Antminer S17 Pro"}]},
    "summary": {"STATUS": [{"Description": "cgminer 1.0.0"}],
                "SUMMARY": [{"GHS 5s": "38537.88", "GHS av": 46111.62, "GHS 30m": 46111.62, "Accepted": 58, "Rejected": 0,
                             "Elapsed": 82, "Best Share": 378593, "Hardware Errors": 0}]},
    "stats": {"STATS": [{"Type": "Antminer S17 Pro"}, {"temp_chip1": "49-52-45-49", "temp_chip2": "50-53-46-48", "temp_pcb1": "31-40-29-37", "fan1": 5400}]},
    "pools": {"POOLS": [{"URL": "stratum+tcp://192.168.1.5:3333", "Status": "Alive", "Priority": 0, "User": "bc1qtest.S17Pro",
                         "Stratum Active": True, "Last Share Time": "0:00:01", "Getworks": 3}]},
}
_bos = {"version": {"VERSION": [{"API": "3.7", "BOSer": "boser-buildroot"}]}, "summary": _braiins_summary}
server.cgminer = lambda ip, cmd, timeout=3: (_s17 if ip == "10.9.9.14" else _bos)[cmd]
server.http_json = _fake_http
server.kind_cache.pop("10.9.9.14", None)
_b = server.poll_one("10.9.9.14")
_not_stock = None
try:
    server.poll_bitmain("10.9.9.15")
except ValueError:
    _not_stock = True
server.http_json, server.cgminer = _real_http, _real_cgminer
check("stock Bitmain firmware is read in TH/s, text values and all", _b["kind"] == "bitmain" and _b["name"] == "S17Pro"
      and abs(_b["ths"] - 38.53788) < 1e-6 and abs(_b["ths_long"] - 46.11162) < 1e-6 and _b["temp"] == 53 and _b["temp2"] == 40
      and _b["pool"] == "Solo45" and _not_stock, str({k: _b.get(k) for k in ("kind", "name", "ths", "temp", "temp2", "pool")}))
_ok = True
try:
    server.miner_status({"name": "x", "kind": "braiins", "temp": 50, "ths": 1, "last_share": "0:00:01", "ok": True}, None)
except Exception:
    _ok = False
check("a miner's text 'last share' can't break the page", _ok)
from concurrent.futures import ThreadPoolExecutor  # noqa: E402
_real = (server.miner_ips, server.poll_one, server.record)
_calls = []


def _slow_poll_one(ip):
    if ip == "10.9.9.20":
        time.sleep(3)  # an offline miner timing out
        raise TimeoutError("timed out")
    return {}


server.miner_ips = lambda: ["10.9.9.20", "10.9.9.21"]
server.poll_one = _slow_poll_one
server.record = lambda ip, r, e: _calls.append(ip)
_pool, _inflight = ThreadPoolExecutor(4), {}
_t0 = time.time()
_r1 = server.poll_round(_pool, _inflight, _t0)
_dt = time.time() - _t0
time.sleep(0.3)
_r2 = server.poll_round(_pool, _inflight, time.time())  # the slow one is still busy: only the other is asked again
_saved_m = dict(server.S["miners"])
server.S["miners"].clear()
server.S["miners"]["10.9.9.20"] = {"ok": False, "polled": time.time() - 10}
server.miner_ips = lambda: ["10.9.9.20"]
_r3 = server.poll_round(_pool, {}, time.time())  # offline and asked 10 s ago: rests
server.S["miners"]["10.9.9.20"]["polled"] = time.time() - 70
_r4 = server.poll_round(_pool, {}, time.time())  # a minute later: asked again
_pool.shutdown(wait=True)  # let the slow reads finish before putting the real functions back
server.S["miners"].clear()
server.S["miners"].update(_saved_m)
server.miner_ips, server.poll_one, server.record = _real
check("a slow or offline miner can't hold up the others' polling", _dt < 0.5 and set(_r1) == {"10.9.9.20", "10.9.9.21"}
      and _r2 == ["10.9.9.21"] and "10.9.9.21" in _calls, "(round took %.2f s, then %s)" % (_dt, _r2))
check("an offline miner is asked once a minute, not every poll", _r3 == [] and _r4 == ["10.9.9.20"])
_saved = dict(server.S["miners"])
server.S["miners"].clear()
server.S["miners"]["10.9.9.12"] = {"ip": "10.9.9.12", "fails": 9, "first_seen": time.time() - 2 * 86400, "last_ok": time.time() - 2 * 86400}
server.S["miners"]["10.9.9.13"] = {"ip": "10.9.9.13", "fails": 0, "first_seen": time.time() - 2 * 86400, "last_ok": time.time() - 60}
_ips = server.miner_ips()
check("a miner gone for a day leaves the table, a working one stays", "10.9.9.12" not in _ips and "10.9.9.13" in _ips)
server.S["miners"].clear()
server.S["miners"].update(_saved)
_workers = server.S["solo45"].get("workers")
server.S["solo45"]["workers"] = [{"name": "ThorX1", "connected": 0, "hashrate_1h": 3e12, "last_height": 969700}]
_e1 = server.miner_extras({"name": "ThorX1", "height": None, "power": 33}, time.time())
_e2 = server.miner_extras({"name": "ThorX1", "height": 969699, "power": 33}, time.time())
server.S["solo45"]["workers"] = _workers
check("a miner without its own block number shows the block of its latest share",
      _e1.get("height") == 969700 and _e1.get("height_src") == "pool" and "height" not in _e2)
server.STRATUM_PORT = "3337"  # the official Umbrel app's port
check("miners on the app's stratum port count as Solo45", server.pool_name("192.168.1.5", 3337) == "Solo45"
      and server.pool_name("stratum+tcp://192.168.1.5", "3333") == "Solo45" and server.pool_name("10.0.0.2", 23334) == "Datum"
      and server.pool_name("solo.ckpool.org", 3337) == "solo.ckpool.org")
if platform.system() == "Linux":
    check("memory release (malloc_trim) available", P.malloc_trim is not None and server.malloc_trim is not None)

async def empty_first_tests():
    pool = P.Pool(pool_cfg(), data_dir=tempfile.mkdtemp(prefix="solo45-empty-"))
    pool.chain = "main"
    pool.state["settings"]["empty_hold_s"] = 0.3
    sent = []

    class FW:
        authorized, spk = True, None

        async def send_job(self, job, clean):
            sent.append((job.id, clean))
    pool.workers.add(FW()) if hasattr(pool.workers, "add") else pool.workers.append(FW())
    base = {"height": 970000, "previousblockhash": "11" * 32, "version": 0x20000000, "bits": "17022b8b",
            "curtime": 1790000000, "mintime": 1789990000, "coinbasevalue": 312505000, "transactions": []}
    hdr = {"hash": "22" * 32, "previousblockhash": "11" * 32, "height": 970000, "bits": "17022b8b", "mediantime": 1790000500}
    full = dict(base, height=970001, previousblockhash="22" * 32, coinbasevalue=312600000)
    fetched = []

    async def fake_call(method, *params, timeout=15):
        if method == "getblockheader":
            return hdr
        if method == "getblocktemplate":
            if params and params[0].get("mode") == "proposal":
                return None
            fetched.append(1)
            return full
        raise AssertionError(method)
    pool.call = fake_call
    await pool.update_template(clean=True, tpl=base)
    first = pool.job
    ok = await pool.empty_first("22" * 32, "test")
    ej = pool.job
    await pool.update_template(clean=True, tpl=full)  # the long-poll's full template, during the hold
    held = pool.job is ej and not fetched
    await asyncio.sleep(0.6)  # the hold ends: a fresh full template goes out
    fj = pool.job
    check("empty block first: coinbase-only work for the next block at once", ok and ej.empty and ej.height == 970001
          and ej.prev_hex == "22" * 32 and ej.value == 312500000 and not ej.tx_data and not ej.branch
          and ej.bits == 0x17022b8b and ej.curtime >= 1790000501 and ej.witness_commitment is None
          and ej.block(b"h" * 80, b"cb")[80:] == b"\x01cb", str((ok, ej.height, ej.value, len(ej.tx_data))))
    check("empty block first: the full template waits out the hold, then goes out without a forced restart",
          held and fetched and fj is not ej and fj.value == 312600000 and not getattr(fj, "empty", False)
          and sent == [(first.id, True), (ej.id, True), (fj.id, False)], str(sent))
    check("empty block first: not for a new difficulty period", P.empty_template(dict(hdr, height=2015), 0x20000000) is None
          and P.empty_template(dict(hdr, height=839999), 0x20000000)["coinbasevalue"] == 312500000
          and P.empty_template(dict(hdr, height=1049999), 0x20000000)["coinbasevalue"] == 156250000)
    pool.chain = "test"
    check("empty block first: mainnet only", await pool.empty_first("44" * 32, "test") is False)


asyncio.run(empty_first_tests())
print("timing: policy check of %d txs %.0f ms, two jobs %.0f ms" % (len(txs), t_eval, t_job))
print("%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
