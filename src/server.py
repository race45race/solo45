#!/usr/bin/env python3
"""Solo Mining Dashboard: a live view of an Umbrel solo-mining fleet.

Reads the Bitcoin Core log as it is written (and a ckpool log, if another pool
such as Go Brrr runs on the same Umbrel), polls Bitaxe (AxeOS HTTP API) and
Braiins OS (CGMiner API, port 4028) miners and the Solo45 pool, and serves one
page plus a Server-Sent Events stream. It changes Solo45's settings only when
the user asks, and can send phone alerts through ntfy.
The optional Claude assistant (ai.py) needs the anthropic library from ./venv.
"""
import base64
import collections
import ctypes
import json
import math
import os
import queue
import re
import signal
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

import zmqsub

HOME = os.path.expanduser("~")
BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("SOLO45_DASH_DATA") or BASE  # config.json and the saved history
NODE_DIR = os.environ.get("BITCOIN_DATA_DIR") or HOME + "/umbrel/app-data/bitcoin/data/bitcoin"
SOLO45 = os.environ.get("SOLO45_API_BASE") or "http://127.0.0.1:3380"
CFG_PATH = os.path.join(DATA, "config.json")
HISTORY_PATH = os.path.join(DATA, "history.json")
BLOCKS_PATH = os.path.join(DATA, "blocks.json")
DAILY_PATH = os.path.join(DATA, "best_today.json")
BEST_HISTORY_PATH = os.path.join(DATA, "best_history.json")
WORK_PATH = os.path.join(DATA, "work.json")
TEMPS_PATH = os.path.join(DATA, "temps.json")
NTFY_TOKEN_PATH = os.path.join(DATA, "ntfy_token")  # only for a password-protected ntfy server

CFG = {
    "port": 8099,
    "bitcoin_log": NODE_DIR + "/debug.log",
    "ckpool_log": os.environ.get("GOBRRR_LOG") or "",  # a ckpool-based pool's log (e.g. Go Brrr), for its timings
    "miners": [],   # extra miner IPs, on top of those connected to Solo45 (or found in a ckpool log)
    "ignore": [],   # miner IPs to leave out entirely
    "pools": {"23334": "Datum", "21420": "Go Brrr", "21422": "Go Brrr (high diff)", "3333": "Solo45"},
    "poll_seconds": 5,
    "solo45_api": SOLO45 + "/api",
    "solo45_settings_api": SOLO45 + "/api/worker",
    "solo45_pool_settings_api": SOLO45 + "/api/settings",
    "solo45_policy_api": SOLO45 + "/api/policy",
    "solo45_payout_api": SOLO45 + "/api/payout",
    "solo45_shares_api": SOLO45 + "/api/shares",
    "rpc_url": "http://127.0.0.1:8332/",
    "rpc_cookie": NODE_DIR + "/.cookie",
    "rpc_user": "",  # when set, used instead of the cookie file
    "rpc_pass": "",
    "zmq_hashblock": "",  # e.g. tcp://10.21.21.8:28334: new blocks straight from the node, no log reading needed
    "kwh_price": 0.12,  # price per kWh for the electricity cost figures; set on the dashboard
    "currency": "$",    # symbol shown with costs
    "timezone": "",     # the user's time zone, taken from their browser, e.g. America/Chicago ("" = the server's)
    "ai": {"model": "claude-opus-5", "weekly_cap_usd": 2.0, "monthly_cap_usd": 8.0, "report_hour": 8,
           "report_every_days": 3},
    # phone alerts through ntfy (https://ntfy.sh or your own server); off until the user turns them on
    "notify": {"on": False, "server": "https://ntfy.sh", "topic": "", "after_min": 10, "click": "",
               "events": {"block": True, "best": True, "offline": True, "hot": True, "node": True}},
}
if os.path.exists(CFG_PATH):
    with open(CFG_PATH) as f:
        _user = json.load(f)
    CFG["ai"].update(_user.pop("ai", {}))
    _notify = _user.pop("notify", {})
    CFG["notify"]["events"].update(_notify.pop("events", {}))
    CFG["notify"].update(_notify)
    CFG.update(_user)
for _var, _key, _kind in (("SOLO45_DASH_PORT", "port", int), ("BITCOIN_RPC_URL", "rpc_url", str),
                          ("BITCOIN_RPC_USER", "rpc_user", str), ("BITCOIN_RPC_PASS", "rpc_pass", str),
                          ("BITCOIN_ZMQ_HASHBLOCK", "zmq_hashblock", str)):
    if os.environ.get(_var):  # environment settings (used by the Umbrel app) win over config.json
        CFG[_key] = _kind(os.environ[_var])

try:  # the assistant needs the anthropic library, installed in ./venv
    import ai
except Exception as e:  # a broken or missing assistant must never take the dashboard down
    ai = None
    print("AI assistant disabled:", e, flush=True)
assistant = None

try:  # glibc keeps memory that Python freed in per-thread pools; malloc_trim hands it back (absent elsewhere)
    malloc_trim = ctypes.CDLL("libc.so.6").malloc_trim
except (OSError, AttributeError):
    malloc_trim = None

lock = threading.RLock()
subscribers = set()
fast_poll_until = 0.0
new_block = threading.Event()  # wakes the miner poller the moment a block arrives

S = {
    "started": time.time(),
    "tip": None,
    "blocks": [],        # newest first
    "gobrrr": {},        # latest ckpool pool/user stats
    "ck_workers": {},    # ip -> {worker, last_auth, last_drop}
    "miners": {},        # ip -> latest poll result
    "netdiff": None,
    "reward_sats": None,
    "history": [],       # [unix_ts, total_ths, {pool: ths}]
    "found": [],         # block-solve log lines, hopefully one day
    "solo45": {"up": False},  # latest Solo45 pool API reply
    "shares": collections.deque(maxlen=200),  # live share feed from Solo45, oldest first
    "daily": {},         # {"date", "miners": {name: {"best", "at", "hashes"}}}: best share today
    "best_history": [],  # one entry per finished day: {"date", "best", "name", "typical", "miners"}
    "work": {},          # {"month", "hashes", "since", "prev"}: fleet hashes this month
    "temps": {},         # name -> [[t, chip, vr, online], ...] every 5 minutes for 24 h
    "node": {},          # node, network, difficulty-adjustment and halving stats
    "notify_log": [],    # the last phone alerts sent, newest first: {"t", "title"}
}
ck_pending = {}          # block hash -> ckpool "Block hash changed" time (ms)
solo_pending = {}        # block hash -> time (ms) Solo45 sent work on top of it
work_changes = collections.deque(maxlen=50)  # (ms, ip): a Braiins miner received new work


def note_switch(blk, ip, t):
    """Record that the miner at ip got work for blk at time t (ms); call with lock held."""
    m = S["miners"].get(ip) or {}
    name = m.get("name")
    if not name or name in blk["miners"]:
        return
    ms = t - blk["seen_ms"]
    blk["miners"][name] = ms
    if m.get("pool") == "Datum" and (blk.get("datum_ms") is None or ms < blk["datum_ms"]):
        blk["datum_ms"] = ms


def now_ms():
    return int(time.time() * 1000)


def local_now():
    """Now on the user's clock, so "today" and "this month" start at their midnight (the app itself runs on UTC)."""
    if CFG.get("timezone"):
        try:
            return datetime.now(ZoneInfo(CFG["timezone"]))
        except Exception:
            pass
    return datetime.now().astimezone()


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def broadcast(event, data):
    msg = "event: %s\ndata: %s\n\n" % (event, json.dumps(data, separators=(",", ":")))
    for q in list(subscribers):
        try:
            q.put_nowait(msg)
        except queue.Full:
            # a viewer that stopped reading (a closed tab or a sleeping phone, while the Umbrel proxy keeps the
            # connection open): stop queueing for it; its connection closes when the write timeout hits
            subscribers.discard(q)


# ---------------------------------------------------------------- log tailing

def tail(path, on_line, start_at_end=True):
    """Follow a log file forever, surviving rotation and truncation."""
    f, inode, buf = None, None, ""
    while True:
        try:
            if f is None:
                f = open(path, "r", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
                if start_at_end:
                    f.seek(0, 2)
                start_at_end = False  # a rotated file is read from its start
                buf = ""
            chunk = f.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    line, buf = buf.rstrip("\n"), ""
                    try:
                        on_line(line, True)
                    except Exception as e:  # never let one bad line kill the tail
                        print("line error:", e, flush=True)
                continue
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = None
                continue
            time.sleep(0.02)
        except OSError:
            f = None
            time.sleep(2)


def read_tail_lines(path, max_bytes):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
        lines = data.split("\n")
        return lines[1:] if size > max_bytes else lines
    except OSError:
        return []


UPDATETIP = re.compile(
    r"^(\S+?)Z? UpdateTip: new best=([0-9a-f]{64}) height=(\d+) .*?tx=(\d+) date='([^']+)'")


def iso_ms(s):
    s = s.rstrip("Z")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in s else "%Y-%m-%dT%H:%M:%S"
    return int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)


def on_node_line(line, live):
    m = UPDATETIP.search(line)
    if m:
        add_block(int(m.group(3)), m.group(2), now_ms() if live else iso_ms(m.group(1)), iso_ms(m.group(5)), live)


def on_new_tip(bhash, seen_ms, live=True):
    """A new best block announced by the node (ZMQ or RPC polling)."""
    with lock:
        if S["tip"] and S["tip"]["hash"] == bhash:
            return
    hdr = rpc("getblockheader", bhash)
    add_block(hdr["height"], bhash, seen_ms, hdr["time"] * 1000, live)


def add_block(height, bhash, seen_ms, mined_ms, live):
    blk = {
        "height": height,
        "hash": bhash,
        "seen_ms": seen_ms,
        "mined_ms": mined_ms,
        "live": live,
        "gobrrr_ms": None,
        "solo45_ms": None,
        "datum_ms": None,
        "miners": {},
    }
    global fast_poll_until
    with lock:
        if S["tip"] and S["tip"]["hash"] == bhash:
            return
        if bhash in ck_pending:
            blk["gobrrr_ms"] = ck_pending.pop(bhash) - blk["seen_ms"]
        if live and bhash in solo_pending:
            t, build_ms = solo_pending.pop(bhash)
            blk["solo45_ms"], blk["solo45_build_ms"] = t - blk["seen_ms"], build_ms
        if live:
            # a Braiins miner may have received the new work just before we read the log line.
            # Keep the window short: a routine Datum refresh ~0.3 s earlier was once miscounted.
            for t, ip in list(work_changes):
                if blk["seen_ms"] - 150 <= t <= blk["seen_ms"]:
                    note_switch(blk, ip, t)
        S["tip"] = blk
        S["blocks"].insert(0, blk)
        del S["blocks"][50:]
        if live:
            fast_poll_until = time.time() + 8  # Bitaxes switch within ~1 s; 8 s leaves plenty of margin
            new_block.set()
    if live:
        broadcast("block", blk)
        save_blocks()


CK_LINE = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\] (.*)$")
CK_AUTH = re.compile(r"(Authorised|Dropped) client \d+ ([\d.]+) .*?worker [^.\s]+\.(\S+)")


def ck_ms(ts):
    return int(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def on_ck_line(line, live):
    m = CK_LINE.match(line)
    if not m:
        return
    ts, msg = m.group(1), m.group(2)
    if msg.startswith("Block hash changed to "):
        bhash, t = msg.split()[-1], ck_ms(ts)
        with lock:
            for b in S["blocks"]:
                if b["hash"] == bhash:
                    b["gobrrr_ms"] = t - b["seen_ms"]
                    break
            else:
                ck_pending[bhash] = t
                if len(ck_pending) > 50:
                    ck_pending.pop(next(iter(ck_pending)))
        if live:
            broadcast("gobrrr_work", {"hash": bhash, "t": t})
            save_blocks()
    elif msg.startswith("Pool:{") or msg.startswith("User "):
        try:
            payload = json.loads(msg[msg.index("{"):])
        except ValueError:
            return
        with lock:
            key = "pool" if msg.startswith("Pool:") else "user"
            S["gobrrr"].setdefault(key, {}).update(payload)
            S["gobrrr"]["updated_ms"] = ck_ms(ts)
    elif "Authorised client" in msg or "Dropped client" in msg:
        a = CK_AUTH.search(msg)
        if a:
            with lock:
                w = S["ck_workers"].setdefault(a.group(2), {})
                w["worker"] = a.group(3)
                w["last_auth" if a.group(1) == "Authorised" else "last_drop"] = ck_ms(ts)
    elif re.search(r"BLOCK ACCEPTED|Solved and confirmed block|Possible block solve", msg, re.I):
        with lock:
            S["found"].append({"t": ck_ms(ts), "msg": msg[:300]})
        if live:
            broadcast("found", {"t": ck_ms(ts), "msg": msg[:300]})


# ------------------------------------------------------------------- Solo45

def solo45_loop():
    """Poll the Solo45 pool API; time its block switches against the node log."""
    seen_found = set()
    last_seq, last_uptime = 0, 0.0
    while True:
        try:
            d = http_json(CFG["solo45_api"], timeout=3, headers=pool_headers())
            if d.get("uptime", 0) < last_uptime:
                last_seq = 0  # the pool restarted, so its share numbers start again at 1
            last_uptime = d.get("uptime", 0)
            new = http_json("%s?since=%d" % (CFG["solo45_shares_api"], last_seq), timeout=3, headers=pool_headers())["shares"]
            if new:
                last_seq = new[-1]["seq"]
                with lock:
                    S["shares"].extend(new)
                    # Solo45 sees every share, so its miners' best of the day is exact
                    today = local_now().strftime("%Y-%m-%d")
                    if S["daily"].get("date") == today:
                        for sh in new:
                            rec = S["daily"]["miners"].get(sh["worker"])
                            if rec is not None and not sh["rejected"] and (sh["share"] or 0) > rec["best"] \
                                    and sh["t"] >= S["daily"].get("since", 0):
                                rec["best"], rec["at"] = sh["share"], sh["t"]
                broadcast("shares", new)
            p = d["pool"]
            sw = p.get("last_switch")
            with lock:
                S["solo45"] = dict(p, up=True, workers=d["workers"], checked=time.time())
                if sw and sw.get("workers") and p.get("prev"):  # 0 workers = pool (re)start
                    t = int(sw["at"] * 1000)
                    for b in S["blocks"]:
                        if b["hash"] == p["prev"]:
                            if b["live"] and b.get("solo45_ms") is None:
                                b["solo45_ms"] = t - b["seen_ms"]
                                b["solo45_build_ms"] = sw.get("ms")
                            break
                    else:
                        solo_pending[p["prev"]] = (t, sw.get("ms"))
                        while len(solo_pending) > 20:
                            solo_pending.pop(next(iter(solo_pending)))
                for blk in p.get("blocks") or []:
                    if blk["hash"] not in seen_found:
                        seen_found.add(blk["hash"])
                        msg = "Solo45: block %d by %s, node said %s" % (
                            blk["height"], blk["worker"], blk["result"] or "accepted")
                        S["found"].append({"t": int(blk["at"] * 1000), "msg": msg})
        except (OSError, ValueError) as e:  # Solo45 really didn't answer (or sent something unreadable)
            err = str(e)[:120]
            if isinstance(e, urllib.error.HTTPError) and e.code == 403:
                err = "the pool turned the dashboard away: give both the same SOLO45_API_TOKEN"
            with lock:
                S["solo45"] = dict(S["solo45"], up=False, error=err)
        except Exception as e:  # a bug in this loop is not a pool outage: log it, don't raise the alarm
            print("solo45_loop error: %r" % e, flush=True)
        time.sleep(1)


# --------------------------------------------------------------------- node

def rpc(method, *params):
    if CFG["rpc_user"]:
        auth = base64.b64encode(("%s:%s" % (CFG["rpc_user"], CFG["rpc_pass"])).encode()).decode()
    else:
        with open(CFG["rpc_cookie"]) as f:
            auth = base64.b64encode(f.read().strip().encode()).decode()
    body = json.dumps({"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(CFG["rpc_url"], body, {"Content-Type": "text/plain", "Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=10) as r:
        reply = json.load(r)
    if reply.get("error"):
        raise RuntimeError(reply["error"])
    return reply["result"]


def zmq_loop(url):
    """New blocks the moment the node connects them, from its ZMQ feed (zmqpubhashblock)."""
    host, port = url.replace("tcp://", "").rsplit(":", 1)
    while True:
        sub = None
        try:
            sub = zmqsub.ZmqSub(host, int(port))
            print("listening for new blocks on %s" % url, flush=True)
            while True:
                parts = sub.recv()
                if len(parts) >= 2 and parts[0] == b"hashblock":
                    on_new_tip(parts[1].hex(), now_ms())
        except Exception as e:
            print("block feed (%s): %s; retrying in 5 s" % (url, e), flush=True)
        finally:
            if sub:
                sub.close()
        time.sleep(5)


def tip_poll_loop():
    """Without ZMQ or the node's log: ask the node for its best block every second."""
    first = True
    while True:
        try:
            on_new_tip(rpc("getbestblockhash"), now_ms(), live=not first)  # the first one wasn't seen arriving
            first = False
        except Exception:
            pass
        time.sleep(1)


def node_status():
    """Bitcoin Core's state for the assistant, straight from RPC (no log files needed)."""
    bc, net, mp = rpc("getblockchaininfo"), rpc("getnetworkinfo"), rpc("getmempoolinfo")
    peers = rpc("getpeerinfo")
    return {
        "blocks": bc["blocks"], "headers": bc["headers"], "initial_block_download": bc["initialblockdownload"],
        "verification_progress": bc["verificationprogress"], "size_on_disk_gb": round(bc.get("size_on_disk", 0) / 1e9, 1),
        "pruned": bc.get("pruned"), "version": net["subversion"], "relay_fee_sat_vb": net["relayfee"] * 1e5,
        "connections_in": net["connections_in"], "connections_out": net["connections_out"],
        "mempool": {"txs": mp["size"], "mb": round(mp["bytes"] / 1e6, 2), "usage_mb": round(mp["usage"] / 1e6, 1),
                    "max_mb": round(mp["maxmempool"] / 1e6), "min_fee_sat_vb": mp["mempoolminfee"] * 1e5},
        "peers": [{"id": p["id"], "inbound": p["inbound"], "type": p.get("connection_type"), "version": p.get("subver"),
                   "synced_blocks": p.get("synced_blocks"), "ping_ms": round(p["pingtime"] * 1000) if p.get("pingtime") else None,
                   "blocks_in_flight": p.get("inflight")} for p in peers[:40]],
        "other_chain_tips": [t for t in rpc("getchaintips") if t["status"] != "active"][:5],
    }


def node_loop():
    """Every 30 s: sync status, peers, mempool, the coming difficulty adjustment and the halving."""
    period_start = {}  # height -> time of the first block of the current 2016-block period
    while True:
        try:
            bc, net, mp = rpc("getblockchaininfo"), rpc("getnetworkinfo"), rpc("getmempoolinfo")
            h = bc["blocks"]
            tip_time = rpc("getblockheader", bc["bestblockhash"])["time"]
            start = h - h % 2016
            if start not in period_start:
                period_start.clear()
                period_start[start] = rpc("getblockheader", rpc("getblockhash", start))["time"]
            done = h - start
            avg = (tip_time - period_start[start]) / done if done else 600.0
            left = 2016 - done
            halving = (h // 210000 + 1) * 210000
            with lock:
                S["node"] = {
                    "ok": True, "height": h, "headers": bc["headers"],
                    "synced": not bc["initialblockdownload"] and bc["verificationprogress"] > 0.9999,
                    "peers_in": net["connections_in"], "peers_out": net["connections_out"], "version": net["subversion"],
                    "mempool_tx": mp["size"], "mempool_mb": mp["bytes"] / 1e6, "mempool_fees": mp.get("total_fee"),
                    "size_gb": bc.get("size_on_disk", 0) / 1e9,
                    "adj_blocks_done": done, "adj_blocks_left": left, "adj_avg_min": avg / 60,
                    "adj_change_pct": (600 / avg - 1) * 100 if avg else None, "adj_eta_s": left * avg,
                    "halving_height": halving, "halving_blocks_left": halving - h, "halving_eta_s": (halving - h) * 600,
                    "subsidy_now": 50 / 2 ** (h // 210000), "subsidy_next": 50 / 2 ** (h // 210000 + 1),
                    "checked": time.time(),
                }
        except Exception as e:
            with lock:
                S["node"] = dict(S["node"], ok=False, error=str(e)[:120])
        time.sleep(30)


# ------------------------------------------------------------- miner polling

def http_json(url, timeout=3, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout) as r:
        return json.load(r)


def pool_headers():
    """The Umbrel app's shared secret, which the pool's API asks for (for reading too, since v0.1.20)."""
    token = os.environ.get("SOLO45_API_TOKEN")
    return {"X-Solo45-Token": token} if token else {}


def cgminer(ip, cmd, timeout=3):
    with socket.create_connection((ip, 4028), timeout=timeout) as s:
        s.sendall(json.dumps({"command": cmd}).encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8", "replace").strip("\x00 \n"))


SUFFIX = {"k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}


def as_num(v):
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        m = re.match(r"^\s*([\d.]+)\s*([kKMGTPE]?)", v)
        if m:
            return float(m.group(1)) * SUFFIX.get(m.group(2), 1)
    return None


STRATUM_PORT = os.environ.get("SOLO45_STRATUM_PORT") or "3333"  # the port miners use for Solo45 (the app sets it)


def pool_name(host, port):
    host = (host or "").replace("stratum+tcp://", "").strip("/")
    private = host.startswith(("192.168.", "10.", "172.")) or host.endswith(".local")
    if private and str(port) == STRATUM_PORT:
        return "Solo45"
    if private and str(port) in CFG["pools"]:
        return CFG["pools"][str(port)]
    return host or "?"


def poll_bitaxe(ip):
    i = http_json("http://%s/api/system/info" % ip)
    return {
        "kind": "bitaxe",
        "name": i.get("hostname") or ip,
        "model": "Bitaxe " + str(i.get("ASICModel") or ""),
        "ths_now": (i.get("hashRate") or 0) / 1000,
        "ths": (i.get("hashRate_1m") or i.get("hashRate") or 0) / 1000,
        "ths_long": (i.get("hashRate_10m") or 0) / 1000,
        "expected_ths": (i.get("expectedHashrate") or 0) / 1000,
        "temp": i.get("temp"),
        "temp2": i.get("vrTemp"),
        "power": i.get("power"),
        "fan": i.get("fanspeed"),
        "best": as_num(i.get("bestDiff")),
        "best_session": as_num(i.get("bestSessionDiff")),
        "accepted": i.get("sharesAccepted"),
        "rejected": i.get("sharesRejected"),
        "height": i.get("blockHeight"),
        "uptime": i.get("uptimeSeconds"),
        "pool": pool_name(i.get("stratumURL"), i.get("stratumPort")),
        "on_fallback": bool(i.get("isUsingFallbackStratum")),
        "netdiff": as_num(i.get("networkDifficulty")),
        "reward_sats": i.get("coinbaseValueTotalSatoshis"),
        "block_found": bool(i.get("blockFound")),
        "version": i.get("version"),
        "wifi_rssi": i.get("wifiRSSI"),
        # for the tuning report (read from this same poll: nothing extra is asked of the miner)
        "asic": i.get("ASICModel"),
        "board": i.get("boardVersion"),
        "frequency": i.get("frequency"),
        "core_mv": i.get("coreVoltage"),
        "max_power": i.get("maxPower"),
        "err_pct": i.get("errorPercentage"),
        "asic_errors": sum(a.get("errorCount", 0) for a in (i.get("hashrateMonitor") or {}).get("asics") or []
                           ) if i.get("hashrateMonitor") else None,
    }


def poll_braiins(ip):
    summ = cgminer(ip, "summary")["SUMMARY"][0]
    pools = cgminer(ip, "pools").get("POOLS", [])
    try:
        tuner = cgminer(ip, "tunerstatus")["TUNERSTATUS"][0]
    except Exception:
        tuner = {}
    try:
        temps = cgminer(ip, "temps").get("TEMPS", [])
    except Exception:
        temps = []
    try:
        fans = cgminer(ip, "fans").get("FANS", [])
    except Exception:
        fans = []
    active = next((p for p in pools if p.get("Stratum Active")), None)
    lowest_prio = min((p.get("Priority", 0) for p in pools), default=0)
    host, port, user = "", "", ""
    if active:
        hp = active.get("URL", "").replace("stratum+tcp://", "").rsplit(":", 1)
        host, port = hp[0], (hp[1] if len(hp) > 1 else "")
        user = active.get("User", "")
    fan_pcts = [f.get("Speed") for f in fans if f.get("Speed") is not None]
    return {
        "kind": "braiins",
        "name": user.split(".", 1)[1] if "." in user else ip,
        "model": "Braiins OS",
        "ths_now": (summ.get("MHS 5s") or 0) / 1e6,
        "ths": (summ.get("MHS 1m") or 0) / 1e6,
        "ths_long": (summ.get("MHS 15m") or 0) / 1e6,
        "expected_ths": None,
        "temp": max((t.get("Chip") or 0 for t in temps), default=None),
        "temp2": max((t.get("Board") or 0 for t in temps), default=None),
        "power": tuner.get("ApproximateMinerPowerConsumption"),
        "power_limit": tuner.get("PowerLimit"),
        "fan": sum(fan_pcts) / len(fan_pcts) if fan_pcts else None,
        "best": as_num(summ.get("Best Share")),
        "best_session": None,
        "accepted": summ.get("Accepted"),
        "rejected": summ.get("Rejected"),
        "hw_errors": summ.get("Hardware Errors"),
        "height": None,
        "uptime": summ.get("Elapsed"),
        "pool": pool_name(host, port),
        "on_fallback": bool(active) and active.get("Priority", 0) != lowest_prio,
        "last_share": active.get("Last Share Time") if active else None,
        "block_found": (summ.get("Found Blocks") or 0) > 0,
        "pools": [{"url": p.get("URL"), "status": p.get("Status"),
                   "active": bool(p.get("Stratum Active")), "priority": p.get("Priority")}
                  for p in pools],
    }


thor_cache = {}  # ip -> device info, uptime and recent hashrate samples (info and uptime are read once a minute)


def poll_thor(ip):
    """Hammer Miner Thor (Thor OS, e.g. the Thor X1 with a BM1373): read-only, like the Bitaxe poll."""
    s = http_json("http://%s/v2/miner/status" % ip)["data"]
    t = time.time()
    c = thor_cache.setdefault(ip, {"at": 0, "samples": collections.deque(maxlen=200)})
    if t - c["at"] > 60:
        c["info"] = http_json("http://%s/v2/device/info" % ip).get("data") or {}
        c["dev"] = http_json("http://%s/v2/device/status" % ip).get("data") or {}
        c["at"] = t
    info, dev = c["info"], c["dev"]
    hr = (s.get("current_hashrate") or 0) / 1e12
    c["samples"].append((t, hr))

    def avg(seconds):
        xs = [h for at, h in c["samples"] if t - at <= seconds]
        return sum(xs) / len(xs) if xs else hr

    chips = s.get("chips") or []
    chip_temps = [ch["temperature"] for ch in chips if ch.get("temperature") is not None]
    user = s.get("pool_worker") or ""
    up = dev.get("uptime_seconds")
    return {
        "kind": "thor",
        "name": user.split(".", 1)[1] if "." in user else ip,
        "model": "Hammer " + str(info.get("device_model") or "Thor").title(),
        "ths_now": hr,
        "ths": avg(60),
        "ths_long": avg(600),
        "expected_ths": None,
        "temp": max(chip_temps) if chip_temps else s.get("temp_board"),
        "temp2": s.get("temp_vcore"),
        "power": s.get("power_consumption"),
        "fan": s.get("fan_target_speed"),
        "best": as_num(s.get("bestDiff")),
        "best_session": as_num(s.get("bestSessionDiff")),
        "accepted": s.get("shares_accepted"),
        "rejected": s.get("shares_rejected"),
        "hw_errors": sum(ch.get("hardware_errors") or 0 for ch in chips) if chips else None,
        "height": None,
        "uptime": up + int(t - c["at"]) if up is not None else None,
        "pool": pool_name(s.get("pool_url"), s.get("pool_port")),
        "on_fallback": bool(s.get("isUsingFallbackStratum")),
        "version": info.get("firmware_version"),
        "wifi_rssi": dev.get("wifi_rssi"),
        "asic": info.get("chip_type"),
        "frequency": s.get("frequency"),
        "core_mv": (s.get("coreVoltage") or 0) * 10 or None,
    }


POLLERS = {"bitaxe": poll_bitaxe, "braiins": poll_braiins, "thor": poll_thor}


def unreachable(e):
    """The miner didn't answer at all (offline), as opposed to answering in another miner's language."""
    r = getattr(e, "reason", e)
    return isinstance(r, TimeoutError) or getattr(r, "errno", None) in (101, 113)  # network / host unreachable


kind_cache = {}


def poll_one(ip):
    cached = kind_cache.get(ip)
    order = ([cached] if cached else []) + [k for k in POLLERS if k != cached]
    last_err = None
    for kind in order:
        try:
            r = POLLERS[kind](ip)
            kind_cache[ip] = kind
            return r
        except Exception as e:
            last_err = e
            if unreachable(e):  # an offline miner: trying the other kinds would only hold up the poll
                break
    raise last_err


def miner_ips():
    with lock:
        solo_ips = {w["ip"] for w in S["solo45"].get("workers") or []}
        ips = set(S["ck_workers"]) | set(CFG["miners"]) | set(S["miners"]) | solo_ips
    return sorted(ips - set(CFG["ignore"]), key=lambda s: tuple(int(x) for x in s.split(".")))


session_best = {}  # ip -> the miner's own "best since restart" at the last poll
last_polled = {}   # ip -> time of the last successful poll


def archive_day():
    """Save the finished day's best shares to the history (call with lock held)."""
    if not S["daily"].get("miners"):
        return
    bt = best_today()
    entry = {"date": bt["date"], "best": bt["fleet"]["best"], "name": bt["fleet"]["name"],
             "typical": bt["fleet"]["typical"], "tag": bt["fleet"]["tag"],
             "miners": {m["name"]: m["best"] for m in bt["miners"] if m["best"]}}
    S["best_history"] = [h for h in S["best_history"] if h["date"] != entry["date"]] + [entry]
    del S["best_history"][:-60]
    try:
        save_json(BEST_HISTORY_PATH, S["best_history"])
    except OSError:
        pass


def track_daily_best(ip, result, t):
    """Keep each miner's best share of the day, and the hashes it did today (call with lock held).

    Miners only report their best since they restarted, so a new best of the day is
    recorded when that number goes up while we're watching. For miners on Solo45 the
    live share feed (solo45_loop) gives the exact value, even below that old record.
    """
    today = local_now().strftime("%Y-%m-%d")
    if S["daily"].get("date") != today:
        archive_day()
        S["daily"] = {"date": today, "since": t, "miners": {}}  # bests and hashes both count from "since"
    d = S["daily"]["miners"].setdefault(result["name"], {"best": 0, "at": None, "hashes": 0.0})
    dt = min(t - last_polled.get(ip, t), 15)  # a gap (miner offline, dashboard restart) counts as 15 s at most
    d["hashes"] += (result.get("ths") or 0) * 1e12 * dt
    last_polled[ip] = t
    best = result.get("best_session") if result.get("kind") in ("bitaxe", "thor") else result.get("best")
    if best is None:
        return
    prev = session_best.get(ip)
    if prev is not None and best > prev and best > d["best"]:
        d["best"], d["at"] = best, t
    session_best[ip] = best  # also resets our baseline when the miner restarts


error_counts = {}  # ip -> deque of (time, the ASIC's running error count), last 15 minutes


def track_error_rate(ip, result, t):
    """Chip errors per minute over the last ~15 minutes, from the counter the Bitaxe reports (lock held). The
    counter runs since the miner started, so its total says little; how fast it climbs is what matters."""
    count = result.get("asic_errors")
    if count is None:
        return
    hist = error_counts.setdefault(ip, collections.deque())
    if hist and count < hist[-1][1]:
        hist.clear()  # the miner restarted
    hist.append((t, count))
    while hist and hist[0][0] < t - 900:
        hist.popleft()
    span = hist[-1][0] - hist[0][0]
    result["errors_per_min"] = round((hist[-1][1] - hist[0][1]) / span * 60, 1) if span >= 120 else None


def record(ip, result, err):
    t = time.time()
    with lock:
        m = S["miners"].setdefault(ip, {"ip": ip, "fails": 0})
        if result:
            track_daily_best(ip, result, t)
            track_error_rate(ip, result, t)
            m.update(result)
            m["fails"], m["ok"], m["last_ok"], m["error"] = 0, True, t, None
            if result.get("netdiff"):
                S["netdiff"] = result["netdiff"]
            if result.get("reward_sats"):
                S["reward_sats"] = result["reward_sats"]
            tip = S["tip"]
            # A miner reports the height of the block it is working on: tip + 1.
            if tip and tip["live"] and (result.get("height") or 0) > tip["height"]:
                note_switch(tip, ip, now_ms())
        else:
            m["fails"] += 1
            m["error"] = str(err)[:120]
            if m["fails"] >= 2:
                m["ok"] = False
        m["polled"] = t


def poll_loop():
    pool = ThreadPoolExecutor(max_workers=24)
    while True:
        start = time.time()
        fast = start < fast_poll_until
        ips = miner_ips()
        if fast:
            ips = [ip for ip in ips if kind_cache.get(ip) == "bitaxe"]

        def job(ip):
            try:
                record(ip, poll_one(ip), None)
            except Exception as e:
                record(ip, None, e)

        list(pool.map(job, ips))
        if fast:
            with lock:
                tip = S["tip"]
                if tip and tip["live"]:
                    save_blocks()
        # after a block: every 0.2 s for 2 s (a Bitaxe switches in well under a second), then every 0.5 s
        interval = (0.2 if fast_poll_until - start > 6 else 0.5) if fast else CFG["poll_seconds"]
        # wait out the interval, but start fast polling at once if a block arrives meanwhile
        new_block.wait(max(0.1, interval - (time.time() - start)))
        new_block.clear()


def braiins_work_loop():
    """Time when Braiins miners get new work after a block.

    Braiins OS doesn't report which block it's mining on, but each pool's
    Getworks counter goes up whenever the pool sends a job. Datum also sends a
    routine refresh about every 2 minutes, so the first change from 150 ms before
    the block until 30 s after is taken as the new-block job (rarely, a refresh
    lands just before it).
    """
    last = {}
    while True:
        for ip in [ip for ip, k in list(kind_cache.items()) if k == "braiins" and ip not in CFG["ignore"]]:
            try:
                pools = cgminer(ip, "pools", timeout=1).get("POOLS", [])
                active = next((p for p in pools if p.get("Stratum Active")), None)
                g = (active.get("URL"), active.get("Getworks")) if active else None
            except Exception:
                continue
            if g is None:
                continue
            if ip in last and g != last[ip]:
                t = now_ms()
                with lock:
                    work_changes.append((t, ip))
                    tip = S["tip"]
                    if tip and tip["live"] and t - tip["seen_ms"] <= 30000:
                        note_switch(tip, ip, t)
            last[ip] = g
        time.sleep(0.2)


# ------------------------------------------------------------ derived state

def miner_status(m, tip):
    if not m.get("ok", False) and m.get("fails", 0) >= 2:
        return "offline", "Not responding"
    if m.get("on_fallback"):
        return "warn", "On fallback pool"
    if m.get("temp") and ((m["kind"] in ("bitaxe", "thor") and m["temp"] >= 70) or
                          (m["kind"] == "braiins" and m["temp"] >= 85)):
        return "warn", "Running hot"
    exp = m.get("expected_ths")
    if exp and m.get("ths") is not None and m["ths"] < 0.6 * exp and (m.get("uptime") or 0) > 300:
        return "warn", "Hashrate low"
    if m.get("last_share") and time.time() - m["last_share"] > 180:
        return "warn", "No shares for %d min" % ((time.time() - m["last_share"]) // 60)
    if tip and m.get("height") and m["height"] <= tip["height"] and now_ms() - tip["seen_ms"] > 20000:
        return "warn", "Working on old block"
    return "ok", "Hashing"


def luck(best, typical):
    """How today's best compares with what's typical for the hashes done (call with lock held)."""
    if not best or not typical:
        return None, None
    ratio = best / typical
    tag = "very lucky" if ratio >= 20 else "lucky" if ratio >= 4 else "quiet" if ratio < 0.5 else "normal"
    return ratio, tag


def best_today():
    """Each miner's best share today vs the typical best for the hashes it did (hashes / 2^32)."""
    rows, fleet_best, fleet_hashes, fleet_at, fleet_name = [], 0, 0.0, None, None
    pools = {m.get("name"): m.get("pool") for m in S["miners"].values()}
    for name, d in (S["daily"].get("miners") or {}).items():
        typical = d["hashes"] / 2 ** 32
        ratio, tag = luck(d["best"], typical)
        exact = pools.get(name) == "Solo45"  # off Solo45, only new records since restart show
        rows.append({"name": name, "best": d["best"], "at": d["at"], "typical": typical, "ratio": ratio, "tag": tag,
                     "exact": exact})
        if not exact:
            continue  # the fleet's luck only counts miners whose bests are tracked exactly
        fleet_hashes += d["hashes"]
        if d["best"] > fleet_best:
            fleet_best, fleet_at, fleet_name = d["best"], d["at"], name
    rows.sort(key=lambda r: r["best"], reverse=True)
    ratio, tag = luck(fleet_best, fleet_hashes / 2 ** 32)
    return {"date": S["daily"].get("date"), "since": S["daily"].get("since"), "miners": rows,
            "fleet": {"best": fleet_best, "at": fleet_at, "name": fleet_name,
                      "typical": fleet_hashes / 2 ** 32, "ratio": ratio, "tag": tag}}


def miner_extras(m, now):
    """Electricity cost, 24 h uptime, temperature trend and pool-measured hashrate (lock held)."""
    rows = [r for r in S["temps"].get(m.get("name"), []) if r[0] >= now - 86400]
    pool_ths = pool_height = None
    for w in S["solo45"].get("workers") or []:
        if w.get("name") == m.get("name"):
            pool_height = w.get("last_height")
            if now - w.get("connected", now) > 1800:
                pool_ths = w.get("hashrate_1h", 0) / 1e12  # only once it has been connected for a while
    # A miner that doesn't report its block (Thor OS, Braiins OS) shows the block of its latest share instead.
    # Display only: the "Working on old block" warning still uses what the miner itself reports.
    height = {"height": pool_height, "height_src": "pool"} if not m.get("height") and pool_height else {}
    step = max(1, len(rows) // 48)
    return {
        "cost_day": (m.get("power") or 0) / 1000 * 24 * CFG["kwh_price"],
        "uptime_24h": sum(r[3] for r in rows) / len(rows) if len(rows) >= 6 else None,
        "temp_trend": [[r[1], r[2]] for r in rows[::step]],
        "pool_ths": pool_ths,
        **height,
    }


def switch_stats():
    """Median new-work time per pool over the recent live blocks (lock held)."""
    live = [b for b in S["blocks"] if b.get("live")]
    out = {"blocks": len(live)}
    for key in ("solo45_ms", "datum_ms", "gobrrr_ms"):
        vals = sorted(b[key] for b in live if b.get(key) is not None)
        out[key] = vals[len(vals) // 2] if vals else None
    return out


def work_summary(nd):
    w = S["work"]
    if not w.get("month") or not nd:
        return None
    per_block = nd * 2 ** 32

    def blocks(h):
        return h / per_block if h else 0
    return {"month": w["month"], "since": w.get("since"), "hashes": w["hashes"], "blocks": blocks(w["hashes"]),
            "prev": dict(w["prev"], blocks=blocks(w["prev"]["hashes"])) if w.get("prev") else None}


def snapshot():
    with lock:
        tip = S["tip"]
        now = time.time()
        miners = []
        for ip in miner_ips():
            m = S["miners"].get(ip)
            if not m or "kind" not in m:
                continue
            st, why = miner_status(m, tip)
            miners.append(dict(m, status=st, status_text=why, **miner_extras(m, now)))
        up = [m for m in miners if m["status"] != "offline"]
        total = sum(m.get("ths") or 0 for m in up)
        by_pool = {}
        for m in up:
            by_pool[m["pool"]] = by_pool.get(m["pool"], 0) + (m.get("ths") or 0)
        power = sum(m.get("power") or 0 for m in up)
        nd = S["netdiff"]
        exp_s = nd * 2 ** 32 / (total * 1e12) if nd and total else None

        def odds(ths):
            if not nd or not ths:
                return None
            e = nd * 2 ** 32 / (ths * 1e12)
            return {"expected_s": e, "p_day": 1 - math.exp(-86400 / e),
                    "p_year": 1 - math.exp(-365.25 * 86400 / e)}

        best = max(up + [m for m in miners if m.get("best")],
                   key=lambda m: m.get("best") or 0, default=None)
        return {
            "now_ms": now_ms(),
            "tip": tip,
            "blocks": S["blocks"][:15],
            "gobrrr": S["gobrrr"],
            "solo45": S["solo45"],
            "best_today": best_today(),
            "best_history": S["best_history"][-30:],
            "work": work_summary(nd),
            "node": S["node"],
            "switch": switch_stats(),
            "miners": miners,
            "totals": {
                "ths": total,
                "by_pool": by_pool,
                "power": power,
                "cost_day": power / 1000 * 24 * CFG["kwh_price"],
                "kwh_price": CFG["kwh_price"],
                "currency": CFG["currency"],
                "timezone": CFG["timezone"],
                "j_per_th": power / total if total else None,
                "online": len(up),
                "count": len(miners),
                "netdiff": nd,
                "reward_sats": S["reward_sats"],
                "odds": odds(total),
                "odds_by_pool": {p: odds(v) for p, v in by_pool.items()},
                "expected_s": exp_s,
                "best": {"name": best["name"], "diff": best["best"]} if best and best.get("best") else None,
            },
            "history": S["history"],
            "found": S["found"][-5:],
        }


def save_blocks():
    with lock:
        data = [b for b in S["blocks"] if b.get("live")][:50]
    try:
        save_json(BLOCKS_PATH, data)
    except OSError:
        pass


def save_all():
    """What the loops save every 30 s to 5 min, saved at once (on the way out, so an update loses nothing)."""
    with lock:
        for path, key in ((HISTORY_PATH, "history"), (TEMPS_PATH, "temps"), (DAILY_PATH, "daily"), (WORK_PATH, "work")):
            try:
                save_json(path, S[key])
            except OSError as e:
                print("couldn't save %s: %s" % (path, e), flush=True)
    save_blocks()


def miner_raw(ip):
    """Everything a miner reports, for the assistant."""
    if ip not in miner_ips():
        raise ValueError("%s is not one of the dashboard's miners" % ip)
    if kind_cache.get(ip) == "braiins":
        return {cmd: cgminer(ip, cmd) for cmd in ("summary", "pools", "devs", "temps", "fans", "tunerstatus")}
    return http_json("http://%s/api/system/info" % ip)


def history_sample(hours):
    """Hashrate history, one point per 10 minutes (the stored history is every 30 s)."""
    with lock:
        hist = [h for h in S["history"] if h[0] >= time.time() - hours * 3600]
    out = []
    for ts, total, by_pool in hist[::20]:
        out.append({"time": datetime.fromtimestamp(ts).strftime("%H:%M"), "ths": total, "by_pool": by_pool})
    return out


def save_dash_settings(data):
    """Electricity price and currency from the dashboard, saved in config.json so they survive restarts."""
    new = {}
    if "kwh_price" in data:
        try:
            price = float(data["kwh_price"])
        except (TypeError, ValueError):
            return 400, {"error": "the price must be a number"}
        if not 0 <= price <= 5:
            return 400, {"error": "the price must be between 0 and 5 per kWh"}
        new["kwh_price"] = round(price, 4)
    if "currency" in data:
        cur = str(data["currency"] or "").strip()
        if not 1 <= len(cur) <= 3 or any(c in cur for c in "<>&\"'"):
            return 400, {"error": "the currency symbol must be 1 to 3 characters, like $ or €"}
        new["currency"] = cur
    if "timezone" in data:  # sent by the page from the browser's own setting
        tz = str(data["timezone"] or "")
        try:
            if tz and (len(tz) > 64 or ".." in tz or ZoneInfo(tz) is None):
                raise ValueError
        except Exception:
            return 400, {"error": "unknown time zone"}
        new["timezone"] = tz
    if not new:
        return 400, {"error": "nothing to save"}
    save_config(new)
    CFG.update(new)
    if "timezone" in new:
        print("time zone set to %s" % (new["timezone"] or "the server's"), flush=True)
    return 200, {"ok": True, "kwh_price": CFG["kwh_price"], "currency": CFG["currency"], "timezone": CFG["timezone"]}


def save_config(new, section=None):
    """Merge settings into config.json (or its "ai" section), keeping everything else in it."""
    with lock:
        try:
            with open(CFG_PATH) as f:
                saved = json.load(f)
        except (OSError, ValueError):
            saved = {}
        (saved.setdefault(section, {}) if section else saved).update(new)
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(saved, f, indent=1)
        os.replace(tmp, CFG_PATH)


def save_ai_settings(data):
    """Model, spending caps and report schedule for the AI assistant."""
    new = {}
    if "model" in data:
        if data["model"] not in [m for m, _, _ in ai.MODELS]:
            return 400, {"error": "unknown model"}
        new["model"] = data["model"]
    for key in ("weekly_cap_usd", "monthly_cap_usd"):
        if key in data:
            try:
                val = float(data[key])
            except (TypeError, ValueError):
                return 400, {"error": "the spending limits must be numbers"}
            if not 0 <= val <= 1000:
                return 400, {"error": "the spending limits must be between $0 and $1,000"}
            new[key] = round(val, 2)
    if "report_every_days" in data:
        try:
            val = int(data["report_every_days"])
        except (TypeError, ValueError):
            return 400, {"error": "bad report schedule"}
        if not 0 <= val <= 30:
            return 400, {"error": "reports can be every 1 to 30 days, or off"}
        new["report_every_days"] = val
    if "report_hour" in data:
        try:
            val = int(data["report_hour"])
        except (TypeError, ValueError):
            return 400, {"error": "bad report hour"}
        if not 0 <= val <= 23:
            return 400, {"error": "the report hour must be 0 to 23"}
        new["report_hour"] = val
    if "notes" in data:  # the owner's facts about their setup; the assistant reads them with every question
        notes = str(data["notes"] or "").strip()
        if len(notes) > 8000:
            return 400, {"error": "the notes can be up to 8,000 characters"}
        new["notes"] = notes
    if not new:
        return 400, {"error": "nothing to save"}
    save_config(new, "ai")
    CFG["ai"].update(new)  # the assistant reads this same dict
    return 200, dict(assistant.status(), ok=True)


def default_gateway(route_file="/proc/net/route"):
    """The IPv4 default gateway, which inside an app container is the Umbrel host itself."""
    try:
        with open(route_file) as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
    except (OSError, ValueError):
        pass
    return None


def post_json(url, data, timeout=5):
    headers = dict(pool_headers(), **{"Content-Type": "application/json"})
    req = urllib.request.Request(url, json.dumps(data).encode(), headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {"error": "HTTP %d" % e.code}


def track_work(ths, dt):
    """Add the fleet's hashes to this month's total (call with lock held)."""
    month = local_now().strftime("%Y-%m")
    w = S["work"]
    if w.get("month") != month:
        prev = {"month": w["month"], "hashes": w["hashes"]} if w.get("month") else w.get("prev")
        S["work"] = w = {"month": month, "hashes": 0.0, "since": time.time(), "prev": prev}
    w["hashes"] += ths * 1e12 * dt


def sample_temps(now):
    """Every 5 minutes: each miner's chip and VR temperature and whether it answered (lock held)."""
    for m in S["miners"].values():
        if "name" not in m:
            continue
        rows = S["temps"].setdefault(m["name"], [])
        rows.append([int(now), m.get("temp"), m.get("temp2"), 1 if m.get("ok") else 0])
        del rows[:-288]


def history_loop():
    last_save = time.time()
    n = 0
    while True:
        time.sleep(30)
        n += 1
        snap = snapshot()["totals"]
        with lock:
            S["history"].append([int(time.time()), round(snap["ths"], 3),
                                 {k: round(v, 3) for k, v in snap["by_pool"].items()}])
            del S["history"][:-2880]
            track_work(snap["ths"], 30)
            if n % 10 == 1:
                sample_temps(time.time())
            daily = json.loads(json.dumps(S["daily"]))
            work = dict(S["work"])
        try:
            save_json(DAILY_PATH, daily)
            save_json(WORK_PATH, work)
        except OSError:
            pass
        if time.time() - last_save > 300:
            with lock:
                hist = list(S["history"])
                temps = json.loads(json.dumps(S["temps"]))
            try:
                save_json(HISTORY_PATH, hist)
                save_json(TEMPS_PATH, temps)
            except OSError:
                pass
            last_save = time.time()
            if malloc_trim:  # the dashboard's many threads leave freed memory behind; give it back every 5 min
                malloc_trim(0)


def state_push_loop():
    n = 0
    while True:
        time.sleep(2)
        n += 1
        if subscribers:
            snap = snapshot()
            if n % 15:  # the 24 h chart data only changes every 30 s, and it's most of the size
                snap.pop("history", None)
            broadcast("state", snap)


# -------------------------------------------------------------- phone alerts

NOTIFY_KINDS = ("block", "best", "offline", "hot", "node")


def fmt_diff(d):
    for unit, v in (("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if d >= v:
            return "%.2f %s" % (d / v, unit)
    return "%.0f" % d


def read_ntfy_token():
    try:
        with open(NTFY_TOKEN_PATH) as f:
            return f.read().strip()
    except OSError:
        return ""


def ntfy_send(title, message, priority=3, tags=""):
    """Post one message to the user's ntfy topic. Titles go in an HTTP header, so they're kept ASCII."""
    cfg = CFG["notify"]
    headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": str(priority)}
    if tags:
        headers["Tags"] = tags
    if cfg.get("click"):
        headers["Click"] = cfg["click"]  # tapping the alert opens the dashboard
    token = read_ntfy_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(cfg["server"].rstrip("/") + "/" + cfg["topic"], message.encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def send_alert(kind, title, message, priority=4, tags="warning"):
    """Send an alert if alerts are on and this kind is wanted; True once it went out."""
    cfg = CFG["notify"]
    if not (cfg.get("on") and cfg.get("topic")) or not cfg["events"].get(kind, True):
        return False
    try:
        ntfy_send(title, message, priority, tags)
    except Exception as e:
        print("alert not sent (%s): %s" % (title, e), flush=True)
        return False
    with lock:
        S["notify_log"].insert(0, {"t": time.time(), "title": title})
        del S["notify_log"][10:]
    print("alert sent: %s" % title, flush=True)
    return True


def notify_conditions(snap):
    """Problems going on right now: {key: (kind, title, message, title once it's fixed)}."""
    out = {}
    for m in snap["miners"]:
        name = m.get("name") or m["ip"]
        if m["status"] == "offline":
            out["offline:" + name] = ("offline", "%s is not responding" % name,
                                      "%s (%s) isn't answering. Check its power and Wi-Fi." % (name, m["ip"]),
                                      "%s is back" % name)
        elif m.get("on_fallback"):
            out["backup:" + name] = ("offline", "%s is on its backup pool" % name,
                                     "%s is mining on %s instead of its main pool." % (name, m.get("pool") or "its backup pool"),
                                     "%s is back on its main pool" % name)
        if m.get("status_text") == "Running hot":
            out["hot:" + name] = ("hot", "%s is running hot" % name,
                                  "%s: chip at %s C, fan %s%%." % (name, round(m.get("temp") or 0), round(m.get("fan") or 0)),
                                  "%s has cooled down" % name)
    node = snap.get("node") or {}
    if node.get("ok") is False:
        out["node:down"] = ("node", "Your node isn't answering",
                            "The dashboard can't reach Bitcoin Core: %s" % node.get("error", "no reply"),
                            "Your node is answering again")
    elif node.get("ok") and (not node.get("synced") or (node.get("headers") or 0) > node["height"]):
        out["node:behind"] = ("node", "Your node is behind",
                              "Your node is on block %s, but the network is at %s, so your miners are working on an old block."
                              % ("{:,}".format(node["height"]), "{:,}".format(max(node.get("headers") or 0, node["height"]))),
                              "Your node has caught up")
    so = snap.get("solo45") or {}
    if so.get("checked") and not so.get("up"):
        out["pool:down"] = ("node", "Solo45 isn't responding",
                            "The Solo45 pool isn't answering (%s). Your miners will switch to their backup pools." % so.get("error", "no reply"),
                            "Solo45 is back")
    elif so.get("up") and (so.get("proposal") or {}).get("ok") is False:
        out["pool:check"] = ("node", "Your node rejected Solo45's test block",
                             "Result: %s. A block found now might be invalid; point your miners at their backup pool until it's fixed."
                             % so["proposal"].get("result"),
                             "Solo45's test blocks pass again")
    return out


def notify_events(snap, memo):
    """One-off events since the last look: [(kind, title, message, priority, tags)]. The first look only
    takes note of what's already there, so nothing old is sent when the dashboard (re)starts."""
    events, first = [], "found" not in memo
    found = {"%s:%s" % (f["t"], f["msg"]): f["msg"] for f in snap.get("found") or []}
    found.update({"miner:" + m["ip"]: "%s reports that it found a block!" % m.get("name")
                  for m in snap["miners"] if m.get("block_found")})
    reward = (snap.get("totals") or {}).get("reward_sats")
    for key, msg in found.items():
        if not first and key not in memo["found"]:
            events.append(("block", "BLOCK FOUND!", msg.replace("Solo45: ", "") + (
                ". Reward about %.4f BTC." % (reward / 1e8) if reward else ""), 5, "tada,moneybag"))
    memo["found"] = set(found) | memo.get("found", set())
    so = snap.get("solo45") or {}
    best = so.get("best_ever") or {}
    if so.get("up") and best.get("diff"):
        if memo.get("best") and best["diff"] > memo["best"]:
            nd = (snap.get("totals") or {}).get("netdiff")
            events.append(("best", "New best share ever: %s" % fmt_diff(best["diff"]),
                           "%s found a %s share%s." % (best.get("worker"), fmt_diff(best["diff"]),
                                                      ", about 1/%s of a block" % "{:,}".format(round(nd / best["diff"])) if nd else ""),
                           3, "star"))
        memo["best"] = max(best["diff"], memo.get("best") or 0)
    fb = (so.get("policy") or {}).get("fallback_height")
    if fb and not first and fb != memo.get("fallback"):
        events.append(("node", "A filtered job failed your node's check",
                       "Block %s: Solo45 mined the node's own template instead, so nothing was lost, but the template "
                       "policy has a bug. Please report it." % "{:,}".format(fb), 4, "warning"))
    memo["fallback"] = fb or memo.get("fallback")
    return events


def notify_loop():
    """Every 20 s: send alerts for new events, and for problems that last longer than after_min minutes
    (with a short all-clear once they're over)."""
    memo, active = {}, {}  # active: key -> {"since", "sent", "kind", "fixed", "retry"}
    while True:
        time.sleep(20)
        try:
            snap, now = snapshot(), time.time()
            for ev in notify_events(snap, memo):
                send_alert(*ev)
            current = notify_conditions(snap)
            for key in [k for k in active if k not in current]:
                a = active.pop(key)
                if a["sent"]:
                    send_alert(a["kind"], a["fixed"], "All clear.", 2, "white_check_mark")
            wait = max(1, int(CFG["notify"].get("after_min") or 10)) * 60
            for key, (kind, title, message, fixed) in current.items():
                a = active.setdefault(key, {"since": now, "sent": False, "kind": kind, "fixed": fixed, "retry": 0})
                if not a["sent"] and now - a["since"] >= wait and now >= a["retry"]:
                    a["sent"] = send_alert(kind, title, message, 4, "fire" if kind == "hot" else "warning")
                    a["retry"] = now + 300  # if it didn't go out (alerts off, or ntfy unreachable), look again later
        except Exception as e:
            print("notify_loop error: %r" % e, flush=True)


def notify_status():
    c = CFG["notify"]
    with lock:
        log = list(S["notify_log"])
    return {"on": c["on"], "server": c["server"], "topic": c["topic"], "after_min": c["after_min"],
            "events": c["events"], "token_set": bool(read_ntfy_token()), "log": log}


def save_notify_settings(data):
    """Phone alert settings from the dashboard, saved in config.json (the token in its own file)."""
    c, new = CFG["notify"], {}
    if "on" in data:
        new["on"] = bool(data["on"])
    if "topic" in data:
        topic = str(data["topic"] or "").strip()
        if topic and not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", topic):
            return 400, {"error": "the topic can only use letters, numbers, - and _ (6 to 64 characters)"}
        new["topic"] = topic
    if "server" in data:
        server = str(data["server"] or "").strip().rstrip("/") or "https://ntfy.sh"
        if len(server) > 200 or not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?", server):
            return 400, {"error": "the server must be an address like https://ntfy.sh"}
        new["server"] = server
    if "after_min" in data:
        try:
            val = int(data["after_min"])
        except (TypeError, ValueError):
            return 400, {"error": "the waiting time must be a number of minutes"}
        if not 1 <= val <= 240:
            return 400, {"error": "the waiting time must be 1 to 240 minutes"}
        new["after_min"] = val
    if isinstance(data.get("events"), dict):
        new["events"] = dict(c["events"], **{k: bool(v) for k, v in data["events"].items() if k in NOTIFY_KINDS})
    if "click" in data:
        click = str(data["click"] or "")
        new["click"] = click if re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?/?", click) else ""
    token = str(data.get("token") or "").strip()
    if token and not re.fullmatch(r"[A-Za-z0-9_.\-]{1,200}", token):
        return 400, {"error": "that doesn't look like an ntfy access token"}
    if new.get("on", c["on"]) and not new.get("topic", c["topic"]):
        return 400, {"error": "choose a topic first"}
    if token or data.get("clear_token"):
        fd = os.open(NTFY_TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
    if new:
        save_config(new, "notify")
        c.update(new)
    return 200, dict(notify_status(), ok=True)


def notify_test():
    c = CFG["notify"]
    if not c.get("topic"):
        return 400, {"error": "save a topic first"}
    t = snapshot()["totals"]
    try:
        ntfy_send("Solo45 test", "Alerts from Solo45 reach this phone. Right now: %d of %d miners hashing, %.0f TH/s."
                  % (t["online"], t["count"], t["ths"]), 3, "wave")
    except urllib.error.HTTPError as e:
        return 502, {"error": "the ntfy server answered %d %s" % (e.code, e.reason)}
    except Exception as e:
        return 502, {"error": "couldn't reach %s: %s" % (c["server"], e)}
    with lock:
        S["notify_log"].insert(0, {"t": time.time(), "title": "Solo45 test"})
        del S["notify_log"][10:]
    return 200, {"ok": True}


# ------------------------------------------------------------ home-screen widget

def short_num(n):
    for unit, v in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if n >= v:
            return ("%.1f" % (n / v)).rstrip("0").rstrip(".") + unit
    return "%d" % n


def widget():
    """The umbrelOS home-screen widget (type four-stats): hashrate, miners, today's best share, block odds."""
    snap = snapshot()
    t, fleet = snap["totals"], snap["best_today"]["fleet"]
    ths = t["ths"] or 0
    rate = ("%.2f" % (ths / 1000), "PH/s") if ths >= 1000 else ("%.3g" % ths if ths else "0", "TH/s")
    best = fmt_diff(fleet["best"]).split() + [""] if fleet.get("best") else ["-", ""]
    p_day = (t.get("odds") or {}).get("p_day")
    return {"type": "four-stats", "refresh": "30s", "link": "", "items": [
        {"title": "Hashrate", "text": rate[0], "subtext": rate[1]},
        {"title": "Miners", "text": "%d/%d" % (t["online"], t["count"]), "subtext": "online"},
        {"title": "Best today", "text": best[0], "subtext": best[1]},
        {"title": "Block odds", "text": "1/" + short_num(1 / p_day) if p_day else "-", "subtext": "per day"},
    ]}


# ---------------------------------------------------------- backup and restore

BACKUP_AI_KEYS = ("model", "weekly_cap_usd", "monthly_cap_usd", "report_every_days", "report_hour", "notes")
BACKUP_NOTIFY_KEYS = ("on", "server", "topic", "after_min", "events")


def solo45_get(path, timeout=5):
    return http_json(SOLO45 + path, timeout=timeout, headers=pool_headers())


def make_backup():
    """Everything the user set up, in one file: Solo45's settings plus the dashboard's. No secrets (AI key,
    ntfy token), no statistics or logs."""
    return {
        "solo45_backup": 1,
        "made": local_now().isoformat(timespec="seconds"),
        "pool": solo45_get("/api/export"),
        "dashboard": {
            "kwh_price": CFG["kwh_price"], "currency": CFG["currency"], "miners": CFG["miners"], "ignore": CFG["ignore"],
            "ai": {k: CFG["ai"][k] for k in BACKUP_AI_KEYS if k in CFG["ai"]},
            "notify": {k: CFG["notify"][k] for k in BACKUP_NOTIFY_KEYS},
        },
    }


def restore_backup(data):
    """Load a file made by make_backup. Each part goes through the same checks as a change on the dashboard;
    a part that fails is reported and the rest still applies."""
    if not isinstance(data, dict) or data.get("solo45_backup") != 1:
        return 400, {"error": "that isn't a Solo45 settings backup"}
    done, errors = [], []

    def step(label, result):
        code, reply = result
        (done.append(label) if code == 200 else errors.append("%s: %s" % (label, reply.get("error", code))))

    dash = data.get("dashboard") or {}
    if "kwh_price" in dash or "currency" in dash:
        step("electricity price", save_dash_settings({k: dash[k] for k in ("kwh_price", "currency") if k in dash}))
    lists = {k: [ip for ip in dash.get(k) or [] if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", str(ip))] for k in ("miners", "ignore")}
    if any(lists.values()):
        save_config(lists)
        CFG.update(lists)
        done.append("miner list")
    ai_part = {k: v for k, v in (dash.get("ai") or {}).items() if k in BACKUP_AI_KEYS}
    notes = ai_part.pop("notes", None)
    if ai_part and assistant:
        step("AI settings", save_ai_settings(ai_part))
    if isinstance(notes, str) and len(notes) <= 8000:
        save_config({"notes": notes}, "ai")
        CFG["ai"]["notes"] = notes
    if dash.get("notify"):
        step("phone alerts", save_notify_settings({k: v for k, v in dash["notify"].items() if k in BACKUP_NOTIFY_KEYS}))
    if data.get("pool"):
        try:
            code, reply = post_json(SOLO45 + "/api/restore", data["pool"], timeout=30)
        except OSError as e:
            code, reply = 502, {"error": "Solo45 is not responding: %s" % e}
        if code == 200:
            done.extend(reply.get("restored", []))
            errors.extend(reply.get("errors", []))
        else:
            errors.append("Solo45: %s" % reply.get("error", code))
    print("settings restored from a backup: %s%s" % (", ".join(done) or "nothing",
                                                     "; problems: " + "; ".join(errors) if errors else ""), flush=True)
    return 200, {"ok": not errors, "restored": done, "errors": errors}


# ------------------------------------------------------------------- server

INDEX = os.path.join(BASE, "index.html")
STATIC_DIR = os.path.join(BASE, "static")
ICONS = ("icon-192.png", "icon-512.png", "apple-touch-icon.png", "logo-mark.png")
MANIFEST = json.dumps({  # lets phones add the dashboard to the home screen as an app
    "name": "Solo45", "short_name": "Solo45", "start_url": "/", "display": "standalone",
    "background_color": "#0d1014", "theme_color": "#0d1014",
    "icons": [{"src": "icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
              {"src": "icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}],
}).encode()


PRIVATE_READS = ("/api/state", "/api/shares", "/events", "/api/ai/status")
refused_at = {}  # ip -> when a refusal from it was last logged


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        # the live data shows payout addresses and the miners' addresses on your network: through the Umbrel
        # login only (the home-screen widget's four numbers stay open, umbrelOS fetches those itself)
        if path in PRIVATE_READS and not self.from_proxy("a read of " + path):
            return self.send(403, b'{"error":"only available through the Umbrel login"}', "application/json")
        if path in ("/", "/index.html"):
            with open(INDEX, "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/state":
            self.send(200, json.dumps(snapshot()).encode(), "application/json")
        elif path == "/manifest.webmanifest":
            self.send(200, MANIFEST, "application/manifest+json")
        elif path.lstrip("/") in ICONS or path == "/favicon.ico":
            try:
                with open(os.path.join(STATIC_DIR, "logo-mark.png" if path == "/favicon.ico" else path.lstrip("/")), "rb") as f:
                    self.send(200, f.read(), "image/png")
            except OSError:
                self.send(404, b"not found", "text/plain")
        elif path == "/api/shares":
            with lock:
                shares = list(S["shares"])
            self.send(200, json.dumps(shares).encode(), "application/json")
        elif path == "/api/ai/status":
            st = assistant.status() if assistant else {"enabled": False, "unavailable": True}
            self.send(200, json.dumps(st).encode(), "application/json")
        elif path == "/api/widget":  # fetched by umbrelOS for the home-screen widget
            self.send(200, json.dumps(widget()).encode(), "application/json")
        elif path == "/api/backup":
            if not self.from_proxy("a settings backup"):  # it holds the payout address and alert topic
                return self.send(403, b'{"error":"only available through the Umbrel login"}', "application/json")
            try:
                body = json.dumps(make_backup(), indent=1).encode()
            except Exception as e:
                return self.send(502, json.dumps({"error": "couldn't read Solo45's settings: %s" % e}).encode(), "application/json")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="solo45-settings-%s.json"' % local_now().strftime("%Y-%m-%d"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/notify/status":
            if not self.from_proxy("a read of the alert settings"):  # the topic lets someone read the alerts
                return self.send(403, b'{"error":"only available through the Umbrel login"}', "application/json")
            self.send(200, json.dumps(notify_status()).encode(), "application/json")
        elif path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            # 20 updates (~40 s of state) is plenty for a reader that keeps up; one that doesn't gets dropped in
            # broadcast(), and a write blocked for 30 s ends the connection (each stuck one held a thread and
            # ~20 MB of queued updates: a closed tab behind the Umbrel proxy otherwise stays open forever)
            q = queue.Queue(maxsize=20)
            subscribers.add(q)
            self.connection.settimeout(30)
            try:
                q.put_nowait("event: state\ndata: %s\n\n" % json.dumps(snapshot()))
                while q in subscribers or not q.empty():
                    try:
                        msg = q.get(timeout=15)
                    except queue.Empty:
                        msg = ": ping\n\n"
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                subscribers.discard(q)
        else:
            self.send(404, b"not found", "text/plain")

    def from_proxy(self, what="a change"):
        """In the Umbrel app, other apps can reach this server directly on the app network, bypassing the
        Umbrel login, so changes (and private reads) are only accepted from the Umbrel login: umbrelOS's app
        gateway, which connects from the host (the container's default gateway), or an app_proxy container
        (SOLO45_PROXY_HOST) on umbrelOS versions that use one."""
        host = os.environ.get("SOLO45_PROXY_HOST")
        if not host:
            return True  # running on its own, outside the Umbrel app
        allowed = set()
        gw = default_gateway()
        if gw:
            allowed.add(gw)
        try:
            allowed |= {a[4][0] for a in socket.getaddrinfo(host, None)}
        except OSError:
            pass
        ip = self.client_address[0]
        ok = ip in allowed
        if not ok and time.time() - refused_at.get(ip, 0) > 60:  # log it, at most once a minute per address
            refused_at[ip] = time.time()
            print("refused %s from %s (accepted: %s)" % (what, ip, ", ".join(sorted(allowed)) or "none"), flush=True)
        return ok

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 200000 if path == "/api/restore" else 20000)
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send(400, b'{"error":"bad request"}', "application/json")
        if not self.from_proxy():
            return self.send(403, b'{"error":"changes are only accepted through the Umbrel login"}', "application/json")
        if path in ("/api/solo45/worker", "/api/solo45/settings", "/api/solo45/policy", "/api/solo45/payout"):
            # per-miner difficulty and pool-wide settings, passed on to the pool (which only accepts them from here)
            try:
                api = {"worker": "solo45_settings_api", "settings": "solo45_pool_settings_api", "policy": "solo45_policy_api",
                       "payout": "solo45_payout_api"}
                code, reply = post_json(CFG[api[path.rsplit("/", 1)[1]]], data)
            except OSError as e:
                code, reply = 502, {"error": "Solo45 is not responding: %s" % e}
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path == "/api/dash/settings":
            code, reply = save_dash_settings(data)
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path == "/api/restore":
            code, reply = restore_backup(data)
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path in ("/api/notify/settings", "/api/notify/test"):
            code, reply = save_notify_settings(data) if path.endswith("settings") else notify_test()
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path.startswith("/api/ai/") and not assistant:
            return self.send(503, b'{"error":"The AI assistant is not installed."}', "application/json")
        if path == "/api/ai/key":
            code, reply = assistant.set_key(data.get("key"))
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path == "/api/ai/settings":
            code, reply = save_ai_settings(data)
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path == "/api/ai/ask":
            reply = assistant.ask(data.get("question", ""), data.get("history") or [])
        elif path == "/api/ai/report":
            reply = assistant.make_report()
        else:
            return self.send(404, b'{"error":"not found"}', "application/json")
        self.send(200, json.dumps(reply).encode(), "application/json")


def main():
    global assistant
    if ai:
        assistant = ai.Assistant(CFG["ai"], snapshot, miner_raw, history_sample, node_status, local_now)
        threading.Thread(target=assistant.report_loop, daemon=True).start()
    S["history"] = load_json(HISTORY_PATH, [])[-2880:]
    S["daily"] = load_json(DAILY_PATH, {})
    S["best_history"] = load_json(BEST_HISTORY_PATH, [])
    S["work"] = load_json(WORK_PATH, {})
    S["temps"] = load_json(TEMPS_PATH, {})
    if "since" not in S["daily"]:
        S["daily"] = {}  # an early version without a start time: start today's board fresh
    saved = load_json(BLOCKS_PATH, [])
    have_log = os.path.exists(CFG["bitcoin_log"])  # only when the node's folder is mounted (not in the Umbrel app)
    if have_log:
        for line in read_tail_lines(CFG["bitcoin_log"], 4 * 1024 * 1024):
            on_node_line(line, False)
    blocks = {b["hash"]: b for b in S["blocks"]}
    blocks.update({b["hash"]: b for b in saved})  # saved blocks keep their live switch timings
    S["blocks"] = sorted(blocks.values(), key=lambda b: b["height"], reverse=True)[:50]
    S["tip"] = S["blocks"][0] if S["blocks"] else None
    # new blocks: the node's ZMQ feed if there is one, else its log, else asking it every second
    if CFG["zmq_hashblock"]:
        try:
            on_new_tip(rpc("getbestblockhash"), now_ms(), live=False)  # catch up with blocks found while we were down
        except Exception as e:
            print("node not answering yet:", e, flush=True)
        feed = (zmq_loop, (CFG["zmq_hashblock"],))
    elif have_log:
        feed = (tail, (CFG["bitcoin_log"], on_node_line))
    else:
        feed = (tip_poll_loop, ())
    loops = [feed, (poll_loop, ()), (history_loop, ()), (state_push_loop, ()),
             (solo45_loop, ()), (braiins_work_loop, ()), (node_loop, ()), (notify_loop, ())]
    if CFG["ckpool_log"] and os.path.exists(CFG["ckpool_log"]):  # a ckpool-based pool (like Go Brrr) on this Umbrel
        print("reading the ckpool log for Go Brrr timings...", flush=True)
        try:
            with open(CFG["ckpool_log"], "r", errors="replace") as f:
                for line in f:
                    on_ck_line(line.rstrip("\n"), False)
        except OSError as e:
            print("ckpool log:", e, flush=True)
        loops.append((tail, (CFG["ckpool_log"], on_ck_line)))
    for target, args in loops:
        threading.Thread(target=target, args=args, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", CFG["port"]), Handler)
    srv.daemon_threads = True
    # Docker's stop signal (an app update or restart): save and exit, instead of being killed at the end of the
    # grace period (as a container's first process this one ignores signals it has no handler for).
    # shutdown() waits for serve_forever to return, so it can't run in this thread, where serve_forever is.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    print("Solo Mining Dashboard on port %d" % CFG["port"], flush=True)
    srv.serve_forever()
    save_all()
    print("stopped", flush=True)


if __name__ == "__main__":
    main()
