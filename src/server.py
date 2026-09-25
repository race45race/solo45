#!/usr/bin/env python3
"""Solo Mining Dashboard: a live view of an Umbrel solo-mining fleet.

Reads the Bitcoin Core and ckpool (Go Brrr) logs as they are written, polls
Bitaxe (AxeOS HTTP API) and Braiins OS (CGMiner API, port 4028) miners and the
Solo45 pool, and serves one page plus a Server-Sent Events stream. The only
thing it changes is Solo45's per-miner share difficulty, when the user asks.
The optional Claude assistant (ai.py) needs the anthropic library from ./venv.
"""
import base64
import collections
import json
import math
import os
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

CFG = {
    "port": 8099,
    "bitcoin_log": NODE_DIR + "/debug.log",
    "ckpool_log": os.environ.get("GOBRRR_LOG") or HOME + "/umbrel/app-data/gobrrr-pool/data/ckpool-logs/ckpool.log",
    "miners": [],   # extra miner IPs, on top of those found in the Go Brrr log
    "ignore": [],   # miner IPs to leave out entirely
    "pools": {"23334": "Datum", "21420": "Go Brrr", "21422": "Go Brrr (high diff)", "3333": "Solo45"},
    "poll_seconds": 5,
    "solo45_api": SOLO45 + "/api",
    "solo45_settings_api": SOLO45 + "/api/worker",
    "solo45_pool_settings_api": SOLO45 + "/api/settings",
    "solo45_shares_api": SOLO45 + "/api/shares",
    "rpc_url": "http://127.0.0.1:8332/",
    "rpc_cookie": NODE_DIR + "/.cookie",
    "rpc_user": "",  # when set, used instead of the cookie file
    "rpc_pass": "",
    "kwh_price": 0.12,  # USD per kWh, for the electricity cost figures (set yours in config.json)
    "ai": {"model": "claude-opus-5", "weekly_cap_usd": 2.0, "monthly_cap_usd": 8.0, "report_hour": 8,
           "report_every_days": 3},
}
if os.path.exists(CFG_PATH):
    with open(CFG_PATH) as f:
        _user = json.load(f)
    CFG["ai"].update(_user.pop("ai", {}))
    CFG.update(_user)
for _var, _key, _kind in (("SOLO45_DASH_PORT", "port", int), ("BITCOIN_RPC_URL", "rpc_url", str),
                          ("BITCOIN_RPC_USER", "rpc_user", str), ("BITCOIN_RPC_PASS", "rpc_pass", str)):
    if os.environ.get(_var):  # environment settings (used by the Umbrel app) win over config.json
        CFG[_key] = _kind(os.environ[_var])

try:  # the assistant needs the anthropic library, installed in ./venv
    import ai
except Exception as e:  # a broken or missing assistant must never take the dashboard down
    ai = None
    print("AI assistant disabled:", e, flush=True)
assistant = None

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
            pass


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
    if not m:
        return
    height, bhash = int(m.group(3)), m.group(2)
    blk = {
        "height": height,
        "hash": bhash,
        "seen_ms": now_ms() if live else iso_ms(m.group(1)),
        "mined_ms": iso_ms(m.group(5)),
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
            d = http_json(CFG["solo45_api"], timeout=3)
            if d.get("uptime", 0) < last_uptime:
                last_seq = 0  # the pool restarted, so its share numbers start again at 1
            last_uptime = d.get("uptime", 0)
            new = http_json("%s?since=%d" % (CFG["solo45_shares_api"], last_seq), timeout=3)["shares"]
            if new:
                last_seq = new[-1]["seq"]
                with lock:
                    S["shares"].extend(new)
                    # Solo45 sees every share, so its miners' best of the day is exact
                    today = datetime.now().strftime("%Y-%m-%d")
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
            with lock:
                S["solo45"] = dict(S["solo45"], up=False, error=str(e)[:120])
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
                    "ok": True, "height": h, "synced": not bc["initialblockdownload"] and bc["verificationprogress"] > 0.9999,
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

def http_json(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


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


def pool_name(host, port):
    host = (host or "").replace("stratum+tcp://", "").strip("/")
    private = host.startswith(("192.168.", "10.", "172.")) or host.endswith(".local")
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


kind_cache = {}


def poll_one(ip):
    order = [kind_cache.get(ip)] if ip in kind_cache else ["bitaxe", "braiins"]
    if len(order) == 1:
        order.append("braiins" if order[0] == "bitaxe" else "bitaxe")
    last_err = None
    for kind in order:
        try:
            r = poll_bitaxe(ip) if kind == "bitaxe" else poll_braiins(ip)
            kind_cache[ip] = kind
            return r
        except Exception as e:
            last_err = e
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
    today = datetime.now().strftime("%Y-%m-%d")
    if S["daily"].get("date") != today:
        archive_day()
        S["daily"] = {"date": today, "since": t, "miners": {}}  # bests and hashes both count from "since"
    d = S["daily"]["miners"].setdefault(result["name"], {"best": 0, "at": None, "hashes": 0.0})
    dt = min(t - last_polled.get(ip, t), 15)  # a gap (miner offline, dashboard restart) counts as 15 s at most
    d["hashes"] += (result.get("ths") or 0) * 1e12 * dt
    last_polled[ip] = t
    best = result.get("best_session") if result.get("kind") == "bitaxe" else result.get("best")
    if best is None:
        return
    prev = session_best.get(ip)
    if prev is not None and best > prev and best > d["best"]:
        d["best"], d["at"] = best, t
    session_best[ip] = best  # also resets our baseline when the miner restarts


def record(ip, result, err):
    t = time.time()
    with lock:
        m = S["miners"].setdefault(ip, {"ip": ip, "fails": 0})
        if result:
            track_daily_best(ip, result, t)
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
        interval = 0.5 if fast else CFG["poll_seconds"]
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
    if m.get("temp") and ((m["kind"] == "bitaxe" and m["temp"] >= 70) or
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
    pool_ths = None
    for w in S["solo45"].get("workers") or []:
        if w.get("name") == m.get("name") and now - w.get("connected", now) > 1800:
            pool_ths = w.get("hashrate_1h", 0) / 1e12  # only once it has been connected for a while
    step = max(1, len(rows) // 48)
    return {
        "cost_day": (m.get("power") or 0) / 1000 * 24 * CFG["kwh_price"],
        "uptime_24h": sum(r[3] for r in rows) / len(rows) if len(rows) >= 6 else None,
        "temp_trend": [[r[1], r[2]] for r in rows[::step]],
        "pool_ths": pool_ths,
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


def post_json(url, data, timeout=5):
    headers = {"Content-Type": "application/json"}
    if os.environ.get("SOLO45_API_TOKEN"):  # the Umbrel app's shared secret for changing Solo45 settings
        headers["X-Solo45-Token"] = os.environ["SOLO45_API_TOKEN"]
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
    month = datetime.now().strftime("%Y-%m")
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


# ------------------------------------------------------------------- server

INDEX = os.path.join(BASE, "index.html")
STATIC_DIR = os.path.join(BASE, "static")
ICONS = ("icon-192.png", "icon-512.png", "apple-touch-icon.png")
MANIFEST = json.dumps({  # lets phones add the dashboard to the home screen as an app
    "name": "Solo Mining", "short_name": "Solo Mining", "start_url": "/", "display": "standalone",
    "background_color": "#0d1014", "theme_color": "#0d1014",
    "icons": [{"src": "icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
              {"src": "icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}],
}).encode()


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
        if path in ("/", "/index.html"):
            with open(INDEX, "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/state":
            self.send(200, json.dumps(snapshot()).encode(), "application/json")
        elif path == "/manifest.webmanifest":
            self.send(200, MANIFEST, "application/manifest+json")
        elif path.lstrip("/") in ICONS or path == "/favicon.ico":
            try:
                with open(os.path.join(STATIC_DIR, "icon-192.png" if path == "/favicon.ico" else path.lstrip("/")), "rb") as f:
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
        elif path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue(maxsize=200)
            subscribers.add(q)
            try:
                q.put_nowait("event: state\ndata: %s\n\n" % json.dumps(snapshot()))
                while True:
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

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 20000)
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send(400, b'{"error":"bad request"}', "application/json")
        if path in ("/api/solo45/worker", "/api/solo45/settings"):
            # per-miner difficulty and pool-wide settings, passed on to the pool (which only accepts them from here)
            try:
                code, reply = post_json(CFG["solo45_settings_api" if path.endswith("worker") else "solo45_pool_settings_api"], data)
            except OSError as e:
                code, reply = 502, {"error": "Solo45 is not responding: %s" % e}
            return self.send(code, json.dumps(reply).encode(), "application/json")
        if path.startswith("/api/ai/") and not assistant:
            return self.send(503, b'{"error":"The AI assistant is not installed."}', "application/json")
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
        assistant = ai.Assistant(CFG["ai"], snapshot, miner_raw, history_sample)
        threading.Thread(target=assistant.report_loop, daemon=True).start()
    S["history"] = load_json(HISTORY_PATH, [])[-2880:]
    S["daily"] = load_json(DAILY_PATH, {})
    S["best_history"] = load_json(BEST_HISTORY_PATH, [])
    S["work"] = load_json(WORK_PATH, {})
    S["temps"] = load_json(TEMPS_PATH, {})
    if "since" not in S["daily"]:
        S["daily"] = {}  # an early version without a start time: start today's board fresh
    saved = load_json(BLOCKS_PATH, [])
    for line in read_tail_lines(CFG["bitcoin_log"], 4 * 1024 * 1024):
        on_node_line(line, False)
    S["blocks"].sort(key=lambda b: b["height"], reverse=True)
    by_hash = {b["hash"]: b for b in saved}
    S["blocks"] = [by_hash.get(b["hash"], b) for b in S["blocks"]]
    if S["blocks"]:
        S["tip"] = S["blocks"][0]
    print("scanning Go Brrr log...", flush=True)
    try:
        with open(CFG["ckpool_log"], "r", errors="replace") as f:
            for line in f:
                on_ck_line(line.rstrip("\n"), False)
    except OSError as e:
        print("ckpool log:", e, flush=True)
    for target, args in ((tail, (CFG["bitcoin_log"], on_node_line)),
                         (tail, (CFG["ckpool_log"], on_ck_line)),
                         (poll_loop, ()), (history_loop, ()), (state_push_loop, ()),
                         (solo45_loop, ()), (braiins_work_loop, ()), (node_loop, ())):
        threading.Thread(target=target, args=args, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", CFG["port"]), Handler)
    srv.daemon_threads = True
    print("Solo Mining Dashboard on port %d" % CFG["port"], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
