"""Claude assistant for the Solo Mining dashboard.

Read-only: its tools look at live stats, miners and logs. The one thing it can
"do" is propose a Solo45 difficulty change, which the dashboard shows as an
Apply button; nothing changes until the user clicks it. Spending is capped per
rolling 7 and 30 days, and the running total is kept in ai_usage.json.
"""
import json
import os
import threading
import time
from datetime import datetime

import anthropic

BASE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
DATA = os.environ.get("SOLO45_DASH_DATA") or BASE  # key, usage and reports live next to the dashboard's data
KEY_PATH = os.path.join(DATA, "anthropic_key")
USAGE_PATH = os.path.join(DATA, "ai_usage.json")
REPORTS_PATH = os.path.join(DATA, "ai_reports.json")

# USD per million tokens (input, output). Cache writes cost 1.25x input, cache reads 0.1x.
PRICES = {
    "claude-fable-5-1": (10.0, 50.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-4-5": (1.0, 5.0),
}
# The models offered on the dashboard, cheapest first: (id, name, rough cost of one question).
MODELS = [
    ("claude-haiku-4-5", "Claude Haiku 4.5 - cheapest, simpler answers", "about 3¢"),
    ("claude-sonnet-5", "Claude Sonnet 5 - good balance", "about 5¢"),
    ("claude-opus-5", "Claude Opus 5 - recommended", "about 13¢"),
    ("claude-fable-5-1", "Claude Fable 5.1 - most capable", "about 26¢"),
]
FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5-1")  # models that take the server-side refusal fallback
MAX_TOOL_ROUNDS = 8

LOGS = {
    "solo45": os.environ.get("SOLO45_POOL_LOG") or HOME + "/solo-pool/pool.log",
    "node": (os.environ.get("BITCOIN_DATA_DIR") or HOME + "/umbrel/app-data/bitcoin/data/bitcoin") + "/debug.log",
    "dashboard": DATA + "/dashboard.log",
    "gobrrr": os.environ.get("GOBRRR_LOG") or HOME + "/umbrel/app-data/gobrrr-pool/data/ckpool-logs/ckpool.log",
}
# only offer the logs this install can actually read (the Umbrel app doesn't mount the node's folder)
LOGS = {k: v for k, v in LOGS.items() if k in ("solo45", "dashboard") or os.path.exists(v)}

SYSTEM = """You are the assistant built into a home Bitcoin solo-mining dashboard running on an Umbrel server. You help the owner understand how their miners, pools and node are doing.

The setup:
- Solo45 is the owner's own solo pool (Stratum v1), running on their Umbrel next to their Bitcoin node. It builds work from the node, and every new job is checked with getblocktemplate "proposal" mode (proposal.ok must be true). Other pools shown on the dashboard (for example Datum or a ckpool-based pool) are usually fallbacks.
- Share difficulty only changes how often a miner reports shares. It does not change the chance of finding a block, and a solo miner's best share is luck. Say so if the owner seems to think otherwise.
{NOTES}
How to answer:
- The current dashboard state is included with each question. Use the tools when you need more: logs, one miner's raw stats, or hashrate history.
- Answer in plain English for a hobbyist, short and specific, with the real numbers. Lead with the answer. No long preambles.
- You cannot change anything yourself. If a Solo45 difficulty setting would genuinely help, call propose_difficulty_change; the owner gets an Apply button. Never say a change was made. Other changes (miner settings, pools, the node) you can only describe as steps for the owner.
- If something looks wrong and you are not sure why, say what you checked and what to look at next rather than guessing."""

TOOLS = [
    {
        "name": "read_log",
        "description": "Read the most recent lines of a log on the Umbrel. 'solo45' is the Solo45 pool log, 'dashboard' is this dashboard's log; 'node' (Bitcoin Core's debug.log) and 'gobrrr' (the Go Brrr ckpool log) are only there when this install can read them. Optionally keep only lines containing some text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "log": {"type": "string", "enum": sorted(LOGS)},
                "lines": {"type": "integer", "description": "How many matching lines to return, newest last (max 200)."},
                "contains": {"type": "string", "description": "Only return lines containing this text (case-insensitive)."},
            },
            "required": ["log"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_node_status",
        "description": "Bitcoin Core's current state straight from its RPC: blocks vs headers, sync progress, peers (version, sync height, ping, blocks in flight), mempool size and minimum fee, relay fee and any competing chain tips. Use it for questions about the node.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_miner_details",
        "description": "Full raw stats straight from one miner (Bitaxe AxeOS API or Braiins OS), by IP address. Use when the dashboard summary isn't enough.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_hashrate_history",
        "description": "Fleet hashrate over time (total and per pool, TH/s), sampled every 10 minutes.",
        "input_schema": {
            "type": "object",
            "properties": {"hours": {"type": "integer", "description": "How far back, 1 to 24."}},
            "required": ["hours"],
            "additionalProperties": False,
        },
    },
    {
        "name": "propose_difficulty_change",
        "description": "Suggest a Solo45 share-difficulty setting for one miner. This does NOT apply it: the owner sees an Apply button. Give exactly one of diff (a fixed difficulty), share_seconds (a target time between shares, the pool adjusts difficulty to match) or neither (back to automatic).",
        "input_schema": {
            "type": "object",
            "properties": {
                "worker": {"type": "string", "description": "The Solo45 worker name, for example Bitaxe8."},
                "diff": {"type": "number"},
                "share_seconds": {"type": "number"},
                "reason": {"type": "string", "description": "One short sentence the owner will see next to the button."},
            },
            "required": ["worker", "reason"],
            "additionalProperties": False,
        },
    },
]


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def tail_lines(path, n, contains=None):
    n = max(1, min(int(n or 50), 200))
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 3_000_000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError as e:
        return "Could not read the log: %s" % e
    if contains:
        lines = [l for l in lines if contains.lower() in l.lower()]
    out = "\n".join(lines[-n:])
    return out[-20000:] or "(no matching lines)"


class Assistant:
    def __init__(self, cfg, snapshot_fn, miner_fn, history_fn, node_fn=None, now_fn=None):
        self.cfg = cfg
        self.node_fn = node_fn
        self.now = now_fn or (lambda: datetime.now().astimezone())  # the owner's local time
        self.snapshot_fn = snapshot_fn
        self.miner_fn = miner_fn
        self.history_fn = history_fn
        self.lock = threading.Lock()

    @property
    def system(self):
        """The instructions plus the owner's current notes about their setup (edited on the dashboard)."""
        notes = (self.cfg.get("notes") or "").strip()
        return SYSTEM.replace("{NOTES}", "\nThe owner's notes about their setup:\n" + notes + "\n" if notes else "")

    # -- key, budget

    def api_key(self):
        try:
            with open(KEY_PATH) as f:
                key = f.read().strip()
        except OSError:
            key = ""
        return key or os.environ.get("ANTHROPIC_API_KEY", "")

    def key_hint(self):
        key = self.api_key()
        return "…" + key[-4:] if len(key) > 8 else ""

    def set_key(self, key):
        """Save (or with an empty key, remove) the owner's Anthropic API key. The key is never sent back."""
        key = str(key or "").strip()
        if not key:
            try:
                os.remove(KEY_PATH)
            except FileNotFoundError:
                pass
            return 200, {"ok": True, "key_hint": ""}
        if not key.startswith("sk-ant-") or not 20 <= len(key) <= 300 or any(c.isspace() for c in key):
            return 400, {"error": "That doesn't look like an Anthropic API key (they start with sk-ant-)."}
        tmp = KEY_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        os.replace(tmp, KEY_PATH)
        return 200, {"ok": True, "key_hint": self.key_hint()}

    def spent(self, days):
        cutoff = time.time() - days * 86400
        return sum(c for t, c, _ in _load(USAGE_PATH, []) if t >= cutoff)

    def budget_left(self):
        week = self.cfg["weekly_cap_usd"] - self.spent(7)
        month = self.cfg["monthly_cap_usd"] - self.spent(30)
        return min(week, month)

    def record_cost(self, usage, model, kind):
        p_in, p_out = PRICES.get(model, PRICES["claude-opus-5"])
        cost = (usage.input_tokens * p_in
                + (usage.cache_creation_input_tokens or 0) * p_in * 1.25
                + (usage.cache_read_input_tokens or 0) * p_in * 0.1
                + usage.output_tokens * p_out) / 1e6
        with self.lock:
            rows = [r for r in _load(USAGE_PATH, []) if r[0] >= time.time() - 31 * 86400]
            rows.append([time.time(), cost, kind])
            _save(USAGE_PATH, rows)
        return cost

    def status(self):
        reports = _load(REPORTS_PATH, [])
        return {
            "enabled": bool(self.api_key()),
            "key_hint": self.key_hint(),
            "model": self.cfg["model"],
            "models": [{"id": m, "name": n, "per_question": q} for m, n, q in MODELS],
            "spent_week": round(self.spent(7), 4),
            "spent_month": round(self.spent(30), 4),
            "weekly_cap": self.cfg["weekly_cap_usd"],
            "monthly_cap": self.cfg["monthly_cap_usd"],
            "report": reports[-1] if reports else None,
            "report_hour": self.cfg["report_hour"],
            "report_every_days": self.cfg.get("report_every_days", 1),
            "notes": self.cfg.get("notes", ""),
        }

    # -- tools

    def run_tool(self, name, args, proposals):
        if name == "read_log":
            if args.get("log") not in LOGS:
                return "Unknown log. Choose one of: " + ", ".join(sorted(LOGS)), True
            return tail_lines(LOGS[args["log"]], args.get("lines", 50), args.get("contains")), False
        if name == "get_node_status":
            if not self.node_fn:
                return "Not available here.", True
            try:
                return json.dumps(self.node_fn(), default=str)[:20000], False
            except Exception as e:
                return "The node didn't answer: %s" % e, True
        if name == "get_miner_details":
            try:
                return json.dumps(self.miner_fn(args["ip"]), default=str)[:20000], False
            except Exception as e:
                return "Could not reach that miner: %s" % e, True
        if name == "get_hashrate_history":
            return json.dumps(self.history_fn(max(1, min(int(args.get("hours", 6)), 24)))), False
        if name == "propose_difficulty_change":
            p = {"worker": str(args["worker"]), "reason": str(args.get("reason", ""))[:300]}
            if args.get("diff") is not None:
                p["diff"] = float(args["diff"])
            elif args.get("share_seconds") is not None:
                p["share_seconds"] = float(args["share_seconds"])
            proposals.append(p)
            return "Shown to the owner as an Apply button. It is not applied unless they click it.", False
        return "Unknown tool.", True

    # -- conversation

    def context(self):
        snap = self.snapshot_fn()
        snap.pop("history", None)
        snap["blocks"] = snap.get("blocks", [])[:8]
        snap["best_history"] = snap.get("best_history", [])[-7:]
        for m in snap.get("miners", []):
            m.pop("temp_trend", None)  # long lists; the read-only tools can fetch details if needed
        now = self.now().strftime("%Y-%m-%d %H:%M %Z")
        return "Current time (the owner's time zone): %s\nLive dashboard state (JSON):\n%s" % (
            now, json.dumps(snap, default=str, separators=(",", ":")))

    def ask(self, question, history=(), kind="question"):
        """Answer one question. history: earlier [{"q": ..., "a": ...}] turns from the page."""
        key = self.api_key()
        if not key:
            return {"error": "No API key yet. Add your Anthropic API key under AI settings on the dashboard."}
        if self.budget_left() <= 0:
            return {"error": "Spending cap reached ($%.2f per week, $%.2f per month). The AI will be available again as older usage rolls off."
                    % (self.cfg["weekly_cap_usd"], self.cfg["monthly_cap_usd"])}

        # keys that aren't scoped to a workspace must name one on every request
        headers = {"anthropic-workspace-id": self.cfg["workspace_id"]} if self.cfg.get("workspace_id") else None
        client = anthropic.Anthropic(api_key=key, timeout=180.0, max_retries=2, default_headers=headers)
        messages = []
        for turn in list(history)[-6:]:
            if turn.get("q") and turn.get("a"):
                messages.append({"role": "user", "content": str(turn["q"])[:4000]})
                messages.append({"role": "assistant", "content": str(turn["a"])[:8000]})
        messages.append({"role": "user", "content": self.context() + "\n\n" + str(question)[:4000]})

        proposals, cost, model = [], 0.0, self.cfg["model"]
        try:
            for _ in range(MAX_TOOL_ROUNDS):
                if self.budget_left() <= 0:
                    return {"error": "Spending cap reached partway through this answer.", "cost": cost}
                # the server-side refusal fallback is only offered on some models
                extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"} if model in FALLBACK_MODELS else {}
                response = client.beta.messages.create(
                    model=model,
                    max_tokens=16000,
                    system=self.system,
                    tools=TOOLS,
                    messages=messages,
                    cache_control={"type": "ephemeral"},
                    **extra,
                )
                cost += self.record_cost(response.usage, response.model, kind)
                if response.stop_reason == "refusal":
                    return {"error": "Claude declined to answer this one.", "cost": cost}
                if response.stop_reason != "tool_use":
                    break
                messages.append({"role": "assistant", "content": response.content})
                results = []
                for block in response.content:
                    if block.type == "tool_use":
                        out, is_error = self.run_tool(block.name, block.input, proposals)
                        results.append({"type": "tool_result", "tool_use_id": block.id,
                                        "content": out, "is_error": is_error})
                messages.append({"role": "user", "content": results})
            else:
                return {"error": "The question needed too many steps; try asking something narrower.", "cost": cost}
        except anthropic.AuthenticationError:
            return {"error": "Anthropic rejected the API key in ~/solo-dash/anthropic_key.", "cost": cost}
        except anthropic.PermissionDeniedError:
            return {"error": "This API key isn't allowed to use %s." % model, "cost": cost}
        except anthropic.RateLimitError:
            return {"error": "Anthropic's rate limit was hit; try again in a minute.", "cost": cost}
        except anthropic.BadRequestError as e:
            if "workspace" in str(e.message):
                return {"error": "This API key isn't tied to a workspace. Either create a key inside a workspace, or add "
                                 "\"workspace_id\": \"wrkspc_...\" to the \"ai\" section of ~/solo-dash/config.json.", "cost": cost}
            return {"error": "Anthropic API error 400: %s" % e.message, "cost": cost}
        except anthropic.APIStatusError as e:
            return {"error": "Anthropic API error %s: %s" % (e.status_code, e.message), "cost": cost}
        except anthropic.APIConnectionError:
            return {"error": "Couldn't reach Anthropic. Is the Umbrel online?", "cost": cost}

        answer = "".join(b.text for b in response.content if b.type == "text").strip()
        if response.stop_reason == "max_tokens":
            answer += "\n\n(Answer cut off because it got too long.)"
        return {"answer": answer, "proposals": proposals, "cost": round(cost, 4), "model": response.model}

    # -- daily report

    def make_report(self):
        res = self.ask(
            "Write the owner's regular report (it's written every %d days). Cover the time since the "
            "last report as far as the logs go; hashrate history only covers the last 24 hours, so say "
            "so. Include: fleet hashrate (use get_hashrate_history), each pool, any miner that was offline, hot, slow or "
            "rejecting shares, how fast Solo45 and the Bitaxes switched to new blocks, best "
            "shares, Solo45's block check, and anything unusual in the Solo45 or node logs. "
            "Start with a one-line verdict. Keep it under 250 words, using short bullet points."
            % self.cfg.get("report_every_days", 1),
            kind="report")
        if res.get("answer"):
            reports = _load(REPORTS_PATH, [])
            reports.append({"at": time.time(), "text": res["answer"], "cost": res["cost"]})
            _save(REPORTS_PATH, reports[-14:])
        return res

    def report_loop(self):
        """Write a report every report_every_days days, after report_hour (the owner's local time)."""
        last_try = 0.0
        while True:
            time.sleep(300)
            if not self.api_key() or time.time() - last_try < 3600:  # at most one attempt an hour
                continue
            now = self.now()
            reports = _load(REPORTS_PATH, [])
            last = datetime.fromtimestamp(reports[-1]["at"], now.tzinfo) if reports else None
            every = self.cfg.get("report_every_days", 1)
            if every <= 0:  # automatic reports are off
                continue
            if now.hour >= self.cfg["report_hour"] and (last is None or (now.date() - last.date()).days >= every):
                last_try = time.time()
                self.make_report()
