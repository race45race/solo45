"""Solo45 template policy: leave chosen kinds of transactions out of the blocks this pool builds.

It only ever removes transactions from the node's block template (plus anything that spends them),
then recomputes the reward and the witness commitment. It never touches consensus rules, and the
pool still has the node check every job with getblocktemplate "proposal" mode.

Standard library only.
"""
import copy
import hashlib

RULE_NAMES = {
    "inscriptions": "Inscriptions / Ordinals",
    "opreturn": "Large OP_RETURN data",
    "baremultisig": "Bare multisig (Stamps)",
    "runes": "Runes",
    "minfee": "Below minimum fee rate",
    "child": "Spends a skipped transaction",
}

DEFAULTS = {
    "mode": "watch",  # "off", "watch" (every rule only counts) or "filter" (each rule as set below)
    "rules": {  # "on": the rule is used; "watch": it only counts what it would skip, even in filter mode
        "inscriptions": {"on": True, "watch": False},
        "opreturn": {"on": True, "watch": False, "max_bytes": 83},
        "baremultisig": {"on": True, "watch": False},
        "runes": {"on": True, "watch": False},
        "minfee": {"on": False, "watch": False, "sat_vb": 1.0},
    },
}

OP_0, OP_IF, OP_RETURN, OP_13, OP_CHECKMULTISIG = 0x00, 0x63, 0x6A, 0x5D, 0xAE
WITNESS_COMMITMENT_HEADER = bytes.fromhex("6a24aa21a9ed")


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ------------------------------------------------------------------ parsing

def read_varint(b, i):
    n = b[i]
    if n < 0xFD:
        return n, i + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + size], "little"), i + 1 + size


def parse_tx(raw):
    """Return (output scripts, witness stacks). Raises on malformed data."""
    i = 4
    segwit = raw[i] == 0 and raw[i + 1] == 1
    if segwit:
        i += 2
    n_in, i = read_varint(raw, i)
    for _ in range(n_in):
        i += 36
        slen, i = read_varint(raw, i)
        i += slen + 4
    n_out, i = read_varint(raw, i)
    outputs = []
    for _ in range(n_out):
        i += 8
        slen, i = read_varint(raw, i)
        outputs.append(raw[i:i + slen])
        i += slen
    witnesses = []
    if segwit:
        for _ in range(n_in):
            n_items, i = read_varint(raw, i)
            items = []
            for _ in range(n_items):
                ilen, i = read_varint(raw, i)
                items.append(raw[i:i + ilen])
                i += ilen
            witnesses.append(items)
    if i + 4 != len(raw):
        raise ValueError("unexpected transaction length")
    return outputs, witnesses


def script_ops(script):
    """Yield (opcode, pushed data or None) for a script; stops quietly at a truncated push."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4B:
            size = op
        elif op == 0x4C:
            if i + 1 > len(script):
                return
            size, i = script[i], i + 1
        elif op == 0x4D:
            if i + 2 > len(script):
                return
            size, i = int.from_bytes(script[i:i + 2], "little"), i + 2
        elif op == 0x4E:
            if i + 4 > len(script):
                return
            size, i = int.from_bytes(script[i:i + 4], "little"), i + 4
        else:
            yield op, None
            continue
        if i + size > len(script):
            return
        yield op, script[i:i + size]
        i += size


# ------------------------------------------------------------------ classifiers

def tapscript(stack):
    """The leaf script of a taproot script-path spend, or None."""
    items = list(stack)
    if len(items) >= 2 and items[-1][:1] == b"\x50":  # annex
        items = items[:-1]
    if len(items) < 2:
        return None
    control = items[-1]
    if not control or (control[0] & 0xFE) != 0xC0 or (len(control) - 33) % 32:
        return None
    return items[-2]


def has_envelope(script):
    """True for the OP_FALSE OP_IF ... data envelope that inscriptions (and similar) use."""
    prev = None
    for op, _ in script_ops(script):
        if prev == OP_0 and op == OP_IF:
            return True
        prev = op
    return False


def is_bare_multisig(spk):
    """OP_m <pubkey>... OP_n OP_CHECKMULTISIG, read opcode by opcode (a taproot output also starts
    with OP_1, and its 32-byte key can end in the byte 0xae)."""
    ops = list(script_ops(spk))
    if len(ops) < 4 or ops[-1] != (OP_CHECKMULTISIG, None):
        return False
    (m, _), (n, _), keys = ops[0], ops[-2], ops[1:-2]
    return (0x51 <= m <= 0x60 and 0x51 <= n <= 0x60 and len(keys) == n - 0x50
            and all(data is not None and len(data) in (33, 65) for _, data in keys))


def classify(tx, rules):
    """The content rules this template transaction breaks (empty list = keep it). The fee rule is
    judged on whole packages in evaluate()."""
    reasons = []
    try:
        outputs, witnesses = parse_tx(bytes.fromhex(tx["data"]))
    except (ValueError, IndexError, KeyError):
        return reasons  # can't read it: leave the decision to the node
    on = lambda name: rules.get(name, {}).get("on")
    if on("runes") and any(o[:2] == bytes([OP_RETURN, OP_13]) for o in outputs):
        reasons.append("runes")
    if on("opreturn"):
        limit = rules["opreturn"].get("max_bytes", 83)
        if any(o[:1] == bytes([OP_RETURN]) and len(o) > limit for o in outputs):
            reasons.append("opreturn")
    if on("baremultisig") and any(is_bare_multisig(o) for o in outputs):
        reasons.append("baremultisig")
    if on("inscriptions"):
        for stack in witnesses:
            leaf = tapscript(stack)
            if leaf and has_envelope(leaf):
                reasons.append("inscriptions")
                break
    return reasons


# ------------------------------------------------------------------ templates

def rule_state(rule):
    """'off', 'watch' (only counts) or 'filter' for one rule's settings."""
    if not rule.get("on"):
        return "off"
    return "watch" if rule.get("watch") else "filter"


def vsize(tx):
    """The size the node uses for fee rates: weight / 4, or more for transactions heavy in signature checks."""
    return max(1, (max(tx.get("weight", 0), tx.get("sigops", 0) * 20) + 3) // 4)


def low_fee(txs, candidates, sat_vb):
    """The candidates that don't pay sat_vb, judged by package the way the node builds blocks: keep taking
    the transaction whose not-yet-taken ancestors plus itself pay the best rate, until the best one left
    pays less than sat_vb. So a low-fee parent stays when its child pays enough for both (child pays for
    parent), and a low-fee child can't ride along on a parent that pays well."""
    parents = {n: [d - 1 for d in txs[n].get("depends", []) if d - 1 in candidates] for n in candidates}
    children = {n: [] for n in candidates}
    for n, ps in parents.items():
        for p in ps:
            children[p].append(n)
    fee = {n: txs[n].get("fee", 0) for n in candidates}
    size = {n: vsize(txs[n]) for n in candidates}
    low, seen = set(), set()
    for start in sorted(candidates):
        if start in seen:
            continue
        cluster, stack = set(), [start]  # everything linked to it by spending, in either direction
        while stack:
            n = stack.pop()
            if n not in cluster:
                cluster.add(n)
                stack += parents[n] + children[n]
        seen |= cluster
        anc = {}
        for n in sorted(cluster):  # the template lists parents before children
            anc[n] = {n}.union(*(anc[p] for p in parents[n]))
        left = set(cluster)
        while left:
            best, best_rate = None, -1.0
            for n in sorted(left):
                pkg = anc[n] & left
                rate = sum(fee[m] for m in pkg) / sum(size[m] for m in pkg)
                if rate > best_rate:
                    best, best_rate = pkg, rate
            if best_rate < sat_vb:
                break
            left -= best
        low |= left
    return low


def select(txs, found, rules, names):
    """Which transactions applying the rules in `names` leaves out: {index: reasons}. A transaction that
    spends a left-out one goes too, because a block can't contain a child without its parent."""
    skip = {}
    for n, tx in enumerate(txs):
        reasons = [r for r in found[n] if r in names]
        if not reasons and any((d - 1) in skip for d in tx.get("depends", [])):
            reasons = ["child"]
        if reasons:
            skip[n] = reasons
    if "minfee" in names:
        rest = {n for n in range(len(txs)) if n not in skip}
        for n in sorted(low_fee(txs, rest, rules["minfee"].get("sat_vb", 1.0))):
            skip[n] = ["minfee"]
    return skip


def evaluate(tpl, cfg):
    """What the rules take out of this template ("skip", used in filter mode), and what the rules set to
    watch would take out on top of that ("watch", only counted)."""
    rules = cfg.get("rules", {})
    state = {name: rule_state(rule) for name, rule in rules.items()}
    counted = {name for name, s in state.items() if s != "off"}
    applied = {name for name, s in state.items() if s == "filter"} if cfg.get("mode") == "filter" else set()
    txs = tpl["transactions"]
    found = [classify(tx, rules) for tx in txs]
    skip = select(txs, found, rules, applied)
    would = select(txs, found, rules, counted) if counted != applied else skip
    watch = {n: reasons for n, reasons in would.items() if n not in skip}

    def tally(part):
        by_rule = {}
        for n, reasons in part.items():  # count each transaction once, under its first reason
            entry = by_rule.setdefault(reasons[0], {"txs": 0, "fees": 0})
            entry["txs"] += 1
            entry["fees"] += txs[n].get("fee", 0)
        return by_rule

    return {
        "height": tpl["height"],
        "txs": len(txs),
        "fees": sum(t.get("fee", 0) for t in txs),
        "skip": skip,
        "skipped": len(skip),
        "fees_skipped": sum(txs[n].get("fee", 0) for n in skip),
        "weight_skipped": sum(txs[n].get("weight", 0) for n in skip),
        "by_rule": tally(skip),
        "examples": [{"txid": txs[n]["txid"], "rule": skip[n][0]} for n in list(skip)[:5]],
        "watch": watch,
        "watched": len(watch),
        "fees_watched": sum(txs[n].get("fee", 0) for n in watch),
        "weight_watched": sum(txs[n].get("weight", 0) for n in watch),
        "watch_by_rule": tally(watch),
        "watch_examples": [{"txid": txs[n]["txid"], "rule": watch[n][0]} for n in list(watch)[:5]],
    }


def merkle_root(hashes):
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def witness_commitment(txs):
    """The coinbase's witness commitment output script for these template transactions."""
    wtxids = [b"\x00" * 32] + [bytes.fromhex(t["hash"])[::-1] for t in txs]
    return WITNESS_COMMITMENT_HEADER + sha256d(merkle_root(wtxids) + b"\x00" * 32)


def apply(tpl, report):
    """A copy of the template without the skipped transactions, with the reward and witness
    commitment recomputed and the remaining 'depends' indexes renumbered."""
    skip = report["skip"]
    new = copy.copy(tpl)
    kept, renumber = [], {}
    for n, tx in enumerate(tpl["transactions"]):
        if n in skip:
            continue
        renumber[n + 1] = len(kept) + 1
        tx = dict(tx, depends=[renumber[d] for d in tx.get("depends", []) if d in renumber])
        kept.append(tx)
    new["transactions"] = kept
    new["coinbasevalue"] = tpl["coinbasevalue"] - report["fees_skipped"]
    if tpl.get("default_witness_commitment"):
        new["default_witness_commitment"] = witness_commitment(kept).hex()
    return new


def check_config(data, current):
    """Validate a policy change from the dashboard; returns (new config, error)."""
    cfg = copy.deepcopy(current)
    if "mode" in data:
        if data["mode"] not in ("off", "watch", "filter"):
            return None, "mode must be off, watch or filter"
        cfg["mode"] = data["mode"]
    for name, change in (data.get("rules") or {}).items():
        if name not in DEFAULTS["rules"] or not isinstance(change, dict):
            return None, "unknown rule: %s" % name
        rule = cfg["rules"].setdefault(name, dict(DEFAULTS["rules"][name]))
        if "on" in change:
            rule["on"] = bool(change["on"])
        if "watch" in change:
            rule["watch"] = bool(change["watch"])
        if name == "opreturn" and "max_bytes" in change:
            val = int(change["max_bytes"])
            if not 0 <= val <= 100000:
                return None, "the OP_RETURN limit must be 0 to 100,000 bytes"
            rule["max_bytes"] = val
        if name == "minfee" and "sat_vb" in change:
            val = float(change["sat_vb"])
            if not 0 <= val <= 1000:
                return None, "the minimum fee rate must be 0 to 1,000 sat/vB"
            rule["sat_vb"] = round(val, 3)
    return cfg, None


def load_config(saved):
    """The saved policy merged over the defaults, so new rules appear with their default setting."""
    cfg = copy.deepcopy(DEFAULTS)
    if isinstance(saved, dict):
        if saved.get("mode") in ("off", "watch", "filter"):
            cfg["mode"] = saved["mode"]
        for name, rule in (saved.get("rules") or {}).items():
            if name in cfg["rules"] and isinstance(rule, dict):
                cfg["rules"][name].update(rule)
    return cfg
