"""Stall guard: when the node has seen a new block announced but one peer is holding up its download,
disconnect that peer long before Bitcoin Core's own 10-minute timeout, so the node fetches the block
from another peer and the miners stop working on an old block.

It only ever disconnects a peer (the node replaces it by itself). It never bans, and it stays out of the
way while the node is catching up on many blocks, for example after it was switched off.
"""
import time

MAX_GAP = 3        # only act when the node is 1-3 blocks behind the announced chain
COOLDOWN_S = 30    # at most one round of disconnects per 30 s


class StallGuard:
    def __init__(self, events=None):
        self.behind_since = None   # when the node was first seen behind the announced chain
        self.last_action = 0.0
        self.warned_idle = False   # already logged "behind, but no peer has the block in flight"
        self.events = events if events is not None else []  # newest last, kept by the caller

    def check(self, blocks, headers, ibd, peers, now, limit_s):
        """Decide what to do. Returns (peers to disconnect as [(id, description)], note or None)."""
        if limit_s <= 0 or ibd or headers <= blocks or headers - blocks > MAX_GAP:
            self.behind_since, self.warned_idle = None, False
            return [], None
        if self.behind_since is None:
            self.behind_since = now
        waited = now - self.behind_since
        if waited < limit_s or now - self.last_action < COOLDOWN_S:
            return [], None
        missing = set(range(blocks + 1, headers + 1))
        targets = [p for p in peers if missing & set(p.get("inflight") or [])]
        if not targets:
            if self.warned_idle:
                return [], None
            self.warned_idle = True
            return [], ("the node is %d block(s) behind for %d s, but no peer has the block in flight "
                        "(it may still be checking a large block)" % (headers - blocks, waited))
        self.last_action = now
        out = []
        for p in targets:
            desc = "peer %s (%s, %s)" % (p["id"], p.get("network", "?"), "inbound" if p.get("inbound") else "outbound")
            out.append((p["id"], desc))
        self.events.append({"at": now, "height": blocks + 1, "waited_s": round(waited),
                            "peers": [d for _, d in out]})
        del self.events[:-20]
        return out, None


def describe(event):
    return "%s: block %d waited %d s; disconnected %s" % (
        time.strftime("%H:%M:%S", time.localtime(event["at"])), event["height"], event["waited_s"],
        ", ".join(event["peers"]))
