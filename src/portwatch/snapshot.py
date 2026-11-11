"""Saving snapshots and diffing them against the current state."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

from .models import PortEntry, sort_entries

FORMAT_VERSION = 1


class SnapshotError(ValueError):
    pass


def save_snapshot(path: str, entries: Sequence[PortEntry]) -> None:
    doc = {
        "version": FORMAT_VERSION,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": [e.to_dict() for e in sort_entries(entries)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def load_snapshot(path: str) -> List[PortEntry]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise SnapshotError(f"cannot read snapshot {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
        raise SnapshotError(f"{path} is not a portwatch snapshot (version {FORMAT_VERSION})")
    try:
        return [PortEntry.from_dict(d) for d in doc["entries"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise SnapshotError(f"{path} has malformed entries: {exc}") from exc


@dataclass
class Diff:
    opened: List[PortEntry] = field(default_factory=list)
    closed: List[PortEntry] = field(default_factory=list)
    # (before, after) where the socket is the same but another process owns it
    changed: List[Tuple[PortEntry, PortEntry]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.opened or self.closed or self.changed)

    def to_dict(self) -> Dict[str, object]:
        return {
            "opened": [e.to_dict() for e in self.opened],
            "closed": [e.to_dict() for e in self.closed],
            "changed": [{"before": a.to_dict(), "after": b.to_dict()} for a, b in self.changed],
        }


def _group(entries: Sequence[PortEntry]) -> Dict[Tuple[str, str, int], Dict[object, PortEntry]]:
    groups: Dict[Tuple[str, str, int], Dict[object, PortEntry]] = {}
    for e in entries:
        groups.setdefault(e.key, {})[e.pid] = e
    return groups


def _pid_order(pid):
    return (pid is None, pid or 0)


def diff_entries(old: Sequence[PortEntry], new: Sequence[PortEntry]) -> Diff:
    """Compare two listings.

    A socket address can have several owners at once (UDP 5353 with
    SO_REUSEADDR), so owners are compared per (proto, address, port). When
    one owner left and another arrived on the same address, that is
    reported as an owner change rather than a close plus an open.
    """
    old_g, new_g = _group(old), _group(new)
    diff = Diff()
    for key in set(old_g) | set(new_g):
        o, n = old_g.get(key, {}), new_g.get(key, {})
        gone = sorted(o.keys() - n.keys(), key=_pid_order)
        added = sorted(n.keys() - o.keys(), key=_pid_order)
        paired = min(len(gone), len(added))
        for g, a in zip(gone[:paired], added[:paired]):
            diff.changed.append((o[g], n[a]))
        diff.closed.extend(o[p] for p in gone[paired:])
        diff.opened.extend(n[p] for p in added[paired:])
    diff.opened = sort_entries(diff.opened)
    diff.closed = sort_entries(diff.closed)
    diff.changed.sort(key=lambda ab: (ab[0].port, ab[0].proto, ab[0].address))
    return diff
