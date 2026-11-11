"""Saving snapshots and diffing them against the current state."""

from __future__ import annotations

import json
import os
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


def append_snapshot(path: str, entries: Sequence[PortEntry]) -> int:
    """Append one snapshot as a JSON line to a history file; returns the record count."""
    record = {
        "version": FORMAT_VERSION,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": [e.to_dict() for e in sort_entries(entries)],
    }
    # Refuse to extend a file that is not a readable history.
    count = len(load_history(path)) if os.path.exists(path) else 0
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return count + 1


def load_history(path: str) -> List[Tuple[str, List[PortEntry]]]:
    """Read a history file (one snapshot per line) as (created, entries) pairs."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise SnapshotError(f"cannot read history {path}: {exc.strerror}") from exc
    history: List[Tuple[str, List[PortEntry]]] = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
            if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
                raise ValueError("not a portwatch snapshot record")
            history.append((str(doc["created"]), [PortEntry.from_dict(d) for d in doc["entries"]]))
        except (ValueError, KeyError, TypeError) as exc:
            raise SnapshotError(f"{path} line {n} is not a valid history record: {exc}") from exc
    return history


def parse_since(text: str) -> str:
    """Normalise a UTC date or date-time to the stored 'YYYY-MM-DDTHH:MM:SSZ' form.

    Accepts YYYY-MM-DD (midnight), YYYY-MM-DDTHH:MM and YYYY-MM-DDTHH:MM:SS,
    each with an optional trailing Z. Everything is UTC.
    """
    raw = text.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1]
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    raise ValueError(f"invalid date {text!r}; use YYYY-MM-DD or YYYY-MM-DDTHH:MM[:SS] (UTC)")


def history_changes(history: Sequence[Tuple[str, Sequence[PortEntry]]], since: str = ""):
    """Diff each snapshot against the one before it: [(created, Diff)] for records 2..N.

    With `since` (a normalised timestamp), only intervals that end at or after
    it are kept; each is still diffed against the snapshot just before it.
    """
    return [
        (history[i][0], diff_entries(history[i - 1][1], history[i][1]))
        for i in range(1, len(history))
        if history[i][0] >= since
    ]


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
