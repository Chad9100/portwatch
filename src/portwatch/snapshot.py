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


def diff_entries(old: Sequence[PortEntry], new: Sequence[PortEntry]) -> Diff:
    old_map = {e.key: e for e in old}
    new_map = {e.key: e for e in new}
    diff = Diff()
    diff.opened = sort_entries(new_map[k] for k in new_map.keys() - old_map.keys())
    diff.closed = sort_entries(old_map[k] for k in old_map.keys() - new_map.keys())
    for k in sorted(old_map.keys() & new_map.keys(), key=lambda k: (k[2], k[0], k[1])):
        a, b = old_map[k], new_map[k]
        if a.pid != b.pid:
            diff.changed.append((a, b))
    return diff
