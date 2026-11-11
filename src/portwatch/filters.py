"""Filtering of port entries."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from .models import PortEntry


def parse_ports(spec: Optional[str]) -> Optional[List[range]]:
    """Parse ``80``, ``80,443`` or ``8000-8100,22`` into ranges."""
    if not spec:
        return None
    ranges: List[range] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
            else:
                lo = hi = int(part)
        except ValueError:
            raise ValueError(f"invalid port spec: {part!r}") from None
        if lo > hi or lo < 0 or hi > 65535:
            raise ValueError(f"invalid port range: {part!r}")
        ranges.append(range(lo, hi + 1))
    return ranges or None


def apply_filters(
    entries: Iterable[PortEntry],
    port: Optional[str] = None,
    proc: Optional[str] = None,
    proto: Optional[str] = None,
) -> List[PortEntry]:
    ranges = parse_ports(port)
    needle = proc.lower() if proc else None
    proto = proto.lower() if proto else None
    result = []
    for e in entries:
        if proto and e.proto != proto:
            continue
        if ranges and not any(e.port in r for r in ranges):
            continue
        if needle and needle not in (e.process or "").lower():
            continue
        result.append(e)
    return result
