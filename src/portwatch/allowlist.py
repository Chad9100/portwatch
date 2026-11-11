"""Allow-list files: declare which ports are expected, report the rest.

File format, one rule per line (blank lines and ``#`` comments are ignored)::

    22                # any protocol, port 22
    tcp/80,443        # tcp only, a list of ports
    udp/5000-5100     # a range
    tcp/3000 node     # only when the process name contains "node"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .filters import parse_ports
from .models import PortEntry


class AllowlistError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    proto: Optional[str]
    ports: Sequence[range]
    process: Optional[str] = None

    def matches(self, e: PortEntry) -> bool:
        if self.proto and e.proto != self.proto:
            return False
        if not any(e.port in r for r in self.ports):
            return False
        if self.process and self.process not in (e.process or "").lower():
            return False
        return True


def parse_allowlist(text: str, source: str = "allow-list") -> List[Rule]:
    rules: List[Rule] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        spec = parts[0]
        proto: Optional[str] = None
        if "/" in spec:
            proto, spec = spec.split("/", 1)
            proto = proto.lower()
            if proto not in ("tcp", "udp"):
                raise AllowlistError(f"{source}:{lineno}: unknown protocol {proto!r}")
        try:
            ports = parse_ports(spec)
        except ValueError as exc:
            raise AllowlistError(f"{source}:{lineno}: {exc}") from None
        if not ports:
            raise AllowlistError(f"{source}:{lineno}: missing port")
        process = parts[1].strip().lower() if len(parts) > 1 else None
        rules.append(Rule(proto, ports, process))
    return rules


def load_allowlist(path: str) -> List[Rule]:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError as exc:
        raise AllowlistError(f"cannot read allow-list {path}: {exc.strerror}") from exc
    return parse_allowlist(text, path)


def unexpected(entries: Sequence[PortEntry], rules: Sequence[Rule]) -> List[PortEntry]:
    return [e for e in entries if not any(r.matches(e) for r in rules)]
