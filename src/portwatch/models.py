"""Data model shared by parsers, collectors, snapshots and the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class PortEntry:
    """One listening (TCP) or bound (UDP) socket."""

    proto: str  # "tcp" or "udp"
    address: str  # local address without brackets, e.g. "0.0.0.0" or "::1"
    port: int
    pid: Optional[int] = None
    process: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str, int]:
        """Identity used for diffing: who the socket is, not who owns it."""
        return (self.proto, self.address, self.port)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PortEntry":
        pid = data.get("pid")
        return cls(
            proto=str(data["proto"]).lower(),
            address=str(data["address"]),
            port=int(data["port"]),
            pid=int(pid) if pid is not None else None,
            process=data.get("process"),
        )


def sort_entries(entries):
    """Sort by port and drop exact duplicate rows (same socket, same owner)."""
    unique = dict.fromkeys(entries)
    return sorted(unique, key=lambda e: (e.port, e.proto, e.address, e.pid or 0))
