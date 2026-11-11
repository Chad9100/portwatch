"""Pure parsers for the text produced by netstat, tasklist, ss and /proc.

Nothing here touches the system, so every function is unit-tested with
fixture output.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Dict, List, Optional, Tuple

from .models import PortEntry


def split_host_port(text: str) -> Optional[Tuple[str, int]]:
    """Split ``host:port`` (IPv4, ``[v6]:port``, ``*:port``) into parts.

    Returns None when the text has no numeric port (e.g. ``*:*``).
    """
    text = text.strip()
    if ":" not in text:
        return None
    host, _, port = text.rpartition(":")
    if not port.isdigit():
        return None
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.split("%", 1)[0]  # drop zone id such as %lo or %12
    if host == "":
        host = "*"
    return host, int(port)


# --------------------------------------------------------------- Windows


def parse_netstat(text: str) -> List[PortEntry]:
    """Parse ``netstat -ano`` output. Process names are not filled in.

    TCP rows count only when LISTENING. UDP has no state, so every UDP
    row with a numeric local port is a bound socket.
    """
    entries: List[PortEntry] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto == "TCP" and len(parts) >= 5:
            if parts[3].upper() != "LISTENING":
                continue
            pid_text = parts[4]
        elif proto == "UDP":
            pid_text = parts[-1]
        else:
            continue
        local = split_host_port(parts[1])
        if local is None:
            continue
        pid = int(pid_text) if pid_text.isdigit() else None
        entries.append(PortEntry(proto.lower(), local[0], local[1], pid))
    return entries


def parse_tasklist(text: str) -> Dict[int, str]:
    """Parse ``tasklist /fo csv /nh`` into a pid -> image name map."""
    names: Dict[int, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not row[1].strip().isdigit():
            continue
        names[int(row[1])] = row[0]
    return names


# ----------------------------------------------------------------- Linux

_SS_USERS = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')


def parse_ss(text: str) -> List[PortEntry]:
    """Parse ``ss -tulnp`` output (process info included when present)."""
    entries: List[PortEntry] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        local = split_host_port(parts[4])
        if local is None:
            continue
        pid: Optional[int] = None
        name: Optional[str] = None
        match = _SS_USERS.search(line)
        if match:
            name = match.group(1).replace('\\"', '"')
            pid = int(match.group(2))
        entries.append(PortEntry(proto, local[0], local[1], pid, name))
    return entries


def _decode_proc_address(hex_addr: str) -> str:
    """Decode the hex address column of /proc/net/{tcp,udp}[6]."""
    if len(hex_addr) == 8:
        raw = bytes.fromhex(hex_addr)[::-1]  # stored little-endian
        return ".".join(str(b) for b in raw)
    # IPv6: four 32-bit words, each little-endian
    raw = b"".join(bytes.fromhex(hex_addr[i : i + 8])[::-1] for i in range(0, 32, 8))
    groups = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, 16, 2)]
    return _compress_ipv6(groups)


def _compress_ipv6(groups: List[int]) -> str:
    # Find the longest run of zero groups (length >= 2) for "::" compression.
    best_start, best_len, i = -1, 0, 0
    while i < 8:
        if groups[i] == 0:
            j = i
            while j < 8 and groups[j] == 0:
                j += 1
            if j - i > best_len:
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best_start])
    tail = ":".join(f"{g:x}" for g in groups[best_start + best_len :])
    return f"{head}::{tail}"


def parse_proc_net(text: str, proto: str) -> List[Tuple[PortEntry, int]]:
    """Parse one /proc/net file. Returns (entry, socket inode) pairs.

    ``proto`` is "tcp" or "udp". TCP keeps only state 0A (LISTEN); UDP
    keeps state 07 (unconnected, i.e. bound).
    """
    wanted_state = "0A" if proto == "tcp" else "07"
    result: List[Tuple[PortEntry, int]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or ":" not in parts[1]:
            continue
        if parts[3].upper() != wanted_state:
            continue
        addr_hex, _, port_hex = parts[1].partition(":")
        try:
            address = _decode_proc_address(addr_hex)
            port = int(port_hex, 16)
            inode = int(parts[9])
        except ValueError:
            continue
        result.append((PortEntry(proto, address, port), inode))
    return result
