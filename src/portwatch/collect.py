"""Gather live data from the OS and feed it through the parsers."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from typing import Callable, Dict, List, Optional

from . import parsers
from .models import PortEntry, sort_entries

Runner = Callable[[List[str]], str]


class CollectError(RuntimeError):
    """Raised when the system tools needed to list ports are unavailable."""


def run_command(cmd: List[str]) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=60
        )
    except FileNotFoundError as exc:
        raise CollectError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectError(f"command timed out: {' '.join(cmd)}") from exc
    if proc.returncode != 0 and not proc.stdout:
        raise CollectError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout


def attach_names(entries: List[PortEntry], names: Dict[int, str]) -> List[PortEntry]:
    out = []
    for e in entries:
        if e.process is None and e.pid is not None and e.pid in names:
            e = replace(e, process=names[e.pid])
        out.append(e)
    return out


def collect_windows(runner: Runner = run_command) -> List[PortEntry]:
    entries = parsers.parse_netstat(runner(["netstat", "-ano"]))
    try:
        names = parsers.parse_tasklist(runner(["tasklist", "/fo", "csv", "/nh"]))
    except CollectError:
        names = {}  # still useful with PIDs only
    return sort_entries(attach_names(entries, names))


def _proc_comm(pid: int, proc_root: str) -> Optional[str]:
    try:
        with open(os.path.join(proc_root, str(pid), "comm")) as fh:
            return fh.read().strip()
    except OSError:
        return None


def _inode_owners(proc_root: str) -> Dict[int, int]:
    """Map socket inode -> pid by scanning /proc/<pid>/fd (needs privileges
    to see other users' processes)."""
    owners: Dict[int, int] = {}
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        fd_dir = os.path.join(proc_root, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owners.setdefault(int(target[8:-1]), int(pid))
    return owners


def collect_linux_proc(proc_root: str = "/proc") -> List[PortEntry]:
    """Fallback for systems without ``ss``: read /proc/net directly."""
    found = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(os.path.join(proc_root, "net", name)) as fh:
                found.extend(parsers.parse_proc_net(fh.read(), proto))
        except OSError:
            continue
    if not found:
        raise CollectError(f"could not read any socket tables under {proc_root}/net")
    owners = _inode_owners(proc_root)
    entries = []
    for entry, inode in found:
        pid = owners.get(inode)
        if pid is not None:
            entry = replace(entry, pid=pid, process=_proc_comm(pid, proc_root))
        entries.append(entry)
    return sort_entries(entries)


def collect_linux(runner: Runner = run_command) -> List[PortEntry]:
    try:
        return sort_entries(parsers.parse_ss(runner(["ss", "-tulnp"])))
    except CollectError:
        return collect_linux_proc()


def collect(platform: Optional[str] = None, runner: Runner = run_command) -> List[PortEntry]:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return collect_windows(runner)
    if platform.startswith("linux"):
        return collect_linux(runner)
    raise CollectError(f"unsupported platform: {platform} (Windows and Linux only)")
