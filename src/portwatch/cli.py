"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence

from . import __version__
from .collect import CollectError, collect
from .filters import apply_filters, parse_ports
from .models import PortEntry
from .snapshot import Diff, SnapshotError, diff_entries, load_snapshot, save_snapshot


def format_table(entries: Sequence[PortEntry]) -> str:
    rows = [("PROTO", "ADDRESS", "PORT", "PID", "PROCESS")]
    for e in entries:
        rows.append(
            (
                e.proto,
                e.address,
                str(e.port),
                "-" if e.pid is None else str(e.pid),
                e.process or "-",
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(5)]
    lines = []
    for r in rows:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    return "\n".join(lines)


def _describe(e: PortEntry) -> str:
    who = e.process or "?"
    pid = "-" if e.pid is None else e.pid
    return f"{e.proto} {e.address}:{e.port}  {who} (pid {pid})"


def format_diff(diff: Diff) -> str:
    if diff.empty:
        return "No changes since snapshot."
    lines = []
    for e in diff.opened:
        lines.append(f"+ opened  {_describe(e)}")
    for e in diff.closed:
        lines.append(f"- closed  {_describe(e)}")
    for a, b in diff.changed:
        lines.append(f"~ owner   {a.proto} {a.address}:{a.port}  {a.process or '?'} (pid {a.pid}) -> {b.process or '?'} (pid {b.pid})")
    lines.append(f"{len(diff.opened)} opened, {len(diff.closed)} closed, {len(diff.changed)} changed owner")
    return "\n".join(lines)


def _filter_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--port", help="port or list/range, e.g. 80, 80,443, 8000-8100")
    p.add_argument("--proc", help="case-insensitive substring of the process name")
    p.add_argument("--proto", choices=["tcp", "udp"], help="only this protocol")
    p.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portwatch", description="List listening ports and watch them change."
    )
    parser.add_argument("--version", action="version", version=f"portwatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list listening TCP and bound UDP ports")
    _filter_args(p_list)

    p_snap = sub.add_parser("snapshot", help="save the current ports to FILE")
    p_snap.add_argument("file")
    _filter_args(p_snap)

    p_diff = sub.add_parser("diff", help="show ports opened/closed since a snapshot")
    p_diff.add_argument("file")
    _filter_args(p_diff)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        parse_ports(args.port)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        current = apply_filters(collect(), args.port, args.proc, args.proto)
        if args.command == "list":
            if args.json:
                print(json.dumps([e.to_dict() for e in current], indent=2))
            else:
                print(format_table(current))
        elif args.command == "snapshot":
            save_snapshot(args.file, current)
            msg = f"Saved {len(current)} ports to {args.file}"
            if args.json:
                print(json.dumps({"saved": len(current), "file": args.file}))
            else:
                print(msg)
        else:
            old = apply_filters(load_snapshot(args.file), args.port, args.proc, args.proto)
            diff = diff_entries(old, current)
            print(json.dumps(diff.to_dict(), indent=2) if args.json else format_diff(diff))
    except (CollectError, SnapshotError, OSError) as exc:
        print(f"portwatch: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
