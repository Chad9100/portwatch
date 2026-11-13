"""Command line interface."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from typing import List, Optional, Sequence

from . import __version__
from .allowlist import AllowlistError, load_allowlist, unexpected
from .collect import CollectError, collect
from .filters import apply_filters, parse_ports
from .models import PortEntry
from .services import service_name
from .snapshot import (
    Diff,
    SnapshotError,
    append_snapshot,
    diff_entries,
    history_changes,
    load_history,
    load_snapshot,
    parse_since,
    prune_history,
    save_snapshot,
)


def format_log(changes, count: int) -> str:
    """Render per-snapshot changes; `changes` is [(created, Diff)]."""
    lines = []
    for created, diff in changes:
        if diff.empty:
            lines.append(f"{created}  no changes")
            continue
        lines.append(f"{created}")
        for e in diff.opened:
            lines.append(f"  + opened  {_describe(e)}")
        for e in diff.closed:
            lines.append(f"  - closed  {_describe(e)}")
        for a, b in diff.changed:
            lines.append(
                f"  ~ owner   {a.proto} {_addr(a)}  {a.process or '?'} (pid {a.pid})"
                f" -> {b.process or '?'} (pid {b.pid})"
            )
    n = len(changes)
    lines.append(
        f"{count} {'snapshot' if count == 1 else 'snapshots'}, "
        f"{n} {'interval' if n == 1 else 'intervals'}"
    )
    return "\n".join(lines)


def summarize_changes(changes) -> List[dict]:
    """Count opened/closed/changed-owner events per (proto, port), sorted by port."""
    counts: dict = {}

    def bump(proto: str, port: int, field: str) -> None:
        row = counts.setdefault(
            (port, proto), {"proto": proto, "port": port, "opened": 0, "closed": 0, "changed": 0}
        )
        row[field] += 1

    for _created, diff in changes:
        for e in diff.opened:
            bump(e.proto, e.port, "opened")
        for e in diff.closed:
            bump(e.proto, e.port, "closed")
        for a, _b in diff.changed:
            bump(a.proto, a.port, "changed")
    return [counts[k] for k in sorted(counts)]


def format_summary(rows: Sequence[dict], count: int, intervals: int) -> str:
    table = [("PROTO", "PORT", "OPENED", "CLOSED", "CHANGED")]
    for r in rows:
        table.append((r["proto"], str(r["port"]), str(r["opened"]), str(r["closed"]), str(r["changed"])))
    lines = []
    if rows:
        widths = [max(len(t[i]) for t in table) for i in range(5)]
        for t in table:
            lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(t)).rstrip())
    else:
        lines.append("no changes")
    lines.append(f"{_plural(count, 'snapshot')}, {_plural(intervals, 'interval')}")
    return "\n".join(lines)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def format_table(entries: Sequence[PortEntry], services: bool = False) -> str:
    header = ("PROTO", "ADDRESS", "PORT", "PID", "PROCESS")
    rows = [header + ("SERVICE",) if services else header]
    for e in entries:
        row = (
            e.proto,
            e.address,
            str(e.port),
            "-" if e.pid is None else str(e.pid),
            e.process or "-",
        )
        if services:
            row += (service_name(e.port, e.proto) or "-",)
        rows.append(row)
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for r in rows:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    return "\n".join(lines)


SORT_KEYS = ["port", "proto", "address", "pid", "process"]


def sort_by(entries: Sequence[PortEntry], key: str) -> List[PortEntry]:
    """Stable sort by one column; ties keep the default (port, proto, ...) order."""
    if key == "pid":
        return sorted(entries, key=lambda e: (e.pid is None, e.pid or 0))
    if key == "process":
        return sorted(entries, key=lambda e: (not e.process, (e.process or "").lower()))
    return sorted(entries, key=lambda e: getattr(e, key))


def format_csv(entries: Sequence[PortEntry], services: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["proto", "address", "port", "pid", "process"] + (["service"] if services else []))
    for e in entries:
        row = [e.proto, e.address, e.port, "" if e.pid is None else e.pid, e.process or ""]
        if services:
            row.append(service_name(e.port, e.proto) or "")
        w.writerow(row)
    return buf.getvalue().rstrip("\n")


def _addr(e: PortEntry) -> str:
    host = f"[{e.address}]" if ":" in e.address else e.address
    return f"{host}:{e.port}"


def _describe(e: PortEntry) -> str:
    who = e.process or "?"
    pid = "-" if e.pid is None else e.pid
    return f"{e.proto} {_addr(e)}  {who} (pid {pid})"


def format_diff(diff: Diff) -> str:
    if diff.empty:
        return "No changes since snapshot."
    lines = []
    for e in diff.opened:
        lines.append(f"+ opened  {_describe(e)}")
    for e in diff.closed:
        lines.append(f"- closed  {_describe(e)}")
    for a, b in diff.changed:
        lines.append(f"~ owner   {a.proto} {_addr(a)}  {a.process or '?'} (pid {a.pid}) -> {b.process or '?'} (pid {b.pid})")
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
    p_list.add_argument(
        "--services", action="store_true", help="add a SERVICE column / field with well-known names"
    )
    p_list.add_argument("--csv", action="store_true", help="CSV output with a header row")
    p_list.add_argument(
        "--sort",
        choices=SORT_KEYS,
        help="sort by this column (default: port); unknown pid/process sort last",
    )

    p_snap = sub.add_parser("snapshot", help="save the current ports to FILE")
    p_snap.add_argument("file")
    p_snap.add_argument(
        "--append",
        action="store_true",
        help="append to FILE as a history (one snapshot per line) for 'portwatch log'",
    )
    _filter_args(p_snap)

    p_log = sub.add_parser("log", help="show what changed between the snapshots in a history file")
    p_log.add_argument("file", help="history file written by 'snapshot --append'")
    p_log.add_argument(
        "--since",
        metavar="DATE",
        help="only intervals ending at or after this UTC date/time, "
        "e.g. 2026-11-12 or 2026-11-12T08:30",
    )
    p_log.add_argument(
        "--until",
        metavar="DATE",
        help="only intervals ending at or before this UTC date/time (a bare date means midnight)",
    )
    p_log.add_argument(
        "--last",
        metavar="N",
        type=int,
        help="only the last N intervals (after --since/--until)",
    )
    p_log.add_argument(
        "--summary",
        action="store_true",
        help="print only per-port opened/closed/changed counts over the selected intervals",
    )
    _filter_args(p_log)

    p_prune = sub.add_parser("prune", help="trim old snapshots from a history file")
    p_prune.add_argument("file", help="history file written by 'snapshot --append'")
    p_prune.add_argument(
        "--keep", metavar="N", type=int, required=True, help="number of newest snapshots to keep"
    )
    p_prune.add_argument("--json", action="store_true", help="machine-readable output")

    p_diff = sub.add_parser("diff", help="show ports opened/closed since a snapshot")
    p_diff.add_argument("file")
    _filter_args(p_diff)

    p_check = sub.add_parser(
        "check", help="report ports not in an allow-list file (exit 1 if any)"
    )
    p_check.add_argument("file", help="allow-list file, one rule per line, e.g. tcp/22")
    _filter_args(p_check)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        parse_ports(getattr(args, "port", None))
    except ValueError as exc:
        parser.error(str(exc))
    since = ""
    if args.command == "log" and args.since:
        try:
            since = parse_since(args.since)
        except ValueError as exc:
            parser.error(str(exc))
    until = ""
    if args.command == "log" and args.until:
        try:
            until = parse_since(args.until)
        except ValueError as exc:
            parser.error(str(exc))
    if args.command == "log" and args.last is not None and args.last < 1:
        parser.error("--last must be at least 1")
    if args.command == "prune" and args.keep < 1:
        parser.error("--keep must be at least 1")
    try:
        if args.command == "prune":
            removed, kept = prune_history(args.file, args.keep)
            if args.json:
                print(json.dumps({"removed": removed, "kept": kept, "file": args.file}))
            else:
                print(f"Removed {_plural(removed, 'snapshot')} from {args.file}, kept {kept}")
            return 0
        if args.command == "log":
            history = [
                (created, apply_filters(entries, args.port, args.proc, args.proto))
                for created, entries in load_history(args.file)
            ]
            changes = history_changes(history, since, until, args.last)
            if args.summary:
                rows = summarize_changes(changes)
                if args.json:
                    print(json.dumps(rows, indent=2))
                else:
                    print(format_summary(rows, len(history), len(changes)))
            elif args.json:
                print(json.dumps(
                    [{"created": c, **d.to_dict()} for c, d in changes], indent=2))
            else:
                print(format_log(changes, len(history)))
            return 0
        current = apply_filters(collect(), args.port, args.proc, args.proto)
        if args.command == "list":
            if args.csv and args.json:
                parser.error("--csv and --json cannot be combined")
            if args.sort:
                current = sort_by(current, args.sort)
            if args.csv:
                print(format_csv(current, services=args.services))
            elif args.json:
                items = [e.to_dict() for e in current]
                if args.services:
                    for item in items:
                        item["service"] = service_name(item["port"], item["proto"])
                print(json.dumps(items, indent=2))
            else:
                print(format_table(current, services=args.services))
        elif args.command == "snapshot":
            if args.append:
                total = append_snapshot(args.file, current)
                msg = f"Appended {len(current)} ports to {args.file} ({_plural(total, 'snapshot')})"
            else:
                save_snapshot(args.file, current)
                msg = f"Saved {len(current)} ports to {args.file}"
            if args.json:
                print(json.dumps({"saved": len(current), "file": args.file}))
            else:
                print(msg)
        elif args.command == "check":
            bad = unexpected(current, load_allowlist(args.file))
            if args.json:
                print(json.dumps([e.to_dict() for e in bad], indent=2))
            elif bad:
                print(format_table(bad))
                print(f"{len(bad)} unexpected of {len(current)} ports")
            else:
                print(f"All {len(current)} ports are in the allow-list.")
            return 1 if bad else 0
        else:
            old = apply_filters(load_snapshot(args.file), args.port, args.proc, args.proto)
            diff = diff_entries(old, current)
            print(json.dumps(diff.to_dict(), indent=2) if args.json else format_diff(diff))
    except (CollectError, SnapshotError, AllowlistError, OSError) as exc:
        print(f"portwatch: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
