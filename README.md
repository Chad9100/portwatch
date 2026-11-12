# portwatch

See which processes are listening on which ports, and what changed since last time.
Pure Python standard library, no dependencies. Works on Windows (`netstat -ano` +
`tasklist`) and Linux (`ss -tulnp`, with a `/proc/net` fallback).

## Install

```
pip install .
```

Requires Python 3.10+. This installs a `portwatch` command (also `python -m portwatch`).

## Usage

```
portwatch list     [--port SPEC] [--proc NAME] [--proto tcp|udp] [--json | --csv] [--services]
                   [--sort port|proto|address|pid|process]
portwatch snapshot FILE [filters]
portwatch snapshot FILE --append [filters]
portwatch log      FILE [filters] [--since DATE] [--until DATE] [--last N] [--json]
portwatch diff     FILE [filters] [--json]
portwatch check    ALLOWFILE [filters] [--json]
```

- `snapshot --append` adds the current ports to FILE as one JSON line instead of overwriting it, building a history (it refuses to extend a file that is not a valid history). `log FILE` then prints what opened, closed or changed owner between each pair of consecutive snapshots, with UTC timestamps; filters apply to the stored snapshots, and nothing is collected live. `--since DATE` keeps only intervals that end at or after a UTC date or time (`2026-11-12`, `2026-11-12T08:30`, `2026-11-12T08:30:05`, optional trailing `Z`); each kept interval is still compared with the snapshot just before it, and the last line still counts every snapshot in the file. `--until DATE` is the mirror image (same date forms, a bare date means midnight, the boundary is inclusive), so `--since` and `--until` together select a window. `--last N` keeps only the final N intervals after those bounds (N must be at least 1).
- `check` lists sockets that match no rule in the allow-list file and exits 1 if there are any (0 if all are expected), for CI/cron use. One rule per line, `#` starts a comment: `22` (any protocol), `tcp/80,443`, `udp/5000-5100`, and an optional process-name substring after the ports (`tcp/3000 node`). A bad rule is an error with its line number (exit 2).

- `--port` takes a port, a list or ranges: `80`, `80,443`, `8000-8100,22`.
- `--proc` is a case-insensitive substring of the process name.
- `--services` (list only) adds a SERVICE column (a `service` field in JSON, `null` if unknown) from a built-in table of well-known ports such as 22 ssh and 443 https.
- `--csv` (list only, not with `--json`) prints a header row and one line per socket; unknown pid/process are empty fields.
- `--sort` (list only) orders by one column; the default is port. Process names sort case-insensitively, and unknown pids/processes come last.
- TCP rows are listening sockets; UDP rows are bound sockets (UDP has no listen state).
- `diff` reports ports opened, closed, or whose owning process changed since the snapshot.
- Exit code is 0 on success and 2 on errors (bad snapshot or allow-list, missing system tools); `check` also exits 1 when unexpected ports are found.

On Linux, process names for sockets owned by other users need root (`sudo portwatch list`).
On Windows the parser expects English `netstat` output (the `LISTENING` state text).

## Example (real output)

The block below was captured by running the commands on a Windows 11 PC. The only edit is that two private network addresses (a LAN and a VPN address) in the first two tables, the first CSV block and the `check` table were replaced with the documentation addresses 192.0.2.10 and 192.0.2.11 (column widths adjusted to match).

```
$ portwatch list --proto tcp --port 1-1024
PROTO  ADDRESS          PORT  PID   PROCESS
tcp    0.0.0.0          135   1632  svchost.exe
tcp    ::               135   1632  svchost.exe
tcp    192.0.2.10       139   4     System
tcp    192.0.2.11       139   4     System
tcp    0.0.0.0          445   4     System
tcp    ::               445   4     System

$ portwatch list --proto tcp --port 1-1024 --services
PROTO  ADDRESS     PORT  PID   PROCESS      SERVICE
tcp    0.0.0.0     135   1632  svchost.exe  msrpc
tcp    ::          135   1632  svchost.exe  msrpc
tcp    192.0.2.10  139   4     System       netbios-ssn
tcp    192.0.2.11  139   4     System       netbios-ssn
tcp    0.0.0.0     445   4     System       smb
tcp    ::          445   4     System       smb

$ portwatch list --proc code
PROTO  ADDRESS    PORT   PID    PROCESS
tcp    127.0.0.1  23894  15456  Code.exe
tcp    127.0.0.1  31440  26068  Code.exe
tcp    127.0.0.1  33371  3780   Code.exe
tcp    127.0.0.1  53890  19384  Code.exe
tcp    127.0.0.1  63460  5700   Code.exe

$ portwatch list --proto tcp --port 1-1024 --csv --services
proto,address,port,pid,process,service
tcp,0.0.0.0,135,1632,svchost.exe,msrpc
tcp,::,135,1632,svchost.exe,msrpc
tcp,192.0.2.10,139,4,System,netbios-ssn
tcp,192.0.2.11,139,4,System,netbios-ssn
tcp,0.0.0.0,445,4,System,smb
tcp,::,445,4,System,smb

$ portwatch list --proc code --sort pid --csv
proto,address,port,pid,process
tcp,127.0.0.1,33371,3780,Code.exe
tcp,127.0.0.1,63460,5700,Code.exe
tcp,127.0.0.1,23894,15456,Code.exe
tcp,127.0.0.1,53890,19384,Code.exe
tcp,127.0.0.1,31440,26068,Code.exe

$ cat allow.txt
# expected
tcp/135 svchost
445
$ portwatch check allow.txt --proto tcp --port 1-1024
PROTO  ADDRESS     PORT  PID  PROCESS
tcp    192.0.2.10  139   4    System
tcp    192.0.2.11  139   4    System
2 unexpected of 6 ports
$ echo $?
1

$ portwatch snapshot before.json
Saved 137 ports to before.json

$ portwatch diff before.json   # after starting a python listener on 48765
+ opened  tcp 127.0.0.1:48765  python.exe (pid 23632)
1 opened, 0 closed, 0 changed owner

$ portwatch snapshot hist.jsonl --append --proto tcp --port 40000-50000   # three times, with a python listener on 48765 open only during the second
Appended 19 ports to hist.jsonl (1 snapshot)
Appended 20 ports to hist.jsonl (2 snapshots)
Appended 19 ports to hist.jsonl (3 snapshots)

$ portwatch log hist.jsonl
2026-11-12T00:07:56Z
  + opened  tcp 127.0.0.1:48765  python.exe (pid 19616)
2026-11-12T00:07:57Z
  - closed  tcp 127.0.0.1:48765  python.exe (pid 19616)
3 snapshots, 2 intervals

$ portwatch log hist.jsonl --since 2026-11-12T01:46:33   # from a separate identical run, so timestamps and pid differ from above
2026-11-12T01:46:34Z
  - closed  tcp 127.0.0.1:48765  python.exe (pid 9704)
3 snapshots, 1 interval

$ portwatch log hist.jsonl --last 2   # from another identical run (python listener on 48765 open only during the first interval), 4 snapshots
2026-11-12T03:07:17Z
  - closed  tcp 127.0.0.1:48765  python.exe (pid 12984)
2026-11-12T03:07:19Z  no changes
4 snapshots, 2 intervals

$ portwatch log hist.jsonl --until 2026-11-12T03:07:16
2026-11-12T03:07:15Z
  + opened  tcp 127.0.0.1:48765  python.exe (pid 12984)
4 snapshots, 1 interval

$ portwatch log hist.jsonl --since 2026-11-12T03:07:16 --until 2026-11-12T03:07:17
2026-11-12T03:07:17Z
  - closed  tcp 127.0.0.1:48765  python.exe (pid 12984)
4 snapshots, 1 interval

$ portwatch list --port 48765 --json
[
  {
    "proto": "tcp",
    "address": "127.0.0.1",
    "port": 48765,
    "pid": 23632,
    "process": "python.exe"
  }
]
```

## Development

```
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"    # .venv/bin/pip on Linux
pytest
```

The parsers in `src/portwatch/parsers.py` are pure functions tested against
fixture output in `tests/fixtures/`; the command runner is injected so the
collectors are tested without touching the system. See [ROADMAP.md](ROADMAP.md).

## License

MIT
