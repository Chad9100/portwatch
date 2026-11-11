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
portwatch list     [--port SPEC] [--proc NAME] [--proto tcp|udp] [--json]
portwatch snapshot FILE [filters]
portwatch diff     FILE [filters] [--json]
```

- `--port` takes a port, a list or ranges: `80`, `80,443`, `8000-8100,22`.
- `--proc` is a case-insensitive substring of the process name.
- TCP rows are listening sockets; UDP rows are bound sockets (UDP has no listen state).
- `diff` reports ports opened, closed, or whose owning process changed since the snapshot.
- Exit code is 0 on success and 2 on errors (bad snapshot, missing system tools).

On Linux, process names for sockets owned by other users need root (`sudo portwatch list`).
On Windows the parser expects English `netstat` output (the `LISTENING` state text).

## Example (real output)

The block below was captured by running the commands on a Windows 11 PC, not edited by hand.

```
$ portwatch list --proto tcp --port 1-1024
PROTO  ADDRESS          PORT  PID   PROCESS
tcp    0.0.0.0          135   1632  svchost.exe
tcp    ::               135   1632  svchost.exe
tcp    192.168.135.105  139   4     System
tcp    26.92.186.48     139   4     System
tcp    0.0.0.0          445   4     System
tcp    ::               445   4     System

$ portwatch list --proc code
PROTO  ADDRESS    PORT   PID    PROCESS
tcp    127.0.0.1  23894  15456  Code.exe
tcp    127.0.0.1  31440  26068  Code.exe
tcp    127.0.0.1  33371  3780   Code.exe
tcp    127.0.0.1  53890  19384  Code.exe
tcp    127.0.0.1  63460  5700   Code.exe

$ portwatch snapshot before.json
Saved 137 ports to before.json

$ portwatch diff before.json   # after starting a python listener on 48765
+ opened  tcp 127.0.0.1:48765  python.exe (pid 23632)
1 opened, 0 closed, 0 changed owner

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
