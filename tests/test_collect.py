from pathlib import Path

import pytest

from portwatch import collect as c
from portwatch.models import PortEntry

FIX = Path(__file__).parent / "fixtures"


def read(name):
    return (FIX / name).read_text(encoding="utf-8")


def fake_runner(outputs):
    calls = []

    def run(cmd):
        calls.append(cmd)
        out = outputs[cmd[0]]
        if isinstance(out, Exception):
            raise out
        return out

    run.calls = calls
    return run


def test_windows_joins_names():
    run = fake_runner({"netstat": read("netstat_win.txt"), "tasklist": read("tasklist.csv")})
    entries = c.collect("win32", run)
    by_key = {e.key: e for e in entries}
    assert by_key[("tcp", "127.0.0.1", 5432)].process == "postgres.exe"
    assert by_key[("tcp", "0.0.0.0", 445)].process == "System"
    assert run.calls[0] == ["netstat", "-ano"]
    assert run.calls[1] == ["tasklist", "/fo", "csv", "/nh"]


def test_windows_unknown_pid_has_no_name():
    run = fake_runner({"netstat": read("netstat_win.txt"), "tasklist": ""})
    entries = c.collect("win32", run)
    assert all(e.process is None for e in entries)
    assert entries[0].pid is not None


def test_windows_tasklist_failure_still_lists():
    run = fake_runner(
        {"netstat": read("netstat_win.txt"), "tasklist": c.CollectError("denied")}
    )
    assert len(c.collect("win32", run)) == 11


def test_windows_netstat_failure_raises():
    run = fake_runner({"netstat": c.CollectError("boom")})
    with pytest.raises(c.CollectError):
        c.collect("win32", run)


def test_windows_sorted_by_port():
    run = fake_runner({"netstat": read("netstat_win.txt"), "tasklist": read("tasklist.csv")})
    ports = [e.port for e in c.collect("win32", run)]
    assert ports == sorted(ports)


def test_linux_uses_ss():
    run = fake_runner({"ss": read("ss.txt")})
    entries = c.collect("linux", run)
    assert len(entries) == 9
    assert run.calls == [["ss", "-tulnp"]]


def test_linux_falls_back_to_proc(monkeypatch):
    monkeypatch.setattr(
        c, "collect_linux_proc", lambda: [PortEntry("tcp", "0.0.0.0", 1, 2, "x")]
    )
    run = fake_runner({"ss": c.CollectError("command not found: ss")})
    assert c.collect("linux", run) == [PortEntry("tcp", "0.0.0.0", 1, 2, "x")]


def test_unsupported_platform():
    with pytest.raises(c.CollectError):
        c.collect("darwin", fake_runner({}))


def make_proc_tree(tmp_path):
    root = tmp_path / "proc"
    (root / "net").mkdir(parents=True)
    for name in ("tcp", "tcp6", "udp"):
        (root / "net" / name).write_text(read(f"proc_net_{name}.txt"))
    return root


def test_proc_fallback_without_owners(tmp_path):
    root = make_proc_tree(tmp_path)
    entries = c.collect_linux_proc(str(root))
    assert {(e.proto, e.port) for e in entries} == {
        ("tcp", 53), ("tcp", 22), ("tcp", 631), ("udp", 68),
    }
    assert all(e.pid is None for e in entries)


def test_proc_fallback_with_no_tables(tmp_path):
    with pytest.raises(c.CollectError):
        c.collect_linux_proc(str(tmp_path))


def test_proc_comm_missing(tmp_path):
    assert c._proc_comm(99, str(tmp_path)) is None


def test_proc_comm_read(tmp_path):
    (tmp_path / "7").mkdir()
    (tmp_path / "7" / "comm").write_text("sshd\n")
    assert c._proc_comm(7, str(tmp_path)) == "sshd"


def test_run_command_missing_binary():
    with pytest.raises(c.CollectError):
        c.run_command(["definitely-not-a-real-command-xyz"])
