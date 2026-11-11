import json

import pytest

from portwatch import cli
from portwatch.collect import CollectError
from portwatch.models import PortEntry

A = PortEntry("tcp", "0.0.0.0", 22, 100, "sshd")
B = PortEntry("tcp", "0.0.0.0", 80, 200, "nginx")
C = PortEntry("udp", "0.0.0.0", 53, None, None)


@pytest.fixture
def state(monkeypatch):
    holder = {"entries": [A, B, C]}
    monkeypatch.setattr(cli, "collect", lambda: list(holder["entries"]))
    return holder


def test_list_table(state, capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == ["PROTO", "ADDRESS", "PORT", "PID", "PROCESS"]
    assert "sshd" in out[1]
    assert out[3].split()[-2:] == ["-", "-"]  # unknown pid / process


def test_list_json(state, capsys):
    assert cli.main(["list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0] == A.to_dict()
    assert len(data) == 3


def test_list_filter_port(state, capsys):
    cli.main(["list", "--port", "80", "--json"])
    assert [e["port"] for e in json.loads(capsys.readouterr().out)] == [80]


def test_list_filter_proc(state, capsys):
    cli.main(["list", "--proc", "SSH", "--json"])
    assert [e["port"] for e in json.loads(capsys.readouterr().out)] == [22]


def test_list_filter_proto(state, capsys):
    cli.main(["list", "--proto", "udp", "--json"])
    assert [e["port"] for e in json.loads(capsys.readouterr().out)] == [53]


def test_list_no_match_prints_header_only(state, capsys):
    cli.main(["list", "--port", "9999"])
    assert len(capsys.readouterr().out.strip().splitlines()) == 1


def test_bad_port_spec_exits_2(state, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["list", "--port", "abc"])
    assert exc.value.code == 2


def test_bad_proto_exits_2(state):
    with pytest.raises(SystemExit):
        cli.main(["list", "--proto", "sctp"])


def test_no_command_exits_2():
    with pytest.raises(SystemExit):
        cli.main([])


def test_snapshot_writes_file(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    assert cli.main(["snapshot", str(f)]) == 0
    assert "Saved 3 ports" in capsys.readouterr().out
    assert len(json.loads(f.read_text())["entries"]) == 3


def test_snapshot_respects_filters(state, tmp_path):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f), "--proto", "tcp"])
    assert len(json.loads(f.read_text())["entries"]) == 2


def test_diff_no_changes(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f)])
    capsys.readouterr()
    assert cli.main(["diff", str(f)]) == 0
    assert "No changes" in capsys.readouterr().out


def test_diff_opened_and_closed(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f)])
    capsys.readouterr()
    new = PortEntry("tcp", "127.0.0.1", 5000, 5, "flask")
    state["entries"] = [A, C, new]
    cli.main(["diff", str(f)])
    out = capsys.readouterr().out
    assert "+ opened  tcp 127.0.0.1:5000  flask (pid 5)" in out
    assert "- closed  tcp 0.0.0.0:80  nginx (pid 200)" in out
    assert "1 opened, 1 closed, 0 changed owner" in out


def test_diff_json(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f)])
    capsys.readouterr()
    state["entries"] = [A, B]
    cli.main(["diff", str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["closed"] == [C.to_dict()]
    assert data["opened"] == [] and data["changed"] == []


def test_diff_owner_changed_line(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f)])
    capsys.readouterr()
    state["entries"] = [PortEntry("tcp", "0.0.0.0", 22, 777, "dropbear"), B, C]
    cli.main(["diff", str(f)])
    assert "~ owner   tcp 0.0.0.0:22  sshd (pid 100) -> dropbear (pid 777)" in capsys.readouterr().out


def test_diff_missing_snapshot_exits_2(state, tmp_path, capsys):
    assert cli.main(["diff", str(tmp_path / "none.json")]) == 2
    assert "error" in capsys.readouterr().err


def test_collect_error_exits_2(monkeypatch, capsys):
    def boom():
        raise CollectError("no tools")

    monkeypatch.setattr(cli, "collect", boom)
    assert cli.main(["list"]) == 2
    assert "no tools" in capsys.readouterr().err


def test_format_table_alignment():
    out = cli.format_table([A, PortEntry("tcp", "::1", 12345, 1, "x")])
    lines = out.splitlines()
    assert lines[0].index("PORT") == lines[1].index("22")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "portwatch 0.1.0" in capsys.readouterr().out
