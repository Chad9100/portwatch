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


def test_list_services_table(state, capsys):
    assert cli.main(["list", "--services"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split()[-1] == "SERVICE"
    assert out[1].split()[-1] == "ssh"
    assert out[2].split()[-1] == "http"
    assert out[3].split()[-1] == "dns"  # udp 53


def test_list_services_json_and_unknown(state, capsys):
    state["entries"].append(PortEntry("tcp", "127.0.0.1", 48765, 1, "x"))
    cli.main(["list", "--services", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert {d["port"]: d["service"] for d in data}[22] == "ssh"
    assert data[-1]["service"] is None


def test_list_without_services_unchanged(state, capsys):
    cli.main(["list"])
    assert "SERVICE" not in capsys.readouterr().out


def test_service_name_udp_only():
    from portwatch.services import service_name

    assert service_name(67, "udp") == "dhcp"
    assert service_name(67, "tcp") is None


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


def test_append_and_log(state, tmp_path, capsys):
    f = tmp_path / "hist.jsonl"
    assert cli.main(["snapshot", str(f), "--append"]) == 0
    assert "Appended 3 ports" in capsys.readouterr().out
    state["entries"] = [A, C, PortEntry("tcp", "127.0.0.1", 9000, 5, "py")]
    cli.main(["snapshot", str(f), "--append"])
    assert "(2 snapshots)" in capsys.readouterr().out
    state["entries"] = [A, C, PortEntry("tcp", "127.0.0.1", 9000, 5, "py")]
    cli.main(["snapshot", str(f), "--append"])
    capsys.readouterr()
    assert len(f.read_text().splitlines()) == 3
    assert cli.main(["log", str(f)]) == 0
    out = capsys.readouterr().out
    assert "+ opened  tcp 127.0.0.1:9000" in out
    assert "- closed  tcp 0.0.0.0:80" in out
    assert "no changes" in out
    assert out.splitlines()[-1] == "3 snapshots, 2 intervals"


def test_log_json_and_filter(state, tmp_path, capsys):
    f = tmp_path / "hist.jsonl"
    cli.main(["snapshot", str(f), "--append"])
    state["entries"] = [A]
    cli.main(["snapshot", str(f), "--append"])
    capsys.readouterr()
    assert cli.main(["log", str(f), "--json", "--port", "80"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and data[0]["closed"][0]["port"] == 80
    assert data[0]["created"].endswith("Z")
    cli.main(["log", str(f), "--port", "22"])
    assert "no changes" in capsys.readouterr().out


def test_log_errors(state, tmp_path, capsys):
    assert cli.main(["log", str(tmp_path / "missing")]) == 2
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n")
    assert cli.main(["log", str(bad)]) == 2
    assert "line 1" in capsys.readouterr().err
    assert cli.main(["snapshot", str(bad), "--append"]) == 2
    assert bad.read_text() == "not json\n"  # refused, not extended


def test_log_single_snapshot(state, tmp_path, capsys):
    f = tmp_path / "hist.jsonl"
    cli.main(["snapshot", str(f), "--append"])
    capsys.readouterr()
    cli.main(["log", str(f)])
    assert capsys.readouterr().out.strip() == "1 snapshot, 0 intervals"


def test_append_first_snapshot_singular(state, tmp_path, capsys):
    f = tmp_path / "hist.jsonl"
    cli.main(["snapshot", str(f), "--append"])
    assert capsys.readouterr().out.strip().endswith("(1 snapshot)")


def _write_history(path, stamps_entries):
    lines = [
        json.dumps({"version": 1, "created": c, "entries": [e.to_dict() for e in es]})
        for c, es in stamps_entries
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_log_since(tmp_path, capsys):
    f = tmp_path / "h.jsonl"
    _write_history(f, [
        ("2026-11-10T10:00:00Z", [A]),
        ("2026-11-10T11:00:00Z", [A, B]),
        ("2026-11-12T09:00:00Z", [A]),
        ("2026-11-12T10:30:00Z", [A, C]),
    ])
    assert cli.main(["log", str(f), "--since", "2026-11-11"]) == 0
    out = capsys.readouterr().out
    assert "2026-11-10" not in out
    assert "- closed  tcp 0.0.0.0:80" in out
    assert "+ opened  udp 0.0.0.0:53" in out
    assert out.splitlines()[-1] == "4 snapshots, 2 intervals"
    # time-of-day boundary is inclusive
    cli.main(["log", str(f), "--since", "2026-11-12T10:30:00Z", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [d["created"] for d in data] == ["2026-11-12T10:30:00Z"]
    cli.main(["log", str(f), "--since", "2026-11-12T10:31"])
    assert capsys.readouterr().out.strip() == "4 snapshots, 0 intervals"


def test_log_since_bad_date(tmp_path, capsys):
    f = tmp_path / "h.jsonl"
    _write_history(f, [("2026-11-10T10:00:00Z", [A])])
    with pytest.raises(SystemExit) as exc:
        cli.main(["log", str(f), "--since", "yesterday"])
    assert exc.value.code == 2
    assert "invalid date" in capsys.readouterr().err


def test_parse_since_forms():
    from portwatch.snapshot import parse_since

    assert parse_since("2026-11-12") == "2026-11-12T00:00:00Z"
    assert parse_since("2026-11-12T08:30") == "2026-11-12T08:30:00Z"
    assert parse_since("2026-11-12T08:30:05Z") == "2026-11-12T08:30:05Z"
    with pytest.raises(ValueError):
        parse_since("2026-13-01")


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


def test_diff_brackets_ipv6_addresses(state, tmp_path, capsys):
    f = tmp_path / "snap.json"
    cli.main(["snapshot", str(f)])
    capsys.readouterr()
    state["entries"] = [A, B, C, PortEntry("tcp", "::", 9000, 1, "srv")]
    cli.main(["diff", str(f)])
    assert "+ opened  tcp [::]:9000  srv (pid 1)" in capsys.readouterr().out


def _ports(capsys):
    out = capsys.readouterr().out.splitlines()[1:]
    return [int(line.split()[2]) for line in out]


def test_sort_by_pid_unknown_last(state, capsys):
    assert cli.main(["list", "--sort", "pid"]) == 0
    assert _ports(capsys) == [22, 80, 53]  # pids 100, 200, None


def test_sort_by_process_case_insensitive_unknown_last(state, capsys):
    state["entries"].append(PortEntry("tcp", "0.0.0.0", 9, 5, "Apache"))
    cli.main(["list", "--sort", "process"])
    assert _ports(capsys) == [9, 80, 22, 53]  # Apache, nginx, sshd, none


def test_sort_by_proto(state, capsys):
    cli.main(["list", "--sort", "proto"])
    assert _ports(capsys) == [22, 80, 53]  # tcp, tcp, udp


def test_csv_output(state, capsys):
    assert cli.main(["list", "--csv"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "proto,address,port,pid,process",
        "tcp,0.0.0.0,22,100,sshd",
        "tcp,0.0.0.0,80,200,nginx",
        "udp,0.0.0.0,53,,",
    ]


def test_csv_services_and_quoting(state, capsys):
    state["entries"] = [PortEntry("tcp", "::1", 22, 1, "a,b")]
    cli.main(["list", "--csv", "--services"])
    assert capsys.readouterr().out.splitlines() == [
        "proto,address,port,pid,process,service",
        'tcp,::1,22,1,"a,b",ssh',
    ]


def test_csv_and_json_conflict(state):
    with pytest.raises(SystemExit) as exc:
        cli.main(["list", "--csv", "--json"])
    assert exc.value.code == 2


def test_sort_applies_to_json(state, capsys):
    cli.main(["list", "--sort", "pid", "--json"])
    assert [d["port"] for d in json.loads(capsys.readouterr().out)] == [22, 80, 53]
