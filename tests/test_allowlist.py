import json

import pytest

from portwatch import cli
from portwatch.allowlist import AllowlistError, parse_allowlist, unexpected
from portwatch.models import PortEntry

A = PortEntry("tcp", "0.0.0.0", 22, 100, "sshd")
B = PortEntry("tcp", "0.0.0.0", 80, 200, "nginx")
C = PortEntry("udp", "0.0.0.0", 53, None, None)


def test_parse_comments_and_blank_lines():
    rules = parse_allowlist("# hi\n\n22  # ssh\ntcp/80,443\n")
    assert len(rules) == 2
    assert rules[0].proto is None
    assert rules[1].proto == "tcp"


def test_proto_restricts():
    rules = parse_allowlist("udp/22\n")
    assert unexpected([A], rules) == [A]
    assert unexpected([PortEntry("udp", "::", 22)], rules) == []


def test_range_and_process():
    rules = parse_allowlist("tcp/1-100 SSHD\n")
    assert unexpected([A], rules) == []
    assert unexpected([PortEntry("tcp", "0.0.0.0", 22, 1, "other")], rules)
    assert unexpected([PortEntry("tcp", "0.0.0.0", 22)], rules)  # unknown owner


@pytest.mark.parametrize("text", ["abc\n", "icmp/1\n", "tcp/\n", "70000\n", "5-2\n"])
def test_bad_lines(text):
    with pytest.raises(AllowlistError):
        parse_allowlist(text)


def test_error_has_line_number():
    with pytest.raises(AllowlistError, match="allow-list:2:"):
        parse_allowlist("22\nbogus\n")


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(cli, "collect", lambda: [A, B, C])


def test_check_clean_exit_0(state, tmp_path, capsys):
    f = tmp_path / "allow.txt"
    f.write_text("22\n80\n53\n", encoding="utf-8")
    assert cli.main(["check", str(f)]) == 0
    assert "All 3 ports" in capsys.readouterr().out


def test_check_unexpected_exit_1(state, tmp_path, capsys):
    f = tmp_path / "allow.txt"
    f.write_text("tcp/22\n", encoding="utf-8")
    assert cli.main(["check", str(f)]) == 1
    out = capsys.readouterr().out
    assert "nginx" in out and "sshd" not in out
    assert "2 unexpected of 3 ports" in out


def test_check_json(state, tmp_path, capsys):
    f = tmp_path / "allow.txt"
    f.write_text("22,80\n", encoding="utf-8")
    assert cli.main(["check", str(f), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert [d["port"] for d in data] == [53]


def test_check_missing_file_exit_2(state, tmp_path, capsys):
    assert cli.main(["check", str(tmp_path / "nope.txt")]) == 2
    assert "cannot read allow-list" in capsys.readouterr().err


def test_check_bad_file_exit_2(state, tmp_path, capsys):
    f = tmp_path / "allow.txt"
    f.write_text("nonsense\n", encoding="utf-8")
    assert cli.main(["check", str(f)]) == 2


def test_check_respects_filters(state, tmp_path):
    f = tmp_path / "allow.txt"
    f.write_text("22\n", encoding="utf-8")
    assert cli.main(["check", str(f), "--proto", "tcp", "--port", "22"]) == 0
