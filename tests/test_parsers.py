from pathlib import Path

import pytest

from portwatch import parsers
from portwatch.models import PortEntry

FIX = Path(__file__).parent / "fixtures"


def read(name):
    return (FIX / name).read_text(encoding="utf-8")


# ---- split_host_port

@pytest.mark.parametrize(
    "text,expected",
    [
        ("0.0.0.0:135", ("0.0.0.0", 135)),
        ("127.0.0.1:5432", ("127.0.0.1", 5432)),
        ("[::]:80", ("::", 80)),
        ("[::1]:8080", ("::1", 8080)),
        ("[fe80::1%12]:1900", ("fe80::1", 1900)),
        ("127.0.0.53%lo:53", ("127.0.0.53", 53)),
        ("*:123", ("*", 123)),
        (":22", ("*", 22)),
        ("*:*", None),
        ("nocolon", None),
        ("", None),
    ],
)
def test_split_host_port(text, expected):
    assert parsers.split_host_port(text) == expected


# ---- netstat

@pytest.fixture(scope="module")
def netstat():
    return parsers.parse_netstat(read("netstat_win.txt"))


def test_netstat_counts(netstat):
    assert len(netstat) == 11
    assert sum(e.proto == "tcp" for e in netstat) == 6
    assert sum(e.proto == "udp" for e in netstat) == 5


def test_netstat_skips_established_and_time_wait(netstat):
    ports = {e.port for e in netstat}
    assert 50321 not in ports
    assert 52000 not in ports


def test_netstat_ipv4_listener(netstat):
    assert PortEntry("tcp", "127.0.0.1", 5432, 4120) in netstat


def test_netstat_ipv6_listener(netstat):
    assert PortEntry("tcp", "::1", 8080, 7777) in netstat
    assert PortEntry("tcp", "::", 135, 1632) in netstat


def test_netstat_udp_uses_last_column_as_pid(netstat):
    assert PortEntry("udp", "0.0.0.0", 123, 2200) in netstat


def test_netstat_udp_zone_id_stripped(netstat):
    assert PortEntry("udp", "fe80::1", 1900, 4400) in netstat


def test_netstat_no_process_names(netstat):
    assert all(e.process is None for e in netstat)


def test_netstat_empty_and_garbage():
    assert parsers.parse_netstat("") == []
    assert parsers.parse_netstat("Active Connections\n\nfoo bar\n") == []


def test_netstat_crlf_lines():
    text = "  TCP    0.0.0.0:80   0.0.0.0:0   LISTENING   10\r\n"
    assert parsers.parse_netstat(text) == [PortEntry("tcp", "0.0.0.0", 80, 10)]


def test_netstat_lowercase_state_tolerated():
    text = "  tcp 0.0.0.0:80 0.0.0.0:0 listening 10\n"
    assert len(parsers.parse_netstat(text)) == 1


# ---- tasklist

def test_tasklist_map():
    names = parsers.parse_tasklist(read("tasklist.csv"))
    assert names[1632] == "svchost.exe"
    assert names[4] == "System"
    assert names[0] == "System Idle Process"


def test_tasklist_name_with_spaces_and_parens():
    names = parsers.parse_tasklist(read("tasklist.csv"))
    assert names[3300] == "Some App (x86).exe"


def test_tasklist_ignores_junk():
    assert parsers.parse_tasklist("INFO: nothing\n\n") == {}
    assert parsers.parse_tasklist('"a.exe","notanumber"\n') == {}


# ---- ss

@pytest.fixture(scope="module")
def ss():
    return parsers.parse_ss(read("ss.txt"))


def test_ss_skips_header_and_counts(ss):
    assert len(ss) == 9


def test_ss_process_info(ss):
    assert PortEntry("tcp", "0.0.0.0", 22, 801, "sshd") in ss


def test_ss_zone_id_removed(ss):
    assert PortEntry("udp", "127.0.0.53", 53, 612, "systemd-resolve") in ss


def test_ss_missing_process_is_none(ss):
    assert PortEntry("tcp", "::1", 631) in ss
    assert PortEntry("udp", "::", 5353) in ss


def test_ss_multiple_users_takes_first(ss):
    nginx = [e for e in ss if e.port == 80]
    assert nginx == [PortEntry("tcp", "0.0.0.0", 80, 900, "nginx")]


def test_ss_escaped_quotes_in_name(ss):
    assert PortEntry("tcp", "0.0.0.0", 3000, 1234, 'my "odd" app') in ss


def test_ss_ignores_other_netids():
    assert parsers.parse_ss("raw UNCONN 0 0 *:1 *:*\n") == []


def test_ss_empty():
    assert parsers.parse_ss("") == []


# ---- /proc/net

def test_proc_tcp_listen_only():
    result = parsers.parse_proc_net(read("proc_net_tcp.txt"), "tcp")
    assert [(e.address, e.port, inode) for e, inode in result] == [
        ("127.0.0.1", 53, 20001),
        ("0.0.0.0", 22, 20002),
    ]


def test_proc_tcp6():
    result = parsers.parse_proc_net(read("proc_net_tcp6.txt"), "tcp")
    assert [(e.address, e.port) for e, _ in result] == [("::", 22), ("::1", 631)]


def test_proc_udp_state_07():
    result = parsers.parse_proc_net(read("proc_net_udp.txt"), "udp")
    assert [(e.proto, e.address, e.port, i) for e, i in result] == [
        ("udp", "0.0.0.0", 68, 20020)
    ]


def test_proc_malformed_rows_skipped():
    text = "header\n  0: ZZZZ:0016 00000000:0000 0A 0:0 0:0 0 0 0 5\n"
    assert parsers.parse_proc_net(text, "tcp") == []


def test_compress_ipv6():
    assert parsers._compress_ipv6([0] * 8) == "::"
    assert parsers._compress_ipv6([0, 0, 0, 0, 0, 0, 0, 1]) == "::1"
    assert parsers._compress_ipv6([1, 2, 3, 4, 5, 6, 7, 8]) == "1:2:3:4:5:6:7:8"
    assert parsers._compress_ipv6([0xFE80, 0, 0, 0, 0, 0, 0, 1]) == "fe80::1"
