import pytest

from portwatch.filters import apply_filters, parse_ports
from portwatch.models import PortEntry

ENTRIES = [
    PortEntry("tcp", "0.0.0.0", 22, 1, "sshd"),
    PortEntry("tcp", "0.0.0.0", 80, 2, "nginx"),
    PortEntry("tcp", "::", 443, 2, "nginx"),
    PortEntry("udp", "0.0.0.0", 53, 3, "Dnsmasq"),
    PortEntry("tcp", "127.0.0.1", 8080, None, None),
]


def ports(result):
    return [e.port for e in result]


def test_parse_ports_none():
    assert parse_ports(None) is None
    assert parse_ports("") is None


def test_parse_ports_single_list_range():
    r = parse_ports("80,8000-8002")
    assert 80 in r[0] and 8001 in r[1] and 8003 not in r[1]


@pytest.mark.parametrize("bad", ["abc", "10-5", "70000", "1-99999", "-5", "1-2-3"])
def test_parse_ports_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_no_filters_returns_all():
    assert apply_filters(ENTRIES) == ENTRIES


def test_filter_port_single():
    assert ports(apply_filters(ENTRIES, port="80")) == [80]


def test_filter_port_list_and_range():
    assert ports(apply_filters(ENTRIES, port="22,8000-9000")) == [22, 8080]


def test_filter_proc_case_insensitive_substring():
    assert ports(apply_filters(ENTRIES, proc="NGI")) == [80, 443]
    assert ports(apply_filters(ENTRIES, proc="dns")) == [53]


def test_filter_proc_excludes_unknown_process():
    assert 8080 not in ports(apply_filters(ENTRIES, proc="e"))


def test_filter_proto():
    assert ports(apply_filters(ENTRIES, proto="udp")) == [53]
    assert len(apply_filters(ENTRIES, proto="TCP")) == 4


def test_filters_combine_with_and():
    assert ports(apply_filters(ENTRIES, port="1-100", proc="nginx", proto="tcp")) == [80]
    assert apply_filters(ENTRIES, port="22", proto="udp") == []
