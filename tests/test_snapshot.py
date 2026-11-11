import json

import pytest

from portwatch.models import PortEntry
from portwatch.snapshot import (
    SnapshotError,
    diff_entries,
    load_snapshot,
    save_snapshot,
)

A = PortEntry("tcp", "0.0.0.0", 22, 100, "sshd")
B = PortEntry("tcp", "0.0.0.0", 80, 200, "nginx")
C = PortEntry("udp", "0.0.0.0", 53, 300, "dns")


def test_roundtrip(tmp_path):
    f = tmp_path / "s.json"
    save_snapshot(str(f), [B, A, PortEntry("tcp", "::1", 631)])
    loaded = load_snapshot(str(f))
    assert loaded == [A, B, PortEntry("tcp", "::1", 631)]  # saved sorted by port


def test_saved_file_shape(tmp_path):
    f = tmp_path / "s.json"
    save_snapshot(str(f), [A])
    doc = json.loads(f.read_text())
    assert doc["version"] == 1
    assert doc["created"].endswith("Z")
    assert doc["entries"] == [A.to_dict()]


def test_load_missing_file(tmp_path):
    with pytest.raises(SnapshotError):
        load_snapshot(str(tmp_path / "nope.json"))


def test_load_invalid_json(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("{not json")
    with pytest.raises(SnapshotError):
        load_snapshot(str(f))


def test_load_wrong_version(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"version": 99, "entries": []}))
    with pytest.raises(SnapshotError):
        load_snapshot(str(f))


def test_load_not_an_object(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("[1, 2]")
    with pytest.raises(SnapshotError):
        load_snapshot(str(f))


def test_load_malformed_entries(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"version": 1, "entries": [{"proto": "tcp"}]}))
    with pytest.raises(SnapshotError):
        load_snapshot(str(f))


def test_diff_identical_is_empty():
    assert diff_entries([A, B], [A, B]).empty


def test_diff_opened():
    d = diff_entries([A], [A, B])
    assert d.opened == [B] and d.closed == [] and d.changed == []


def test_diff_closed():
    d = diff_entries([A, B], [A])
    assert d.closed == [B] and d.opened == []


def test_diff_owner_change():
    new_a = PortEntry("tcp", "0.0.0.0", 22, 999, "other")
    d = diff_entries([A], [new_a])
    assert d.changed == [(A, new_a)]
    assert d.opened == [] and d.closed == []
    assert not d.empty


def test_diff_same_port_different_proto_is_distinct():
    udp22 = PortEntry("udp", "0.0.0.0", 22, 1)
    d = diff_entries([A], [A, udp22])
    assert d.opened == [udp22]


def test_diff_results_sorted_by_port():
    d = diff_entries([], [B, A, C])
    assert [e.port for e in d.opened] == [22, 53, 80]


def test_diff_to_dict():
    d = diff_entries([A], [B])
    out = d.to_dict()
    assert out["opened"] == [B.to_dict()]
    assert out["closed"] == [A.to_dict()]
    assert out["changed"] == []


def test_entry_from_dict_defaults():
    e = PortEntry.from_dict({"proto": "TCP", "address": "::", "port": "80"})
    assert e == PortEntry("tcp", "::", 80, None, None)
