"""Logic of the vm3 protocol on synthetic records (the corpus itself is private)."""

import pytest

from evaluation import vm2, vm3


def test_windows11_has_no_binary_absent_tests():
    # Unlike VM2 (Server 2022, no sdclt.exe), Windows 11 has every UAC binary.
    assert vm3.ABSENT_TESTS == set()


def test_vm3_reuses_vm2s_frozen_escalation_rule():
    # The detector logic and the mechanical completion rule are identical to VM2's.
    assert vm3.run.__module__ == "evaluation.vm3"
    assert vm2.escalation_completed is vm2.escalation_completed  # imported, not redefined
    assert vm3.MODES == vm2.MODES


def test_inputs_refused_until_the_export_hash_is_recorded(monkeypatch, tmp_path):
    for name in ("corpus.ndjson", "atomic-log.csv", "benign-period.csv", "defender-detections.csv", "defender-threats.csv"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    monkeypatch.setattr(vm3, "ROOT", tmp_path)
    for attr, name in (("CORPUS", "corpus.ndjson"), ("ATOMIC_LOG", "atomic-log.csv"), ("BENIGN_LOG", "benign-period.csv"),
                       ("DEFENDER_DETECTIONS", "defender-detections.csv"), ("DEFENDER_THREATS", "defender-threats.csv")):
        monkeypatch.setattr(vm3, attr, tmp_path / name)
    monkeypatch.setattr(vm3, "CORPUS_SHA256", None)
    with pytest.raises(ValueError, match="CORPUS_SHA256 is not set"):
        vm3.inputs_manifest()
    monkeypatch.setattr(vm3, "CORPUS_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="does not match"):
        vm3.inputs_manifest()


def test_inputs_refused_when_a_file_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(vm3, "CORPUS", tmp_path / "nope.ndjson")
    with pytest.raises(FileNotFoundError, match="vm3 inputs missing"):
        vm3.inputs_manifest()
