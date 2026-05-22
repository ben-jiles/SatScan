import pytest
from pathlib import Path
from src.parser.ccsds_parser import CCSDSParser

def test_parser_synthetic():
    parser = CCSDSParser()
    packets = parser.parse_file(Path("samples/synthetic/normal_tm.bin"))
    assert len(packets) > 0
    assert packets[0].header.sequence_count is not None

def test_replay_detection():
    parser = CCSDSParser()
    packets = parser.parse_file(Path("samples/synthetic/replay_attack.bin"))
    from src.checks.engine import SecurityCheckEngine
    findings = SecurityCheckEngine().run_all(packets)
    replay_findings = [f for f in findings if "Replay" in f["check_type"]]
    assert len(replay_findings) > 0
