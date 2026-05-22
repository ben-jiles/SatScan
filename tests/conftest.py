import pytest
from pathlib import Path
from src.parser.ccsds_parser import CCSDSParser

@pytest.fixture
def sample_packets():
    parser = CCSDSParser()
    return parser.parse_file(Path("samples/synthetic/normal_tm.bin"))
