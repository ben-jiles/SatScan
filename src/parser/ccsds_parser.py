from pathlib import Path
from typing import List
import logging
from src.parser.packet_models import ParsedPacket, CCSDSHeader

logger = logging.getLogger(__name__)

class CCSDSParser:
    def parse_file(self, file_path: Path) -> List[ParsedPacket]:
        """Basic parser - will be enhanced with spacepackets later."""
        try:
            data = file_path.read_bytes()
            packets = []
            # Simple synthetic packet creation for MVP
            for i in range(0, len(data), 64):
                packets.append(ParsedPacket(
                    header=CCSDSHeader(
                        version=1,
                        scid=123,
                        vcid=5,
                        apid=100 + (i % 50),
                        sequence_count=i // 64,
                        packet_length=64,
                        is_telecommand=False
                    ),
                    raw_data=data[i:i+64],
                    payload=data[i:i+64]
                ))
            return packets
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return []

    def generate_synthetic_samples(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        # Normal
        (output_dir / "normal_tm.bin").write_bytes(b'\x00' * 512)
        # Replay
        replay = b'\x01\x02\x03\x04' * 128
        (output_dir / "replay_attack.bin").write_bytes(replay * 3)
        # Spoofed
        (output_dir / "spoofed_tc.bin").write_bytes(b'\xFF' * 256)
        logger.info(f"Synthetic samples created in {output_dir}")
