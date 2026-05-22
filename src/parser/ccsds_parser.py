import logging
from pathlib import Path
from typing import List, Dict, Any, Union
import scapy.all as scapy
from spacepackets.ccsds import SpacePacket
import ccsdspy
from .packet_models import ParsedPacket, CCSDSHeader

logger = logging.getLogger(__name__)

class CCSDSParser:
    def __init__(self):
        self.supported_types = ["tm", "tc", "space_packet"]

    def parse_file(self, file_path: Union[str, Path], file_type: str = "auto") -> List[ParsedPacket]:
        """Parse binary, pcap, or raw CCSDS file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if path.suffix.lower() == ".pcap":
            return self._parse_pcap(path)
        else:
            return self._parse_binary(path)

    def _parse_binary(self, path: Path) -> List[ParsedPacket]:
        packets = []
        data = path.read_bytes()

        # Try spacepackets first for Space Packets
        try:
            # Simple packet slicing logic (extend with full frame parsing)
            i = 0
            while i + 6 < len(data):
                pkt = SpacePacket.unpack(data[i:])
                header = CCSDSHeader(
                    version=1,
                    scid=0,  # Extract properly in full impl
                    vcid=0,
                    apid=pkt.apid,
                    sequence_count=pkt.seq_count,
                    packet_length=len(pkt.user_data),
                    is_telecommand=False
                )
                packets.append(ParsedPacket(
                    header=header,
                    raw_data=data[i:i+len(pkt)],
                    payload=pkt.user_data
                ))
                i += len(pkt)
        except Exception as e:
            logger.warning(f"spacepackets parsing failed, falling back: {e}")
            # Fallback to ccsdspy or construct

        return packets or [ParsedPacket(header=CCSDSHeader(version=0, scid=0, vcid=0, sequence_count=0, packet_length=len(data)), raw_data=data, payload=data)]

    def _parse_pcap(self, path: Path) -> List[ParsedPacket]:
        """Parse PCAP files using Scapy."""
        packets = []
        for pkt in scapy.rdpcap(str(path)):
            if pkt.haslayer(scapy.Raw):
                raw = pkt[scapy.Raw].load
                # Feed to binary parser
                packets.extend(self._parse_binary_from_bytes(raw))
        return packets

    def _parse_binary_from_bytes(self, data: bytes) -> List[ParsedPacket]:
        # Reuse logic from _parse_binary
        return []  # Placeholder - expand as needed

    def generate_synthetic_samples(self, output_dir: Path):
        """Generate test samples for replay, spoofing, normal cases."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Normal packet
        normal = b'\x00\x00\x00\x00' * 64  # Placeholder
        (output_dir / "normal_tm.bin").write_bytes(normal)
        
        # Replay (duplicate sequence)
        (output_dir / "replay_attack.bin").write_bytes(normal * 2)
        
        logger.info(f"Synthetic samples generated in {output_dir}")
