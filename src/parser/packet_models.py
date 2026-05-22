from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class CCSDSHeader(BaseModel):
    version: int
    scid: int  # Spacecraft ID
    vcid: int  # Virtual Channel ID
    apid: Optional[int] = None
    sequence_count: int
    packet_length: int
    timestamp: Optional[datetime] = None
    is_telecommand: bool = False

class ParsedPacket(BaseModel):
    header: CCSDSHeader
    raw_data: bytes
    payload: bytes
    anomalies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
