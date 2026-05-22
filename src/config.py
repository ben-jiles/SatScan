from pydantic_settings import BaseSettings

class SatScanConfig(BaseSettings):
    version: str = "0.2.0"
    ai_enabled: bool = True
    default_model: str = "llama3.2:3b"
    temperature: float = 0.3

    class Config:
        env_prefix = "SATSCAN_"
