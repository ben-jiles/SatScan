import numpy as np
from typing import List, Dict
from src.parser.packet_models import ParsedPacket

class MLAnomalyDetector:
    """Lightweight ML-based anomaly detection for telemetry sequences."""

    def __init__(self):
        self.model = None
        self.is_trained = False

    def extract_features(self, packets: List[ParsedPacket]) -> np.ndarray:
        """Extract sequence and timing features."""
        if not packets:
            return np.array([]).reshape(0, 3)

        features = []
        for pkt in packets:
            features.append([
                pkt.header.sequence_count,
                pkt.header.packet_length,
                len(pkt.payload)
            ])
        return np.array(features)

    def detect_anomalies(self, packets: List[ParsedPacket], contamination: float = 0.1) -> List[Dict]:
        """Run Isolation Forest for anomaly detection."""
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            return []  # Graceful fallback if ML extras not installed

        X = self.extract_features(packets)
        if len(X) < 5:
            return []  # Not enough data

        model = IsolationForest(contamination=contamination, random_state=42)
        predictions = model.fit_predict(X)

        findings = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                findings.append({
                    "id": f"ml_anomaly_{i}",
                    "check_type": "ML Anomaly Detector",
                    "description": f"Statistical anomaly detected in packet {i} (sequence/length outlier).",
                    "severity": "MEDIUM",
                    "sparta_id": "IA-0006",
                    "packet_index": i,
                    "recommendation": "Investigate for potential spoofing or sensor injection."
                })
        return findings
