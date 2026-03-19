# raspberry_pi/inference.py  — FIXED VERSION
# Key change: pads live features to match model's expected 77 features

import numpy as np
import joblib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.helpers import log_runtime, log_error

class InferenceEngine:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.expected_features = 77   # what your Colab model was trained on
        self.is_ready = False
        self._load_all()

    def _load_all(self):
        models_dir = Path(__file__).parent.parent / "models"
        try:
            self.model = joblib.load(models_dir / "rf_model.joblib")
            self.scaler = joblib.load(models_dir / "rf_scaler.joblib")
            self.label_encoder = joblib.load(models_dir / "rf_label_encoder.joblib")

            with open(models_dir / "rf_features.json") as f:
                cfg = json.load(f)
            self.expected_features = len(cfg.get("features", []))

            self.is_ready = True
            log_runtime(f"✅ Model ready — expects {self.expected_features} features, "
                        f"{len(self.label_encoder.classes_)} classes")
        except Exception as e:
            log_error("Failed to load model files", e)

    def _pad_features(self, features: np.ndarray) -> np.ndarray:
        """Pad or truncate feature vector to match model input size."""
        current = len(features)
        if current == self.expected_features:
            return features
        elif current < self.expected_features:
            # Pad with zeros for missing features
            padded = np.zeros(self.expected_features, dtype=np.float32)
            padded[:current] = features
            return padded
        else:
            # Truncate if somehow more
            return features[:self.expected_features]

    def is_attack(self, features: np.ndarray, threshold: float = 0.5):
        """
        Returns (is_attack, class_name, confidence)
        """
        if not self.is_ready:
            return False, "UNKNOWN", 0.0
        try:
            features = self._pad_features(features)
            features_2d = features.reshape(1, -1)

            # Scale
            scaled = self.scaler.transform(features_2d)

            # Predict
            pred_class = int(self.model.predict(scaled)[0])
            probas = self.model.predict_proba(scaled)[0]
            confidence = float(probas[pred_class])

            # Get human-readable name
            class_name = self.label_encoder.inverse_transform([pred_class])[0]

            is_malicious = (pred_class != 0) and (confidence >= threshold)
            return is_malicious, pred_class, confidence

        except Exception as e:
            log_error("Inference error", e)
            return False, 0, 0.0

    def get_class_name(self, class_id: int) -> str:
        """Convert class number to attack name."""
        try:
            return self.label_encoder.inverse_transform([class_id])[0]
        except:
            return "UNKNOWN"