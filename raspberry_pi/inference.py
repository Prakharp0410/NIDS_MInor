# raspberry_pi/inference.py — FIXED VERSION

import numpy as np
import joblib
import json
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.helpers import log_runtime, log_error

class InferenceEngine:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.expected_features = 77
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

            # Handle both formats: plain list OR {"features": [...]}
            if isinstance(cfg, list):
                self.feature_names = cfg
            else:
                self.feature_names = cfg.get("features", [])

            self.expected_features = len(self.feature_names)
            self.is_ready = True
            log_runtime(f"✅ Model ready — expects {self.expected_features} features, "
                        f"{len(self.label_encoder.classes_)} classes")
        except Exception as e:
            log_error("Failed to load model files", e)

    def _pad_features(self, features: np.ndarray) -> np.ndarray:
        current = len(features)
        if current == self.expected_features:
            return features
        elif current < self.expected_features:
            padded = np.zeros(self.expected_features, dtype=np.float32)
            padded[:current] = features
            return padded
        else:
            return features[:self.expected_features]

    def is_attack(self, features: np.ndarray, threshold: float = 0.5):
        if not self.is_ready:
            return False, "UNKNOWN", 0.0
        try:
            features = self._pad_features(features)

            # Wrap in DataFrame with correct column names to suppress warning
            if self.feature_names:
                features_df = pd.DataFrame([features], columns=self.feature_names)
                scaled = self.scaler.transform(features_df)
            else:
                scaled = self.scaler.transform(features.reshape(1, -1))

            pred_class = int(self.model.predict(scaled)[0])
            probas = self.model.predict_proba(scaled)[0]
            confidence = float(probas[pred_class])
            class_name = self.label_encoder.inverse_transform([pred_class])[0]
            is_malicious = (pred_class != 0) and (confidence >= threshold)
            return is_malicious, pred_class, confidence

        except Exception as e:
            log_error("Inference error", e)
            return False, 0, 0.0

    def get_class_name(self, class_id: int) -> str:
        try:
            return self.label_encoder.inverse_transform([class_id])[0]
        except:
            return "UNKNOWN"
