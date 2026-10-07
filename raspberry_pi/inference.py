"""
ML inference for the Raspberry Pi NIDS/NIPS.

Loads the Random Forest, StandardScaler and LabelEncoder trained on
CICIDS2017 and classifies flow feature vectors, singly or in batches.

Tuned for the Pi:
- the forest runs on one thread (n_jobs=1). With n_jobs=-1 every call
  spins up a thread pool, which costs far more than the trees themselves
  for the handful of rows the engine classifies at a time;
- scaling is plain numpy arithmetic instead of a pandas DataFrame;
- one predict_proba call gives both the class and its confidence;
- batches cost almost the same as single rows, so the engine queues flows
  and classifies them together.
"""

import json
import sys
import warnings
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.helpers import log_runtime, log_error, attack_family

Prediction = Tuple[int, str, float]   # (class index, model class name, confidence)


class InferenceEngine:
    def __init__(self, models_dir: Optional[Path] = None, n_jobs: int = 1):
        self.models_dir = Path(models_dir) if models_dir else Path(__file__).parent.parent / "models"
        self.n_jobs = n_jobs
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names: List[str] = []
        self.class_names: List[str] = []
        self.benign_indices = set()
        self.expected_features = 77
        self.is_ready = False
        self._mean = None
        self._scale = None
        self._load_all()

    def _load_all(self):
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.model = joblib.load(self.models_dir / "rf_model.joblib")
                self.scaler = joblib.load(self.models_dir / "rf_scaler.joblib")
                self.label_encoder = joblib.load(self.models_dir / "rf_label_encoder.joblib")
            self._report_version_mismatch(caught)

            with open(self.models_dir / "rf_features.json") as f:
                cfg = json.load(f)
            self.feature_names = cfg if isinstance(cfg, list) else cfg.get("features", [])
            self.expected_features = len(self.feature_names)

            if hasattr(self.model, "n_jobs"):
                self.model.n_jobs = self.n_jobs
            if hasattr(self.model, "verbose"):
                self.model.verbose = 0

            self._mean = np.asarray(self.scaler.mean_, dtype=np.float64)
            self._scale = np.asarray(self.scaler.scale_, dtype=np.float64)
            self._scale[self._scale == 0] = 1.0

            # The encoder's labels in model-index order. Fix the mojibake
            # dash in "Web Attack - ..." left by the CSV encoding.
            model_classes = getattr(self.model, "classes_", np.arange(len(self.label_encoder.classes_)))
            self.class_names = [
                str(self.label_encoder.inverse_transform([int(c)])[0]).replace("�", "-")
                for c in model_classes
            ]
            self.benign_indices = {i for i, name in enumerate(self.class_names)
                                   if name.strip().lower() == "benign"}

            self.predict_batch(np.zeros((1, self.expected_features)))   # warm-up
            self.is_ready = True
            log_runtime(f"Model ready: {self.expected_features} features, "
                        f"{len(self.class_names)} classes, n_jobs={self.n_jobs}")
        except Exception as e:
            log_error("Failed to load model files", e)

    @staticmethod
    def _report_version_mismatch(caught):
        """scikit-learn warns when a model was saved by another version."""
        for w in caught:
            if "version" in str(w.message).lower():
                log_runtime("The model files were saved with a different scikit-learn "
                            "version; install the pinned version from requirements.txt. "
                            f"Detail: {str(w.message).splitlines()[0]}", "WARNING")
                return

    # ── Prediction ─────────────────────────────────────────────
    def _prepare(self, features: np.ndarray) -> np.ndarray:
        X = np.asarray(features, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        n = X.shape[1]
        if n < self.expected_features:
            X = np.pad(X, ((0, 0), (0, self.expected_features - n)))
        elif n > self.expected_features:
            X = X[:, :self.expected_features]
        X = (X - self._mean) / self._scale
        X[~np.isfinite(X)] = 0.0
        # The trees compare float32 thresholds
        return X.astype(np.float32)

    def predict_batch(self, features: np.ndarray) -> List[Prediction]:
        """Classify a 2-D array of feature rows in one call."""
        probas = self.model.predict_proba(self._prepare(features))
        best = probas.argmax(axis=1)
        return [(int(i), self.class_names[i], float(probas[row, i]))
                for row, i in enumerate(best)]

    def is_malicious_class(self, class_index: int) -> bool:
        return class_index not in self.benign_indices

    def is_attack(self, features: np.ndarray, threshold: float = 0.5):
        """Single-row compatibility API: (is_malicious, class index, confidence)."""
        if not self.is_ready:
            return False, 0, 0.0
        try:
            index, _, confidence = self.predict_batch(features)[0]
            return (self.is_malicious_class(index) and confidence >= threshold), index, confidence
        except Exception as e:
            log_error("Inference error", e)
            return False, 0, 0.0

    def get_class_name(self, class_id: int) -> str:
        try:
            return self.class_names[int(class_id)]
        except (IndexError, TypeError, ValueError):
            return "UNKNOWN"

    def get_attack_family(self, class_id: int) -> str:
        """Dashboard label for a model class, e.g. 'DoS Hulk' -> 'DoS'."""
        return attack_family(self.get_class_name(class_id))
