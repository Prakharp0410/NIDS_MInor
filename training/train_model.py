"""
Model Training module for NIDS.

Trains Random Forest classifier on CICIDS2017 dataset.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import RANDOM_STATE, RF_N_ESTIMATORS, RF_MAX_DEPTH, RF_MIN_SAMPLES_SPLIT, RF_MIN_SAMPLES_LEAF
from utils.helpers import log_runtime, log_error

class RandomForestModel:
    """Random Forest classifier for intrusion detection."""
    
    def __init__(self, n_estimators: int = RF_N_ESTIMATORS,
                 max_depth: int = RF_MAX_DEPTH,
                 min_samples_split: int = RF_MIN_SAMPLES_SPLIT,
                 min_samples_leaf: int = RF_MIN_SAMPLES_LEAF,
                 random_state: int = RANDOM_STATE):
        """Initialize Random Forest model."""
        from sklearn.ensemble import RandomForestClassifier
        
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=random_state,
            n_jobs=-1,
            verbose=1
        )
        
        self.is_trained = False
        log_runtime(f"Initialized RandomForestClassifier with {n_estimators} estimators")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train the model."""
        try:
            log_runtime(f"Training RandomForestClassifier with {X_train.shape[0]} samples...")
            self.model.fit(X_train, y_train)
            self.is_trained = True
            log_runtime("Model training completed")
        except Exception as e:
            log_error("Failed to train model", e)
            raise
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get prediction probabilities."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.model.predict_proba(X)
    
    def get_feature_importance(self) -> np.ndarray:
        """Get feature importances."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.model.feature_importances_
    
    def save(self, filepath: Path) -> None:
        """Save model to file."""
        try:
            import joblib
            joblib.dump(self.model, filepath)
            log_runtime(f"Model saved to {filepath}")
        except Exception as e:
            log_error(f"Failed to save model", e)
    
    def load(self, filepath: Path) -> None:
        """Load model from file."""
        try:
            import joblib
            self.model = joblib.load(filepath)
            self.is_trained = True
            log_runtime(f"Model loaded from {filepath}")
        except Exception as e:
            log_error(f"Failed to load model", e)

def train_model(X_train: np.ndarray, y_train: np.ndarray,
                X_val: np.ndarray = None, y_val: np.ndarray = None) -> RandomForestModel:
    """Train and return model."""
    
    model = RandomForestModel()
    model.train(X_train, y_train)
    
    if X_val is not None and y_val is not None:
        from sklearn.metrics import accuracy_score
        y_pred = model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        log_runtime(f"Validation Accuracy: {accuracy:.4f}")
    
    return model
