"""
Inference module for Raspberry Pi NIDS.

Loads trained model and performs real-time inference.
"""

import numpy as np
from pathlib import Path
from typing import Tuple, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import MODEL_FILE, SCALER_FILE, FEATURES_FILE
from utils.helpers import log_runtime, log_error, load_json

class InferenceEngine:
    """Performs ML inference on network flows."""
    
    def __init__(self, model_path: Path = MODEL_FILE, 
                 scaler_path: Path = SCALER_FILE,
                 features_path: Path = FEATURES_FILE):
        """
        Initialize inference engine.
        
        Args:
            model_path: Path to trained model
            scaler_path: Path to feature scaler
            features_path: Path to features configuration
        """
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.is_ready = False
        
        self.load_model(model_path)
        self.load_scaler(scaler_path)
        self.load_features(features_path)
        
        if self.model and self.scaler:
            self.is_ready = True
            log_runtime("InferenceEngine ready for inference")
    
    def load_model(self, model_path: Path) -> bool:
        """Load trained model."""
        try:
            import joblib
            
            if not model_path.exists():
                log_runtime(f"Model file not found: {model_path}", "ERROR")
                return False
            
            self.model = joblib.load(model_path)
            log_runtime(f"Model loaded from {model_path}")
            return True
            
        except Exception as e:
            log_error(f"Failed to load model", e)
            return False
    
    def load_scaler(self, scaler_path: Path) -> bool:
        """Load feature scaler."""
        try:
            import joblib
            
            if not scaler_path.exists():
                log_runtime(f"Scaler file not found: {scaler_path}", "WARNING")
                return False
            
            self.scaler = joblib.load(scaler_path)
            log_runtime(f"Scaler loaded from {scaler_path}")
            return True
            
        except Exception as e:
            log_error(f"Failed to load scaler", e)
            return False
    
    def load_features(self, features_path: Path) -> bool:
        """Load feature configuration."""
        try:
            if not features_path.exists():
                log_runtime(f"Features file not found: {features_path}", "WARNING")
                return False
            
            config = load_json(features_path)
            self.feature_names = config.get('feature_names', [])
            log_runtime(f"Loaded {len(self.feature_names)} feature names")
            return True
            
        except Exception as e:
            log_error(f"Failed to load features", e)
            return False
    
    def preprocess_features(self, features: np.ndarray) -> np.ndarray:
        """
        Preprocess features using loaded scaler.
        
        Args:
            features: Raw feature vector
            
        Returns:
            Scaled feature vector
        """
        try:
            if self.scaler is None:
                log_runtime("No scaler available, returning raw features", "WARNING")
                return features
            
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            scaled = self.scaler.transform(features)
            return scaled
            
        except Exception as e:
            log_error("Failed to preprocess features", e)
            return features
    
    def predict(self, features: np.ndarray) -> int:
        """
        Predict class label for single sample.
        
        Args:
            features: Feature vector
            
        Returns:
            Predicted class label
        """
        if not self.is_ready:
            raise RuntimeError("Inference engine not ready")
        
        try:
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            scaled = self.preprocess_features(features)
            prediction = self.model.predict(scaled)[0]
            
            return int(prediction)
            
        except Exception as e:
            log_error("Failed to make prediction", e)
            return 0
    
    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities.
        
        Args:
            features: Feature vector
            
        Returns:
            Class probabilities
        """
        if not self.is_ready:
            raise RuntimeError("Inference engine not ready")
        
        try:
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            scaled = self.preprocess_features(features)
            
            if hasattr(self.model, 'predict_proba'):
                probas = self.model.predict_proba(scaled)[0]
            else:
                probas = np.array([1.0, 0.0])  # Default for models without proba
            
            return probas
            
        except Exception as e:
            log_error("Failed to get prediction probabilities", e)
            return np.array([])
    
    def batch_predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predict for multiple samples.
        
        Args:
            features: Feature matrix (n_samples, n_features)
            
        Returns:
            Array of predictions
        """
        if not self.is_ready:
            raise RuntimeError("Inference engine not ready")
        
        try:
            scaled = self.preprocess_features(features)
            predictions = self.model.predict(scaled)
            return predictions
            
        except Exception as e:
            log_error("Failed to batch predict", e)
            return np.array([])
    
    def get_confidence(self, features: np.ndarray, predicted_class: int) -> float:
        """
        Get confidence score for prediction.
        
        Args:
            features: Feature vector
            predicted_class: Predicted class label
            
        Returns:
            Confidence score (0-1)
        """
        try:
            probas = self.predict_proba(features)
            
            if len(probas) > 0 and predicted_class < len(probas):
                return float(probas[predicted_class])
            
            return 0.0
            
        except Exception as e:
            log_error("Failed to get confidence", e)
            return 0.0
    
    def is_attack(self, features: np.ndarray, threshold: float = 0.5) -> Tuple[bool, int, float]:
        """
        Determine if traffic is malicious.
        
        Args:
            features: Feature vector
            threshold: Confidence threshold for attack classification
            
        Returns:
            Tuple of (is_attack, predicted_class, confidence)
        """
        prediction = self.predict(features)
        confidence = self.get_confidence(features, prediction)
        
        is_malicious = (prediction != 0) and (confidence >= threshold)
        
        return is_malicious, prediction, confidence
