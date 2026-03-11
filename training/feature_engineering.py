"""
Feature Engineering module for NIDS.

Handles feature selection, scaling, and transformation.
"""

import pandas as pd
import numpy as np
from typing import List, Tuple, Optional
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import RANDOM_STATE
from utils.helpers import log_runtime, log_error, save_json, load_json

class FeatureEngineering:
    """Handles feature selection and engineering."""
    
    def __init__(self):
        """Initialize feature engineering module."""
        self.selected_features = []
        self.feature_importance = {}
        log_runtime("Initialized FeatureEngineering")
    
    def select_features_by_variance(self, df: pd.DataFrame, threshold: float = 0.01) -> pd.DataFrame:
        """Remove low-variance features."""
        try:
            log_runtime(f"Selecting features by variance (threshold={threshold})...")
            
            initial = len(df.columns)
            variances = df.var()
            selected = variances[variances > threshold].index.tolist()
            self.selected_features = selected
            
            log_runtime(f"Retained {len(selected)}/{initial} features")
            return df[selected]
            
        except Exception as e:
            log_error("Failed to select features by variance", e)
            raise
    
    def select_features_by_importance(self, df: pd.DataFrame, y: pd.Series,
                                     top_n: int = 50) -> Tuple[pd.DataFrame, dict]:
        """Select top features using Random Forest importance."""
        try:
            log_runtime(f"Selecting top {top_n} features by importance...")
            
            from sklearn.ensemble import RandomForestClassifier
            
            model = RandomForestClassifier(n_estimators=50, max_depth=10, 
                                          random_state=RANDOM_STATE, n_jobs=-1)
            model.fit(df, y)
            
            feature_importance = dict(zip(df.columns, model.feature_importances_))
            sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
            
            self.selected_features = [f[0] for f in sorted_features[:top_n]]
            self.feature_importance = dict(sorted_features[:top_n])
            
            log_runtime(f"Selected {len(self.selected_features)} top features")
            for i, (feature, importance) in enumerate(sorted_features[:10], 1):
                log_runtime(f"  {i}. {feature}: {importance:.4f}")
            
            return df[self.selected_features], feature_importance
            
        except Exception as e:
            log_error("Failed to select features by importance", e)
            raise
    
    def select_features_by_correlation(self, df: pd.DataFrame,
                                      correlation_threshold: float = 0.95) -> pd.DataFrame:
        """Remove highly correlated features."""
        try:
            log_runtime(f"Removing highly correlated features (threshold={correlation_threshold})...")
            
            initial = len(df.columns)
            corr_matrix = df.corr().abs()
            upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
            to_drop = [column for column in upper.columns if any(upper[column] > correlation_threshold)]
            
            selected_df = df.drop(columns=to_drop)
            self.selected_features = selected_df.columns.tolist()
            
            log_runtime(f"Removed {len(to_drop)} correlated features. Retained {len(self.selected_features)}/{initial}")
            return selected_df
            
        except Exception as e:
            log_error("Failed to select features by correlation", e)
            raise
    
    def save_feature_config(self, filepath: Path) -> None:
        """Save feature configuration to JSON."""
        try:
            config = {
                'selected_features': self.selected_features,
                'feature_count': len(self.selected_features),
                'feature_importance': self.feature_importance,
            }
            save_json(config, filepath)
            log_runtime(f"Feature config saved to {filepath}")
        except Exception as e:
            log_error(f"Failed to save feature config", e)
    
    def load_feature_config(self, filepath: Path) -> dict:
        """Load feature configuration from JSON."""
        try:
            config = load_json(filepath)
            self.selected_features = config.get('selected_features', [])
            self.feature_importance = config.get('feature_importance', {})
            log_runtime(f"Feature config loaded from {filepath}")
            return config
        except Exception as e:
            log_error(f"Failed to load feature config", e)
            return {}

class FeatureScaler:
    """Handles feature scaling and normalization."""
    
    def __init__(self, scaler_type: str = 'StandardScaler'):
        """Initialize feature scaler."""
        if scaler_type == 'StandardScaler':
            from sklearn.preprocessing import StandardScaler
            self.scaler = StandardScaler()
        elif scaler_type == 'MinMaxScaler':
            from sklearn.preprocessing import MinMaxScaler
            self.scaler = MinMaxScaler()
        else:
            from sklearn.preprocessing import StandardScaler
            self.scaler = StandardScaler()
        
        self.scaler_type = scaler_type
        self.is_fitted = False
        log_runtime(f"Initialized {scaler_type}")
    
    def fit(self, X: np.ndarray) -> 'FeatureScaler':
        """Fit scaler to data."""
        self.scaler.fit(X)
        self.is_fitted = True
        log_runtime(f"Fitted {self.scaler_type}")
        return self
    
    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform data using fitted scaler."""
        if not self.is_fitted:
            raise ValueError("Scaler not fitted")
        return self.scaler.transform(X)
    
    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform data."""
        self.fit(X)
        return self.transform(X)
    
    def save(self, filepath: Path) -> None:
        """Save scaler to file."""
        try:
            import joblib
            joblib.dump(self.scaler, filepath)
            log_runtime(f"Scaler saved to {filepath}")
        except Exception as e:
            log_error(f"Failed to save scaler", e)
    
    def load(self, filepath: Path) -> None:
        """Load scaler from file."""
        try:
            import joblib
            self.scaler = joblib.load(filepath)
            self.is_fitted = True
            log_runtime(f"Scaler loaded from {filepath}")
        except Exception as e:
            log_error(f"Failed to load scaler", e)
