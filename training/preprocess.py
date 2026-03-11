"""
Data Preprocessing module for NIDS training.

Handles all data preparation steps before model training.
"""

import pandas as pd
import numpy as np
from typing import Tuple
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error

class DataPreprocessor:
    """Preprocesses data for training."""
    
    def __init__(self):
        """Initialize preprocessor."""
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        log_runtime("Initialized DataPreprocessor")
    
    def split_data(self, X: np.ndarray, y: np.ndarray, 
                  test_size: float = 0.2, random_state: int = 42) -> Tuple:
        """Split data into train and test sets."""
        try:
            from sklearn.model_selection import train_test_split
            
            log_runtime(f"Splitting data with test_size={test_size}...")
            
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            self.X_train = X_train
            self.X_test = X_test
            self.y_train = y_train
            self.y_test = y_test
            
            log_runtime(f"Train set: {X_train.shape[0]} samples")
            log_runtime(f"Test set: {X_test.shape[0]} samples")
            
            return X_train, X_test, y_train, y_test
            
        except Exception as e:
            log_error("Failed to split data", e)
            raise
    
    def get_data(self) -> Tuple:
        """Get preprocessed data."""
        return self.X_train, self.X_test, self.y_train, self.y_test

def preprocess_pipeline(df: pd.DataFrame, label_column: str = 'label_encoded',
                       test_size: float = 0.2) -> Tuple:
    """Complete preprocessing pipeline."""
    try:
        log_runtime("Starting preprocessing pipeline...")
        
        # Separate features and labels
        X = df.drop(columns=[label_column]).values
        y = df[label_column].values
        
        # Split data
        preprocessor = DataPreprocessor()
        X_train, X_test, y_train, y_test = preprocessor.split_data(X, y, test_size=test_size)
        
        log_runtime("Preprocessing completed")
        return X_train, X_test, y_train, y_test
        
    except Exception as e:
        log_error("Failed to preprocess data", e)
        raise
