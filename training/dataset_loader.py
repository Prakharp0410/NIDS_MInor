"""
Dataset Loader for CICIDS2017 Network Intrusion Detection Dataset.

Handles loading, merging, and preprocessing of CICIDS2017 dataset CSV files.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import RAW_DATA_DIR, PROCESSED_DATA_DIR, ATTACK_TYPES, DATASET_FILES, RANDOM_STATE
from utils.helpers import log_runtime, log_error

class CICIDSDatasetLoader:
    """Loader for CICIDS2017 Network Intrusion Detection Dataset."""
    
    def __init__(self, raw_data_dir: Path = RAW_DATA_DIR, 
                 processed_data_dir: Path = PROCESSED_DATA_DIR):
        """Initialize dataset loader."""
        self.raw_data_dir = raw_data_dir
        self.processed_data_dir = processed_data_dir
        self.attack_types = ATTACK_TYPES
        self.df = None
        self.label_column = None
        
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.processed_data_dir.mkdir(parents=True, exist_ok=True)
        
        log_runtime("Initialized CICIDSDatasetLoader")
    
    def load_dataset(self, sample_size: Optional[int] = None) -> pd.DataFrame:
        """Load all dataset files and merge them."""
        try:
            log_runtime("Loading CICIDS2017 dataset...")
            all_dfs = []
            
            for filename in DATASET_FILES:
                filepath = self.raw_data_dir / filename
                
                if not filepath.exists():
                    log_runtime(f"File not found: {filepath}", "WARNING")
                    continue
                
                log_runtime(f"Loading: {filename}")
                df = pd.read_csv(filepath, nrows=sample_size) if sample_size else pd.read_csv(filepath)
                log_runtime(f"  Loaded {len(df)} records")
                all_dfs.append(df)
            
            if not all_dfs:
                raise ValueError("No dataset files loaded")
            
            self.df = pd.concat(all_dfs, ignore_index=True)
            log_runtime(f"Total: {len(self.df)} records, {len(self.df.columns)} features")
            
            return self.df
            
        except Exception as e:
            log_error("Failed to load dataset", e)
            raise
    
    def get_label(self, label_value: str) -> int:
        """Convert label string to class ID."""
        return self.attack_types.get(label_value, 0)
    
    def clean_data(self) -> pd.DataFrame:
        """Clean dataset."""
        if self.df is None:
            raise ValueError("Dataset not loaded")
        
        try:
            log_runtime("Cleaning dataset...")
            
            initial = len(self.df)
            self.df = self.df.drop_duplicates()
            self.df = self.df.dropna(how='all')
            
            self.df.columns = self.df.columns.str.strip()
            
            # Find label column
            label_cols = [col for col in self.df.columns if 'Label' in col or 'label' in col]
            if label_cols:
                self.label_column = label_cols[0]
            else:
                raise ValueError("Label column not found")
            
            log_runtime(f"Removed {initial - len(self.df)} duplicates. Remaining: {len(self.df)}")
            return self.df
            
        except Exception as e:
            log_error("Failed to clean dataset", e)
            raise
    
    def handle_missing_values(self, strategy: str = 'mean') -> pd.DataFrame:
        """Handle missing values."""
        if self.df is None:
            raise ValueError("Dataset not loaded")
        
        try:
            log_runtime(f"Handling missing values with {strategy} strategy...")
            
            numeric_cols = self.df.select_dtypes(include=[np.number]).columns
            
            if strategy == 'mean':
                self.df[numeric_cols] = self.df[numeric_cols].fillna(self.df[numeric_cols].mean())
            elif strategy == 'median':
                self.df[numeric_cols] = self.df[numeric_cols].fillna(self.df[numeric_cols].median())
            elif strategy == 'drop':
                self.df = self.df.dropna(subset=numeric_cols)
            
            log_runtime(f"Handled missing values. Records: {len(self.df)}")
            return self.df
            
        except Exception as e:
            log_error("Failed to handle missing values", e)
            raise
    
    def remove_infinite_values(self) -> pd.DataFrame:
        """Remove infinite values."""
        if self.df is None:
            raise ValueError("Dataset not loaded")
        
        try:
            log_runtime("Removing infinite values...")
            
            numeric_cols = self.df.select_dtypes(include=[np.number]).columns
            
            for col in numeric_cols:
                inf_count = np.isinf(self.df[col]).sum()
                if inf_count > 0:
                    self.df[col] = self.df[col].replace([np.inf, -np.inf], 0)
            
            log_runtime("Infinite values removed")
            return self.df
            
        except Exception as e:
            log_error("Failed to remove infinite values", e)
            raise
    
    def encode_labels(self) -> pd.DataFrame:
        """Encode labels to numeric class IDs."""
        if self.df is None:
            raise ValueError("Dataset not loaded")
        
        try:
            log_runtime("Encoding labels...")
            
            if not self.label_column:
                raise ValueError("Label column not identified")
            
            self.df['label_encoded'] = self.df[self.label_column].apply(self.get_label)
            
            log_runtime(f"Labels encoded. Distribution:")
            for label_id, count in self.df['label_encoded'].value_counts().sort_index().items():
                log_runtime(f"  Class {label_id}: {count} samples")
            
            return self.df
            
        except Exception as e:
            log_error("Failed to encode labels", e)
            raise
    
    def get_feature_columns(self) -> list:
        """Get feature column names."""
        if self.df is None:
            return []
        
        exclude_cols = {'label_encoded', self.label_column, 'index', 'Index'}
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns.tolist()
        return [col for col in numeric_cols if col not in exclude_cols]
    
    def save_processed_dataset(self, filename: str = 'processed_data.csv') -> Path:
        """Save processed dataset."""
        if self.df is None:
            raise ValueError("No dataset to save")
        
        try:
            filepath = self.processed_data_dir / filename
            self.df.to_csv(filepath, index=False)
            log_runtime(f"Dataset saved to {filepath}")
            return filepath
        except Exception as e:
            log_error(f"Failed to save dataset", e)
            raise

def load_cicids_dataset(sample_size: Optional[int] = None) -> Tuple[pd.DataFrame, list]:
    """Convenience function to load and preprocess CICIDS2017 dataset."""
    loader = CICIDSDatasetLoader()
    loader.load_dataset(sample_size=sample_size)
    loader.clean_data()
    loader.handle_missing_values(strategy='mean')
    loader.remove_infinite_values()
    loader.encode_labels()
    
    features = loader.get_feature_columns()
    
    log_runtime(f"Dataset ready: {loader.df.shape[0]} samples, {len(features)} features")
    return loader.df, features
