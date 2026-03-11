"""
Helper utilities for NIDS project.

Provides logging, data handling, and utility functions.
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import numpy as np
from .config import LOG_FORMAT, LOG_LEVEL, LOGS_DIR, CLASS_LABELS

def setup_logger(name: str, log_file: Path, level: str = LOG_LEVEL) -> logging.Logger:
    """Setup and configure a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))
    formatter = logging.Formatter(LOG_FORMAT)
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(getattr(logging, level))
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, level))
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger

def log_alert(timestamp: str, src_ip: str, dst_ip: str, src_port: int, 
              dst_port: int, attack_type: str, confidence: float) -> None:
    """Log a security alert."""
    logger = logging.getLogger("alerts")
    msg = f"ALERT | {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {attack_type} | {confidence:.4f}"
    logger.warning(msg)

def log_runtime(message: str, level: str = "INFO") -> None:
    """Log runtime information."""
    logger = logging.getLogger("runtime")
    getattr(logger, level.lower())(message)

def log_error(message: str, exception: Optional[Exception] = None) -> None:
    """Log error messages."""
    logger = logging.getLogger("errors")
    if exception:
        logger.error(f"{message} | {str(exception)}", exc_info=True)
    else:
        logger.error(message)

def get_class_label(class_id: int) -> str:
    """Convert class ID to label."""
    return CLASS_LABELS.get(class_id, "UNKNOWN")

def save_json(data: Dict[str, Any], filepath: Path) -> None:
    """Save dictionary to JSON file."""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        log_error(f"Failed to save JSON to {filepath}", e)

def load_json(filepath: Path) -> Dict[str, Any]:
    """Load JSON file into dictionary."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        log_error(f"Failed to load JSON from {filepath}", e)
        return {}

def sanitize_data(data: np.ndarray) -> np.ndarray:
    """Sanitize data by handling NaN and infinite values."""
    data[np.isnan(data)] = 0
    data[np.isinf(data)] = 0
    return data

def format_timestamp() -> str:
    """Get current timestamp in standard format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
