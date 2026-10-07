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
from .config import LOG_FORMAT, LOG_LEVEL, LOGS_DIR, CLASS_LABELS, normalize_label

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
    """Convert class ID to label while tolerating string encodings."""
    if class_id is None:
        return "UNKNOWN"

    if isinstance(class_id, str):
        normalized = normalize_label(class_id)
        for key, label in CLASS_LABELS.items():
            if normalize_label(label) == normalized or normalize_label(key) == normalized:
                return label
        return "UNKNOWN"

    return CLASS_LABELS.get(int(class_id), "UNKNOWN")

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


def attack_family(class_name: str) -> str:
    """
    Map a model class name to the project's attack family label, using the
    ATTACK_TYPES / CLASS_LABELS taxonomy (e.g. 'DoS Hulk' -> 'DoS',
    'SSH-Patator' -> 'BruteForce', 'Bot' -> 'Botnet'). Names outside the
    taxonomy, such as 'Heartbleed', are returned unchanged.
    """
    from .config import ATTACK_TYPES
    if not class_name:
        return "UNKNOWN"
    wanted = normalize_label(str(class_name).replace("�", " "))
    for key, family_id in ATTACK_TYPES.items():
        if normalize_label(key) == wanted:
            return CLASS_LABELS.get(family_id, str(class_name))
    return str(class_name)


def configure_logging(level: str = LOG_LEVEL, log_file: Optional[Path] = None) -> None:
    """
    Send every project logger (runtime, alerts, errors) to stdout, which
    systemd stores in the journal, and to a small rotating file. Safe to
    call more than once.
    """
    import sys
    from logging.handlers import RotatingFileHandler

    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    if getattr(root, "_edge_sentinel_configured", False):
        return
    formatter = logging.Formatter(LOG_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            # Bounded size: the SD card must never fill up during a demo
            rotating = RotatingFileHandler(log_file, maxBytes=1_000_000,
                                           backupCount=3, encoding="utf-8")
            rotating.setFormatter(formatter)
            root.addHandler(rotating)
        except OSError as e:
            root.warning(f"File logging disabled: {e}")

    # Keep library chatter (scapy, joblib) out of the journal
    for noisy in ("scapy", "scapy.runtime", "scapy.loading"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
    root._edge_sentinel_configured = True
