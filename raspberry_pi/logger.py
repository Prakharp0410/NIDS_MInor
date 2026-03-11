"""
Logger module for Raspberry Pi NIDS.

Handles all logging for runtime system.
"""

import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import RUNTIME_LOG_FILE, ERROR_LOG_FILE, LOG_FORMAT, LOG_LEVEL

class RuntimeLogger:
    """Manages runtime logging."""
    
    def __init__(self, log_file: Path = RUNTIME_LOG_FILE):
        """Initialize runtime logger."""
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger('runtime')
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(ch)
    
    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(message)
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)

class ErrorLogger:
    """Manages error logging."""
    
    def __init__(self, log_file: Path = ERROR_LOG_FILE):
        """Initialize error logger."""
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger('errors')
        self.logger.setLevel(logging.ERROR)
        
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(fh)
    
    def log_error(self, message: str, exception: Exception = None) -> None:
        """Log error with optional exception."""
        if exception:
            self.logger.error(f"{message} | {str(exception)}", exc_info=True)
        else:
            self.logger.error(message)

# Global logger instances
runtime_logger = RuntimeLogger()
error_logger = ErrorLogger()

def get_runtime_logger() -> RuntimeLogger:
    """Get global runtime logger."""
    return runtime_logger

def get_error_logger() -> ErrorLogger:
    """Get global error logger."""
    return error_logger
