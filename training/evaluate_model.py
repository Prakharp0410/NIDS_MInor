"""
Model Evaluation module for NIDS.

Evaluates trained model performance using various metrics.
"""

import numpy as np
from typing import Dict, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import log_runtime, log_error

class ModelEvaluator:
    """Evaluates model performance."""
    
    def __init__(self):
        """Initialize evaluator."""
        self.metrics = {}
        log_runtime("Initialized ModelEvaluator")
    
    def evaluate(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
        """Evaluate model using standard metrics."""
        try:
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score, f1_score,
                confusion_matrix, classification_report
            )
            
            log_runtime("Evaluating model...")
            
            self.metrics = {
                'accuracy': float(accuracy_score(y_true, y_pred)),
                'precision': float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
                'recall': float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
                'f1': float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
            }
            
            # Per-class metrics
            report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
            self.metrics['classification_report'] = report
            
            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            self.metrics['confusion_matrix'] = cm.tolist()
            
            # Log results
            log_runtime(f"Accuracy:  {self.metrics['accuracy']:.4f}")
            log_runtime(f"Precision: {self.metrics['precision']:.4f}")
            log_runtime(f"Recall:    {self.metrics['recall']:.4f}")
            log_runtime(f"F1 Score:  {self.metrics['f1']:.4f}")
            
            return self.metrics
            
        except Exception as e:
            log_error("Failed to evaluate model", e)
            raise
    
    def print_report(self, y_true: np.ndarray, y_pred: np.ndarray) -> None:
        """Print detailed classification report."""
        try:
            from sklearn.metrics import classification_report
            
            report = classification_report(y_true, y_pred, zero_division=0)
            log_runtime(f"Classification Report:\n{report}")
            
        except Exception as e:
            log_error("Failed to print report", e)
    
    def plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray,
                             class_names: list = None, save_path: Path = None) -> None:
        """Plot confusion matrix."""
        try:
            import matplotlib.pyplot as plt
            from sklearn.metrics import confusion_matrix
            
            cm = confusion_matrix(y_true, y_pred)
            
            fig, ax = plt.subplots(figsize=(10, 8))
            im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
            
            ax.figure.colorbar(im, ax=ax)
            ax.set(xticks=np.arange(cm.shape[1]), yticks=np.arange(cm.shape[0]))
            
            if class_names:
                ax.set_xticklabels(class_names)
                ax.set_yticklabels(class_names)
            
            plt.xlabel('Predicted Label')
            plt.ylabel('True Label')
            plt.title('Confusion Matrix')
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path)
                log_runtime(f"Confusion matrix saved to {save_path}")
            
            plt.show()
            
        except Exception as e:
            log_error("Failed to plot confusion matrix", e)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get evaluation metrics."""
        return self.metrics

def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
    """Convenience function to evaluate model."""
    evaluator = ModelEvaluator()
    y_pred = model.predict(X_test)
    metrics = evaluator.evaluate(y_test, y_pred)
    return metrics
