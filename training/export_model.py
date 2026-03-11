"""
Model Export module for NIDS.

Exports trained model and associated artifacts for deployment.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import MODEL_FILE, SCALER_FILE, FEATURES_FILE, MODELS_DIR
from utils.helpers import log_runtime, log_error, save_json

class ModelExporter:
    """Exports trained model and artifacts."""
    
    def __init__(self):
        """Initialize exporter."""
        self.model_path = None
        self.scaler_path = None
        self.features_path = None
        
        # Ensure models directory exists
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        log_runtime("Initialized ModelExporter")
    
    def export_model(self, model, output_path: Path = MODEL_FILE) -> Path:
        """Export trained model."""
        try:
            import joblib
            
            joblib.dump(model.model, output_path)
            self.model_path = output_path
            log_runtime(f"Model exported to {output_path}")
            return output_path
            
        except Exception as e:
            log_error(f"Failed to export model", e)
            raise
    
    def export_scaler(self, scaler, output_path: Path = SCALER_FILE) -> Path:
        """Export feature scaler."""
        try:
            import joblib
            
            joblib.dump(scaler.scaler, output_path)
            self.scaler_path = output_path
            log_runtime(f"Scaler exported to {output_path}")
            return output_path
            
        except Exception as e:
            log_error(f"Failed to export scaler", e)
            raise
    
    def export_features(self, feature_names: list, output_path: Path = FEATURES_FILE) -> Path:
        """Export feature list and configuration."""
        try:
            config = {
                'feature_names': feature_names,
                'feature_count': len(feature_names),
                'features': [{'index': i, 'name': name} for i, name in enumerate(feature_names)]
            }
            
            save_json(config, output_path)
            self.features_path = output_path
            log_runtime(f"Features exported to {output_path} ({len(feature_names)} features)")
            return output_path
            
        except Exception as e:
            log_error(f"Failed to export features", e)
            raise
    
    def export_all(self, model, scaler, feature_names: list) -> dict:
        """Export model, scaler, and features."""
        try:
            log_runtime("Exporting all artifacts...")
            
            model_path = self.export_model(model)
            scaler_path = self.export_scaler(scaler)
            features_path = self.export_features(feature_names)
            
            artifacts = {
                'model': str(model_path),
                'scaler': str(scaler_path),
                'features': str(features_path),
            }
            
            log_runtime("All artifacts exported successfully")
            return artifacts
            
        except Exception as e:
            log_error(f"Failed to export all artifacts", e)
            raise
    
    def verify_exports(self) -> bool:
        """Verify exported files exist."""
        try:
            all_exist = True
            
            if self.model_path and not self.model_path.exists():
                log_runtime(f"Model file not found: {self.model_path}", "ERROR")
                all_exist = False
            
            if self.scaler_path and not self.scaler_path.exists():
                log_runtime(f"Scaler file not found: {self.scaler_path}", "ERROR")
                all_exist = False
            
            if self.features_path and not self.features_path.exists():
                log_runtime(f"Features file not found: {self.features_path}", "ERROR")
                all_exist = False
            
            if all_exist:
                log_runtime("All exported files verified")
            
            return all_exist
            
        except Exception as e:
            log_error("Failed to verify exports", e)
            return False
