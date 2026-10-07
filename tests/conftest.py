import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# utils.config reads EDGE_DB_PATH at import time. Point it at a throwaway
# file so no test ever touches the tracked alerts.db.
os.environ.setdefault(
    "EDGE_DB_PATH",
    str(Path(tempfile.mkdtemp(prefix="edge-sentinel-tests-")) / "alerts.db"),
)
