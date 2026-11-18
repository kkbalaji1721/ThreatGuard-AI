from datetime import datetime, timezone
from pathlib import Path
import json

def load_sample_threats():
    path = Path(__file__).resolve().parent.parent / "data" / "sample_threats.json"
    return json.loads(path.read_text(encoding="utf-8"))

def normalize_threat(item):
    item.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    item.setdefault("source_type", "curated educational sample")
    return item
