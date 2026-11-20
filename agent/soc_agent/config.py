import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
BASE = Path(__file__).resolve().parent.parent
DATA, MODELS, REPORTS = BASE / "data", BASE / "models", BASE / "reports"
for _d in (DATA, MODELS, REPORTS):
    _d.mkdir(exist_ok=True)

INDEXER_URL = os.getenv("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "SecretPassword")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
MERGE_GAP_SECONDS = int(os.getenv("MERGE_GAP_SECONDS", "120"))
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.05"))
