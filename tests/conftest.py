import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", "sqlite:///" + str(ROOT / "data" / "test.db"))
os.environ.setdefault("SECRET_KEY", "test-secret")
db = ROOT / "data" / "test.db"
if db.exists():
    db.unlink()
