import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
UPLOADS_DIR = STORAGE_DIR / "uploads"
TEMP_DIR = STORAGE_DIR / "temp"

# Create directories if they do not exist
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB bounded limit for MVP
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

# Database settings
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{STORAGE_DIR / 'securemailscope.db'}")
