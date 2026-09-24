# SecureMailScope (SIH26159)

**Local-First Passive Network Forensic & Cryptographic Analysis Tool for Email Protocols**

SecureMailScope is an AI-assisted passive network forensic application designed to evaluate the cryptographic security posture of captured SMTP, IMAP, and POP3 email communications. It ingests authorized PCAP/PCAPNG network packet captures, reconstructs observable TCP sessions, analyzes TLS/STARTTLS handshakes, generates evidence-backed security findings, and exports investigation reports.

---

## 🚀 Key Features (Phase 1 Foundation)
- **Safe Capture Upload**: Magic-byte validation for `.pcap` (`0xa1b2c3d4`, `0x4d3cb2a1`) and `.pcapng` (`0x0a0d0d0a`) files.
- **Forensic Hash Integrity**: Immutable SHA-256 fingerprinting for every uploaded capture.
- **Controlled TShark Integration**: Secure argument-array invocation of TShark CLI for packet parsing and TCP stream extraction.
- **Async Job & Stream API**: Job tracking endpoints (`QUEUED`, `PROCESSING`, `COMPLETED`, `FAILED`) and structured TCP stream JSON timeline API.
- **Local-First Architecture**: 100% local processing; no network calls or external data leakage.

---

## 🛠 Tech Stack
- **Backend Framework**: Python 3.11, FastAPI, Pydantic v2, Uvicorn
- **Packet Dissection**: TShark CLI (Wireshark 4.6+)
- **Testing**: pytest, HTTPX (Async API client)
- **Database (Development)**: SQLite with SQLAlchemy ORM

---

## 📁 Repository Structure
```text
backend/
├── app/
│   ├── api/          # FastAPI routers & endpoints (health, investigations, captures, jobs, sessions)
│   ├── core/         # Settings, configuration, TShark executable discovery
│   ├── models/       # SQLAlchemy database models
│   ├── schemas/      # Pydantic data validation schemas
│   └── services/     # Business logic (capture storage, hash, TShark adapter, stream parser)
└── tests/            # pytest suite & synthetic PCAP fixtures
docs/                 # PRD, Architecture, and Design documentation
```

---

## 🚦 Getting Started (Phase 1 Local Setup)

### Prerequisites
- Python 3.11+
- TShark (Wireshark 4.x+) installed at `C:\Program Files\Wireshark\tshark.exe` or added to system `PATH`.

### Setup Instructions
1. **Create & Activate Virtual Environment**:
   ```powershell
   python -m venv backend/venv
   .\backend\venv\Scripts\Activate.ps1
   ```

2. **Install Dependencies**:
   ```powershell
   pip install -r backend/requirements.txt
   ```

3. **Run the FastAPI Server**:
   ```powershell
   uvicorn backend.app.main:app --reload --port 8000
   ```

4. **Run Tests**:
   ```powershell
   pytest backend/tests -v
   ```

---

## 📑 Documentation
- [Product Requirements Document (PRD)](docs/PRD.md)
- [Technical Architecture](docs/architecture.md)
- [Design System](docs/design.md)
