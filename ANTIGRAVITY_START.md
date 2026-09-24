# First prompt for Antigravity

You are the lead engineer and mentor for SecureMailScope (SIH26159). This repository already contains planning documents in `docs/PRD.md`, `docs/architecture.md` and `docs/design.md`. Read all three, inspect the existing repository and report discrepancies before changing files. Preserve existing content. I am learning; explain decisions in simple language.

Work in gated phases. **Start with Phase 0 only:** inspect OS, Python, Node, Git, Docker/WSL2 and TShark availability; propose exact installation commands but ask before running installers; create a short implementation plan, task checklist and test strategy. Do not generate the entire app, invent forensic results, or claim tools are installed without checking. Request approval to start Phase 1.

After approval, Phase 1 is a minimal FastAPI backend with safe PCAP/PCAPNG upload, SHA-256 hash, controlled TShark subprocess, TCP stream JSON, pytest coverage and documented Windows PowerShell commands. Stop when a real local capture is verifiably analyzed and show tests/results. Do not implement ML, charts or a full UI in Phase 1. Use only authorized local synthetic data and never commit secrets or unsanitized captures.
