# SecureChat — E2EE-ready TLS Chat (Localhost)

**Author (GitHub):** DEcode-001

## Features
- Multi-threaded TLS server (Python `ssl`), CLI + Tkinter clients
- Authentication with PBKDF2-SHA256 (salted), stored in SQLite
- Anti-replay via per-session monotonic counters
- Basic DoS mitigation via token-bucket rate limiting
- Certificate pinning on client (SHA-256 fingerprint)

> **Note:** Transport security uses TLS with a **self-signed** certificate bundled/generated locally. The client enforces **fingerprint pinning**, which protects against MITM as long as the fingerprint matches the expected value.

## Quick Start (Windows)
1. Create a Python venv and install Tkinter (bundled in standard Python on Windows).
2. Generate a self-signed certificate:
   - **PowerShell**: `./scripts/generate_cert.ps1`
3. Initialize DB and add two users:
   ```bash
   python src/server.py --add-user alice Password1!
   python src/server.py --add-user bob   Password1!
   ```
4. Start the server:
   ```bash
   python src/server.py --host 127.0.0.1 --port 8443
   ```
5. Copy the fingerprint the client should pin:
   ```powershell
   python scripts/print_fingerprint.py
   ```
6. Start CLI clients:
   ```bash
   python src/client_cli.py --username alice --password Password1! --pin <PASTE_FPR>
   python src/client_cli.py --username bob   --password Password1! --pin <PASTE_FPR>
   ```
7. (Optional) Start GUI client:
   ```bash
   python src/client_gui.py
   ```

## Automated Demo + Screenshot Capture
Run (PowerShell):
```powershell
./scripts/run_demo.ps1
```
This will:
- Start server + two CLI clients with scripted messages
- Save all stdout to `artifacts/logs/*.log`
- Render clean **PNG screenshots** from logs to `artifacts/ss_*.png`
- Export a **Gantt chart** and **architecture diagrams** into `artifacts/`

## Tests
```bash
python -m unittest tests/test_security.py -v
```

## Fingerprint Pinning
The client computes `SHA256` over the server certificate in the TLS handshake and matches it to the **expected fingerprint** supplied by you via `--pin`. This is a practical defense against MITM for a self-signed server.
