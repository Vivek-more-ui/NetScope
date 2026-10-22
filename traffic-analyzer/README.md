# Python-Based HTTP/HTTPS Traffic Analyzer

A specialized educational network traffic analysis application built with **FastAPI (Python 3.12)** and **React 19 + TypeScript + Vite**.

Captures or imports real network packets (PCAP, PCAPNG, Wireshark CSV), extracts protocol metadata, calculates network statistics, and presents the results through an interactive, filterable web application.

---

## 1. Project Purpose & Educational Value

Built for a Computer Networks course demonstration to illustrate:
- **Packet Ingestion**: How link-layer frames (Ethernet) and transport segments (TCP, UDP) are read and dissected.
- **Endpoint Identification**: How IPv4, IPv6, and transport ports identify communicating hosts and conversations.
- **Protocol Classification**: Distinguishing transport layers from application layers (HTTP, TLS, DNS, QUIC, ARP, ICMP).
- **Honesty in Analysis**:
  - Plaintext HTTP exposes request methods (`GET`, `POST`), URI paths, and status codes (`200 OK`).
  - Standard HTTPS encrypts payloads inside TLS records; SNI (Server Name Indication) is visible during handshakes, but application payloads remain opaque without session keys.
  - Port 443 is not automatically HTTPS; UDP 443 commonly carries QUIC/HTTP3.
- **Traffic Aggregation**: Packet size distributions, byte throughput (bits/second), communicating host pairs, and timing histograms.

---

## 2. Architecture & Tech Stack

```
traffic-analyzer/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application, CORS, error handling
│   │   ├── config.py            # Environment configuration, tool detection
│   │   ├── models/packet.py     # Canonical Pydantic contracts & schemas
│   │   ├── routers/
│   │   │   ├── health.py        # GET /api/health
│   │   │   ├── capture.py       # GET /status, GET /interfaces, POST /start, POST /stop
│   │   │   └── analysis.py      # POST /upload, GET /summary, /packets, /protocols, /hosts, /export
│   │   └── services/
│   │       ├── pipeline.py      # Unified capture ingestion layer
│   │       ├── pcap_reader.py   # Pure-Python PCAP and PCAPNG binary parser
│   │       ├── normalize.py     # Dissection & canonical normalization
│   │       ├── stats.py         # Summary aggregates, protocol & host metrics, filters
│   │       ├── tshark.py        # TShark / dumpcap adapter and process manager
│   │       ├── csv_ingest.py    # Wireshark CSV import adapter
│   │       └── store.py         # In-memory and persistent JSONL analysis store
│   └── tests/                   # 322 unit, contract, E2E and security tests
├── frontend/
│   ├── src/
│   │   ├── components/          # CapturePanel, ImportPanel, SummaryView, ChartsSection, PacketExplorer, ExportBar
│   │   ├── api/                 # Strongly-typed API client and query parameter mapping
│   │   └── styles.css           # Clean network analysis interface with light/dark theme
│   └── package.json             # Vite, React, Recharts, Vitest
└── sample_captures/             # Ready-to-use sample captures (demo_traffic.pcap, demo_traffic.csv)
```

---

## 3. Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) TShark / dumpcap for live capturing or advanced dissection

### Step 1: Start Backend API

```bash
cd traffic-analyzer/backend

# Activate the virtual environment
source .venv/bin/activate
# (Or create one: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt)

# Launch the FastAPI server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend API will run on `http://localhost:8000`.
Interactive Swagger API documentation is available at `http://localhost:8000/docs`.

### Step 2: Start Frontend Application

In a new terminal:
```bash
cd traffic-analyzer/frontend

# Install dependencies (if not already installed)
npm install

# Start Vite dev server
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 4. How to Use the Application

1. **Import Capture**:
   - In the **Import Capture** panel on the left sidebar, click "Browse" or drag & drop a file.
   - You can test immediately using `traffic-analyzer/sample_captures/demo_traffic.pcap` or `demo_traffic.csv`.
   - The file is ingested, validated, and normalized in real-time.
2. **Review Summary & Metrics**:
   - Inspect total packet count, wire byte totals, duration, HTTP request/response counts, and encrypted packet counts.
3. **Explore Protocol Breakdown & Visualizations**:
   - View mutually exclusive protocol distributions in charts and percentages.
   - Inspect communicating IP endpoints and top talkers.
   - View traffic volume histograms over the capture timeline.
4. **Packet Explorer**:
   - Filter packets by Protocol, IP address, Port, HTTP Method, Status Code, or full-text query `q`.
   - View frame details: Frame number, timestamp, source/destination IP & ports, transport protocol, application protocol, frame length on wire, inter-packet interval, and flags.
5. **Export Analysis**:
   - Click **Export Packets (CSV)** to download packet records matching the exact schema.
   - Click **Export Summary (JSON)** to download the computed analytical summary.
6. **Live Capture**:
   - Available when TShark or dumpcap has capture permissions on network interfaces (e.g., `lo`, `eth0`, `wlan0`).
   - If capture permissions are restricted by OS policy, use the offline capture import workflow.

---

## 5. Running the Test Suite

### Backend Test Suite (Pytest)
```bash
cd traffic-analyzer/backend
.venv/bin/pytest tests/ -v
```
Validates:
- Normalization contract & schema obedience
- Statistics calculations & byte-accounting formulas
- End-to-end upload, pagination, and filter workflows
- Security protections (no `shell=True`, path traversal defenses, upload bounds)

### Frontend Test Suite (Vitest)
```bash
cd traffic-analyzer/frontend
npm test
```

### Frontend Production Build
```bash
cd traffic-analyzer/frontend
npm run build
```
Creates an optimized production bundle in `dist/`.

---

## 6. Verification Results

Measured on this machine (Linux, Python 3.12.3, Node 18.19.1, TShark 4.2.2):

| Check | Command | Result |
|---|---|---|
| Backend suite | `backend/.venv/bin/pytest` | **321 passed, 1 xfailed** (322 collected) |
| Frontend suite | `frontend/npm test` | **35 passed** (5 files) |
| Type check | `frontend/npm run lint` (`tsc --noEmit`) | **0 errors** |
| Production build | `frontend/npm run build` | **built in 3.5 s** (842 modules) |
| API health | `GET /api/health` | `200`, TShark detected at `~/.local/bin/tshark` |
| Real capture import | upload of a 6 016-packet pcapng | `201`, `packet_count=6016`, `total_bytes=5901040` |
| Live capture | `POST /api/capture/start` on `lo`, then `/stop` | `202` → `200`, 159 packets captured, auto-analysed (`analysis_id` returned) |
| Exports | `export/packets.csv`, `export/summary.json` | 6 016 data rows + header; summary as JSON attachment |
| Error handling | corrupt file / random bytes / `.exe` / empty file / unknown id | `400` / `415` / `415` / `400` / `404`, all with the documented error envelope |

Unit tests need neither root, nor a live network, nor a TShark installation: the
TShark-dependent tests skip themselves when the binary is missing.

---

## 7. Limitations and Honest Caveats

* **Encrypted payloads stay opaque.** TLS/QUIC payloads are reported as `TLS`/`QUIC` with
  `is_encrypted=true`; only metadata that is genuinely on the wire (SNI, TLS version,
  IP, port, sizes) is extracted. No decryption is attempted.
* **HTTP is only reported when it was really seen.** A TCP segment on port 443 is
  labelled `TLS`, never `HTTP`; UDP 443 is labelled `QUIC` when the QUIC layer is
  actually dissected, not because of the port number.
* **`protocol_counts` is the transport layer, `application_protocol_counts` is the
  application layer.** The `/protocols` endpoint returns the application view in `items`
  and the transport view in `transport_items`.
* **No authentication.** The API is meant to run on a local machine; it is not safe to
  expose on a public network. See `docs/SECURITY.md`.
* **Live capture needs capture permission.** `dumpcap`/`tshark` require `CAP_NET_RAW`
  (root or the `setcap` capability). Without it, the API still analyses saved captures
  and reports `503 unavailable` for live capture.
* **Analyses live in the process memory** and are mirrored to `backend/data/analyses/`
  as JSONL. Restarting the server reloads them; deleting the data directory loses them.
* **The built-in reader is a fallback.** TShark is used whenever it is installed because
  it dissects many more protocols; the pure-Python reader covers classic pcap and
  pcapng with Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP. On the same 6 016-packet capture
  both paths agree on the packet count, the byte total, the duration and the HTTP/DNS
  counts; the built-in reader recognises fewer TLS records (352 instead of 677) because
  it can only see a TLS record at the start of a TCP segment. A capture analysed
  without TShark carries the warning *"TShark was not usable for this capture; the
  built-in reader was used instead."*
* **Direction hints are best effort** (`direction_hint`), never ground truth.
* `docs/SECURITY.md` documents the threat model and the controls that are **not**
  implemented.

