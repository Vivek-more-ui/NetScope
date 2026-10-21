# Python-Based HTTP/HTTPS Traffic Analyzer

Backend: Python 3.12 + FastAPI + TShark/Wireshark  •  Frontend: React 19 + TypeScript + Vite

> Status: work in progress. This file is the project entry point; the lead finalises it
> after the acceptance run.

## Quick start

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev          # http://localhost:5173
```

The API is documented at <http://localhost:8000/docs> (OpenAPI/Swagger).

## Documentation

| Document | Contents |
|---|---|
| [docs/SCHEMA.md](docs/SCHEMA.md) | Normalized packet record: fields, types, units, protocol labels, honesty rules. |
| [docs/API.md](docs/API.md) | HTTP endpoints, request/response models, error envelope, pagination and filters. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component map, file ownership, integration rules. |

## Requirements

* Python 3.11+ with the packages in `backend/requirements.txt`
* Node.js 18+ and npm for the frontend
* TShark (Wireshark) for protocol dissection and live capture — optional for offline
  analysis, which falls back to a built-in pure-python pcap reader
* `scripts/install-tshark-user.sh` installs TShark into `~/.local/bin` without root
