# NetScope

NetScope is a full-stack HTTP/HTTPS traffic analysis platform for inspecting packet activity, protocol behavior, and capture quality in a quick, browser-friendly workflow. The project combines a Python backend for PCAP and traffic analysis with a Vite + React frontend for dashboards, summaries, and exploration tools.

## Overview

NetScope helps users ingest packet captures and HTTP/HTTPS traffic data, normalize it into a consistent model, surface protocol-level insights, and review captured flows without needing a heavy desktop packet-analysis tool. It is designed for developers, security analysts, and students who want a clear visual summary of conversations, metadata, and traffic patterns.

## Features

- PCAP upload and stream-based traffic analysis
- HTTP/HTTPS flow normalization and protocol summaries
- Per-capture metrics, chart aggregation, and traffic statistics
- Frontend dashboard for exploring packets and summaries
- Sample captures and bundled traffic data for quick evaluation
- Backend service APIs for health checks, analysis, and capture ingestion
- Documentation covering architecture, API patterns, and security notes
- Automated backend tests for reliability, security, and stats contracts

## Tech Stack

- Backend: Python, FastAPI, Pytest
- Frontend: React, TypeScript, Vite
- Packet analysis: tshark-compatible tooling and traffic parsing workflows
- Data model: normalized packet and analysis outputs for structured inspection

## Repository Layout

- backend/: FastAPI app, packet processing services, tests, and data handling
- frontend/: Vite React dashboard for analysis and summary views
- docs/: API, architecture, schema, and security documentation
- sample_captures/: bundled sample traffic files for local demos
- scripts/: helper scripts for running the local stack

## Getting Started

1. Create and activate a Python virtual environment in the backend project.
2. Install the Python dependencies from the backend requirements file.
3. Install the frontend dependencies with npm in the frontend project.
4. Run the backend service and frontend app locally.
5. Upload sample PCAP files or use the bundled captures to explore the dashboard.

## Security Notes

- Keep all environment secrets out of source control.
- Store credentials in local environment variables or a secure secret manager.
- Do not commit real API keys, tokens, or private capture data.

## License

This project is intended for educational and research usage. The current repository is published as a local project snapshot for traffic-analysis work and experimentation.
