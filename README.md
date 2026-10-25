# SwarmDefense // Zero-Trust Sentinel Gateway SOC

A multi-agent swarm security gateway defending against prompt injections, privilege escalation, and credential exfiltration.

Protects a multi-agent pipeline (`TriageAgent` &rarr; `SummarizerAgent` &rarr; `PlannerAgent` &rarr; `ExecutorAgent`) with a Zero-Trust Sentinel Gateway interceptor that inspects events, tracks taint lineage, and enforces security policies.

---

## Key Features
- **Zero-Trust Token Validation**: Every agent action is verified against an identity token (`tok-triage-8812`, `tok-sum-4410`, etc.).
- **Dynamic Taint Tracking**: Provenance labels (e.g. `[UNTRUSTED_EMAIL]`, `[TAINTED_SUMMARY]`) track data flow across agent steps.
- **Dual Defense Layers**:
  - **Ingress Deep Scan**: Quarantines prompt injection attacks at the ingress boundary (Triage).
  - **Taint & Policy Enforcement**: Even with Ingress Scan disabled, taint tracking and behavioral policy checks catch and block exfiltrations at tool execution time.
- **Interactive SOC Cyber Console**:
  - Live pipeline visualizer with real-time status (`EXECUTED`, `BLOCKED`, `QUARANTINED`).
  - Pre-built attack, evasion, benign, and custom playground scenarios.
  - Step-by-step playback animation to watch attacks unfold and get contained.
  - Telemetry KPIs (Risk Score, Quarantined Count, Taint Lineage, Breach Status).
  - Searchable audit log and JSON export.
- **Dual Engine Modes**:
  - Fast, deterministic simulated sandbox mode (runs offline without API keys).
  - Live Google Gemini 2.5 LLM integration (configurable via UI or `.env`).

---

## Quick Start

### 1. Launch with One Command
```bash
./run.sh
```
Or manually:
```bash
cd swarmdefense_project
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

### 2. Access the Application
- **Security Operations Console (UI)**: [http://localhost:8000](http://localhost:8000)
- **Interactive API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Running Tests
```bash
cd swarmdefense_project
.venv/bin/python test_swarmdefense.py
.venv/bin/python test_server_api.py
```

---

## API Endpoints
- `GET /api/health`: Server status, tracked agents, and active policies.
- `GET /api/scenarios`: Returns preset attack and benign scenarios.
- `POST /api/run-scenario`: Executes an attack or benign scenario (supports JSON body or query params).
- `POST /api/set-api-key`: Configures Gemini API key dynamically.
- `POST /api/reset`: Resets swarm gateway and mock tools state.
