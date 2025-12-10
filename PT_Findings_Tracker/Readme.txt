PT Findings Tracker API
=======================

Overview
--------
`API.py` exposes a lightweight Flask web server plus SQLAlchemy models that let the `PT_DB_MCP` (and any AI-assisted pentesting workflow) register hosts, recon data, commands, and findings in a single SQLite/PostgreSQL-compatible database. The service focuses on structured CRUD endpoints, optimistic idempotency (via `external_id`/`dedupe_key`), and simple HTML dashboards so humans can review what the AI captured.

Tech Stack
----------
- Flask + Werkzeug for routing, templates, file delivery, and middleware hooks.
- SQLAlchemy ORM + Flask-Migrate for models such as `Command`, `Finding`, `Service`, `Vulnerability`, `ExploitAttempt`, and `Evidence`.
- Marshmallow schemas for strict payload validation on every POST.
- SQLite by default (`LLM-allattack-test1_fresh.db` in the app directory) with optional `DATABASE_URL` for other backends.
- Minimal logging middleware that injects `X-Request-Id` and `X-Response-Time` headers to trace AI-driven traffic.

Data Domains
------------
- **Commands** – Shell or tool invocations run during a pentest phase, with stdout, exit codes, and analyst summaries.
- **Findings** – Host-level issues, linked back to the commands/evidence that produced them and tracked by severity/status.
- **Recon** – Per-host services, vulnerabilities, exploit attempts, and free-form service notes to capture scan results.
- **Knowledge artifacts** – Notes and uploaded evidence (screenshots, PCAPs, etc.) tied to hosts and optionally linked entities.

Key API Endpoints
-----------------
- `GET /api/hosts` – Aggregate the unique hosts observed anywhere in the database for quick navigation.
- `POST /api/commands` / `GET /api/commands/<id>` – Upsert-safe command logging with host, phase, and tool metadata.
- `POST /api/findings` / `GET /api/findings` – Create and list findings with severity/status filtering, dedupe, and pagination.
- `POST /api/notes` – Store analyst or AI context tied to a host, command, or finding.
- `POST /api/evidence` & `GET /api/evidence/<id>/download` – Accept multipart uploads and serve the stored files from `uploads/`.
- `POST /api/services/bulk_upsert` / `POST /api/vulns/bulk_upsert` – Efficiently import scanner output with conflict-aware updates.
- `POST /api/services/notes` – Attach textual observations to a specific service/port.
- `POST /api/exploits` – Track exploit attempts plus their success flag.
- `GET /api/search/commands` – Text search across commands/summaries for quick recall.
- `GET /health` – Lightweight readiness probe used by orchestration or monitoring.

Web Dashboard
-------------
Templates under `templates/` (`hosts.html`, `commands.html`, `findings.html`, `services.html`, `vulns.html`) render read-only summaries so operators can audit what the MCP or AI agent created. Pagination, host filters, and severity/status pickers make it easy to triage large engagements.

AI + PT_DB_MCP Workflow
-----------------------
1. `PT_DB_MCP` authenticates within its own context (no JWTs in this PoC) and sends structured POSTs to `/api/commands`, `/api/services/bulk_upsert`, and `/api/vulns/bulk_upsert` right after reconnaissance or exploitation steps.
2. When the agent concludes that a finding is valid, it calls `/api/findings` with the associated commands/evidence references so humans can trace provenance.
3. Uploaded evidence IDs are referenced inside `commands`, `findings`, or vulnerability records, ensuring reports can hyperlink back to raw proof.
4. Analysts refresh the HTML dashboard to review, annotate, or export the accumulated data.

Developer Utilities
-------------------
- `GET /__dev/schema_info` (requires `DEV_ENABLE_SCHEMA_INFO=1`) introspects live tables/columns—handy while iterating on the MCP client.
- `POST /__dev/reset_db` (requires `DEV_ENABLE_RESET=1`) drops and recreates every table; useful for clean-room demos.
- Setting `RESET_DB=1` when launching the module forces a fresh schema before `app.run()` starts (dev only).

Running Locally
---------------
```bash
cd PT_Findings_Tracker
export FLASK_APP=API.py
export DATABASE_URL="sqlite:///$(pwd)/LLM-allattack-test1_fresh.db"
python3 API.py  # listens on 0.0.0.0:5555 by default
```
Uploads are written to `PT_Findings_Tracker/uploads/`; ensure the directory is writable before sending evidence.
