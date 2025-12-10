#!/usr/bin/env python3
"""
FastMCP server that exposes tools for your Pentest Flask API.

Env vars:
  PENTEST_API_BASE   e.g., http://localhost:5000
  PENTEST_API_TOKEN  e.g., a JWT from /api/auth/login
"""

import os
import json
import base64
import mimetypes
from typing import List, Optional, Dict, Any

import httpx
from dotenv import load_dotenv

# FastMCP (Model Context Protocol) — minimalist server with declarative tools
from mcp.server.fastmcp import FastMCP

load_dotenv()

API_BASE = os.getenv("PENTEST_API_BASE", "http://localhost:5555")
API_TOKEN = os.getenv("PENTEST_API_TOKEN")  # Bearer <JWT>

# ---------- HTTP helpers ----------

def _auth_headers():
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

async def _get(client: httpx.AsyncClient, path: str, params: Dict[str, Any] = None):
    r = await client.get(f"{API_BASE}{path}", headers=_auth_headers(), params=params)
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        try:
            body = e.response.json()
        except Exception:
            body = {"message": e.response.text}
        return {"error": body.get("error", body), "status": e.response.status_code}
    try:
        return r.json()
    except ValueError:
        return {"status": r.status_code, "body": r.text}

async def _post_json(client: httpx.AsyncClient, path: str, payload: Dict[str, Any]):
    r = await client.post(f"{API_BASE}{path}", headers=_auth_headers(), json=payload)
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        try:
            body = e.response.json()
        except Exception:
            body = {"message": e.response.text}
        return {"error": body.get("error", body), "status": e.response.status_code}
    try:
        return r.json()
    except ValueError:
        return {"status": r.status_code, "body": r.text}

async def _post_multipart(client: httpx.AsyncClient, path: str, files: Dict[str, Any], data: Dict[str, Any]):
    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    r = await client.post(f"{API_BASE}{path}", headers=headers, files=files, data=data)
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        try:
            body = e.response.json()
        except Exception:
            body = {"message": e.response.text}
        return {"error": body.get("error", body), "status": e.response.status_code}
    try:
        return r.json()
    except ValueError:
        return {"status": r.status_code, "body": r.text}

# ---------- FastMCP server ----------

mcp = FastMCP("pentest-api-mcp", instructions="MCP tools for Pentest Flask API")

# ========== Auth / Setup ==========

@mcp.tool()
async def set_api_base(base_url: str) -> str:
    """
    Set the base URL for the Pentest API, e.g., http://localhost:5555
    """
    global API_BASE
    API_BASE = base_url.rstrip("/")
    return f"API_BASE set to {API_BASE}"

@mcp.tool()
async def set_api_token(jwt_token: str) -> str:
    """
    Set the Bearer JWT token for authenticated endpoints.
    """
    global API_TOKEN
    API_TOKEN = jwt_token.strip()
    return "API_TOKEN set."

# ========== Hosts ==========

@mcp.tool()
async def list_hosts() -> dict:
    """
    List distinct hosts observed in the API (from services/commands/findings).
    """
    async with httpx.AsyncClient(timeout=30) as client:
        return await _get(client, "/api/hosts")

# ========== Commands ==========

@mcp.tool()
async def Record_command(
    host: str,
    phase: str,
    command: str,
    user_id: Optional[int] = None,
    session_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    exit_code: Optional[int] = None,
    output: Optional[str] = None,
    summary: Optional[str] = None,
    external_id: Optional[str] = None
) -> dict:
    """
    Record an executed command for a host (+ optional output/summary). Idempotent via external_id.
    """
    payload = {
        "host": host,
        "user_id": user_id,
        "session_id": session_id,
        "phase": phase,
        "command": command,
        "tool": tool_name,
        "exit_code": exit_code,
        "output": output,
        "summary": summary,
        "external_id": external_id
    }
    async with httpx.AsyncClient(timeout=60) as client:
        return await _post_json(client, "/api/commands", payload)

@mcp.tool()
async def get_command(command_id: int) -> dict:
    """
    Fetch a command by id.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        return await _get(client, f"/api/commands/{command_id}")

@mcp.tool()
async def search_commands(host: Optional[str] = None, q: Optional[str] = None) -> dict:
    """
    Search recent commands by keyword and/or host.
    """
    params = {}
    if host:
        params["host"] = host
    if q:
        params["q"] = q
    async with httpx.AsyncClient(timeout=30) as client:
        return await _get(client, "/api/search/commands", params=params)

# ========== Recon: Services / Vulns / Exploits / Notes ==========

@mcp.tool()
async def services_bulk_upsert(items: List[dict]) -> dict:
    """
    Bulk upsert services discovered during recon (Nmap-style).
    Each item supports:
            host, port, protocol (tcp|udp),
            state, name, product, version, cpe, scripts (dict), banner, last_seen, external_id
    """
    async with httpx.AsyncClient(timeout=120) as client:
        return await _post_json(client, "/api/services/bulk_upsert", {"items": items})

@mcp.tool()
async def vulns_bulk_upsert(items: List[dict]) -> dict:
    """
    Bulk upsert vulnerabilities linked to services.
    Each item supports:
            host, port?, protocol?, title, cve?, severity, cvss?, description?,
            evidence (dict)?, source?, status?, dedupe_key?, external_id?
    """
    async with httpx.AsyncClient(timeout=120) as client:
        return await _post_json(client, "/api/vulns/bulk_upsert", {"items": items})

@mcp.tool()
async def create_exploit_attempt(
    host: str,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    vulnerability_id: Optional[int] = None,
    tool: Optional[str] = None,
    module: Optional[str] = None,
    command: Optional[str] = None,
    result_summary: Optional[str] = None,
    succeeded: Optional[bool] = None,
    external_id: Optional[str] = None
) -> dict:
    """
    Record an exploit attempt and outcome.
    """
    payload = {
        "host": host,
        "port": port,
        "protocol": protocol,
        "vulnerability_id": vulnerability_id,
        "tool": tool,
        "module": module,
        "command": command,
        "result_summary": result_summary,
        "succeeded": succeeded,
        "external_id": external_id
    }
    async with httpx.AsyncClient(timeout=60) as client:
        return await _post_json(client, "/api/exploits", payload)

@mcp.tool()
async def add_service_note(host: str, port: int, protocol: str, note: str, author_id: Optional[int] = None) -> dict:
    """
    Add a note to a specific service identified by host:port/protocol.
    """
    payload = {"host": host, "port": port, "protocol": protocol, "note": note, "author_id": author_id}
    async with httpx.AsyncClient(timeout=30) as client:
        return await _post_json(client, "/api/services/notes", payload)

@mcp.tool()
async def search_services(
    host: Optional[str] = None,
    name: Optional[str] = None,
    port: Optional[int] = None
) -> dict:
    """
    Find services by host/name/port.
    """
    params = {}
    if host:
        params["host"] = host
    if name:
        params["name"] = name
    if port is not None:
        params["port"] = port
    async with httpx.AsyncClient(timeout=30) as client:
        return await _get(client, "/api/services/search", params=params)

# ========== Findings ==========

@mcp.tool()
async def create_finding(
    host: str,
    title: str,
    description: Optional[str] = None,
    severity: Optional[str] = "medium",
    status: Optional[str] = "open",
    commands: Optional[List[dict]] = None,
    evidence: Optional[List[dict]] = None,
    dedupe_key: Optional[str] = None,
    external_id: Optional[str] = None,
    created_by: Optional[int] = None
) -> dict:
    """
    Create (or idempotently upsert) a high-level finding for a host.
    """
    payload = {
        "host": host,
        "created_by": created_by,
        "title": title,
        "description": description,
        "severity": severity,
        "status": status,
        "commands": commands,
        "evidence": evidence,
        "dedupe_key": dedupe_key,
        "external_id": external_id
    }
    async with httpx.AsyncClient(timeout=60) as client:
        return await _post_json(client, "/api/findings", payload)

@mcp.tool()
async def list_findings(host: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None, page: int = 1, per: int = 50) -> dict:
    """
    List findings with filters (host/severity/status).
    """
    params = {"page": page, "per": per}
    if host:
        params["host"] = host
    if severity:
        params["severity"] = severity
    if status:
        params["status"] = status
    async with httpx.AsyncClient(timeout=30) as client:
        return await _get(client, "/api/findings", params=params)

# ========== Evidence upload ==========

@mcp.tool()
async def upload_evidence_file(
    host: str,
    file_path: str,
    uploader_id: Optional[int] = None,
    linked_type: Optional[str] = None,
    linked_id: Optional[int] = None
) -> dict:
    """
    Upload an evidence file from local disk to the API.
    """
    if not os.path.exists(file_path):
        return {"error": f"file not found: {file_path}"}
    # Prepare multipart
    mime, _ = mimetypes.guess_type(file_path)
    mime = mime or "application/octet-stream"
    file_name = os.path.basename(file_path)
    async with httpx.AsyncClient(timeout=120) as client:
        with open(file_path, "rb") as fh:
            files = {"file": (file_name, fh, mime)}
            data = {
                "host": host,
                "uploader_id": str(uploader_id) if uploader_id is not None else "",
                "linked_type": linked_type or "",
                "linked_id": str(linked_id) if linked_id is not None else ""
            }
            return await _post_multipart(client, "/api/evidence", files, data)

# ========== Health check ==========

@mcp.tool()
async def api_health() -> dict:
    """
    Hit /health on the API.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        return await _get(client, "/health")

# ---------- Run MCP server ----------
if __name__ == "__main__":
    # Run the MCP server; it communicates over stdio by default.
    mcp.run()
