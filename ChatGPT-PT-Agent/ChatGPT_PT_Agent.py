import os
import os
import pty
import fcntl
import select
import signal
import time
import json
import re
import subprocess
import subprocess
from openai import OpenAI, RateLimitError
import json
import os, pty, select, fcntl, termios
import os
import json
import base64
import mimetypes
from typing import List, Optional, Dict, Any
import requests
client = OpenAI(api_key="")

API_BASE = os.getenv("PENTEST_API_BASE", "http://192.168.70.222:5555")
API_TOKEN = os.getenv("PENTEST_API_TOKEN")  # optional: Bearer token for the API


_sessions = {}  # session_id -> {"pid": pid, "fd": master_fd}

def start_session(shell: str="/bin/bash"):
    master_fd, slave_fd = pty.openpty()
    pid = os.fork()
    if pid == 0:
        # child: attach to PTY and exec shell
        os.setsid()
        os.dup2(slave_fd, 0); os.dup2(slave_fd, 1); os.dup2(slave_fd, 2)
        os.close(master_fd); os.close(slave_fd)
        os.execv(shell, [shell, "-i"])
    else:
        os.close(slave_fd)
        sid = str(master_fd)  # simple id; you can generate UUID
        _sessions[sid] = {"pid": pid, "fd": master_fd}
        # set nonblocking
        fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return {"session_id": sid}

def send_input(session_id: str, data: str, read_ms: int = 200):
    print(f"chatgpt is sending command : {data}")
    sess = _sessions.get(session_id)
    if not sess: return {"error": "invalid session id"}
    os.write(sess["fd"], data.encode())
    # attempt to read response briefly
    out = []
    r, _, _ = select.select([sess["fd"]], [], [], read_ms/1000.0)
    if r:
        try:
            out.append(os.read(sess["fd"], 65536).decode(errors="ignore"))
        except BlockingIOError:
            pass
    return {"stdout": "".join(out)}

def close_session(session_id: str):
    sess = _sessions.pop(session_id, None)
    if not sess: return {"status": "unknown"}
    try:
        os.close(sess["fd"])
    except OSError:
        pass
    return {"status": "closed"}

def run_command(command: str):
    try:
        print(f"ChatGPT is running command : {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return {
            "command": command,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "command": command,
            "error": str(e)
        }


def call_function(name, args):
    # if name == "run_command":
    if name == "start_session":
        return start_session(shell=args.get("shell") or "/bin/bash")
    if name == "send_input":
        return send_input(
            session_id=args["session_id"],
            data=args["data"],
            read_ms=args.get("read_ms", 250)
        )
    if name == "close_session":
        return close_session(session_id=args["session_id"])
    if name == "finish":
        return finish(**args)
    if name == "create_command":
        return api_create_command(**args)
    if name == "get_command":
        return api_get_command(int(args["command_id"]))
    if name == "create_finding":
        return api_create_finding(**args)
    if name == "list_findings":
        return api_list_findings(**args)
    if name == "create_note":
        return api_create_note(**args)
    if name == "upload_evidence_file":
        # args: file_path, host, uploader_id (optional), linked_type (optional), linked_id (optional)
        return api_upload_evidence(**args)
    if name == "bulk_upsert_services":
        return api_bulk_upsert_services(args.get("items", []))
    if name == "add_service_note":
        return api_add_service_note(**args)
    if name == "search_services":
        return api_search_services(**args)
    if name == "bulk_upsert_vulns":
        return api_bulk_upsert_vulns(args.get("items", []))
    if name == "create_exploit_attempt":
        return api_create_exploit_attempt(args)
    if name == "search_commands":
        return api_search_commands(**args)
    if name == "list_hosts":
        return api_list_hosts()
    if name == "health":
        return api_health()

def finish(message):
    print(f"\n✅ OpenAI finished execution. Task complete. with message {message}")
    exit()
    return {"status": "execution_finished"}

def call_with_retry(**kwargs):
    # Simple exponential backoff; also tries to parse "try again in X.s" from error message
    base = 2.0
    tries = 0
    while True:
        try:
            return client.responses.create(**kwargs)
        except RateLimitError as e:
            msg = str(e)
            m = re.search(r"try again in ([0-9.]+)s", msg)
            wait = float(m.group(1)) if m else min(30.0, base ** tries)
            print(f"[rate-limit] waiting {wait:.2f}s ...")
            time.sleep(wait)
            tries += 1

def _auth_headers():
    hdr = {"Accept": "application/json"}
    if API_TOKEN:
        hdr["Authorization"] = f"Bearer {API_TOKEN}"
    return hdr

def api_post(path: str, json_body: Optional[Dict] = None, files: Optional[Dict] = None, params: Optional[Dict] = None, timeout: int = 20) -> Dict[str, Any]:
    print(f"API POST {path} with params {params} and json body {json_body} and files {files}")
    url = f"{API_BASE.rstrip('/')}/{path.lstrip('/')}"
    try:
        if files:
            # files is a dict like {'file': ('filename', fileobj, 'application/octet-stream')}
            r = requests.post(url, headers=_auth_headers(), params=params or {}, files=files, data=(json_body or {}), timeout=timeout)
        else:
            r = requests.post(url, headers={**_auth_headers(), "Content-Type": "application/json"}, json=json_body or {}, params=params or {}, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw_text": r.text}
        return {"status_code": r.status_code, "ok": r.ok, "body": body}
    except Exception as e:
        return {"status_code": None, "ok": False, "error": str(e)}

def api_get(path: str, params: Optional[Dict] = None, timeout: int = 20) -> Dict[str, Any]:
    print(f"API GET {path} with params {params}")
    url = f"{API_BASE.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, headers=_auth_headers(), params=params or {}, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw_text": r.text}
        return {"status_code": r.status_code, "ok": r.ok, "body": body}
    except Exception as e:
        return {"status_code": None, "ok": False, "error": str(e)}

# --- API call wrappers ---

def api_create_command(host: str, phase: str, command: str, user_id: Optional[int] = None, session_id: Optional[str] = None, tool: Optional[str] = None, exit_code: Optional[int] = None, output: Optional[str] = None, summary: Optional[str] = None, external_id: Optional[str] = None):
    print(f"Creating command record in pentest-db for host {host} with command: {command}")
    payload = {
        "host": host, "phase": phase, "command": command,
        "user_id": user_id, "session_id": session_id, "tool": tool,
        "exit_code": exit_code, "output": output, "summary": summary, "external_id": external_id
    }
    print(f"Creating command record in pentest-db for host {host} with command: {command}")
    return api_post("/api/commands", json_body=payload)

def api_get_command(command_id: int):
    print(f"Fetching command id {command_id} from pentest-db")
    return api_get(f"/api/commands/{int(command_id)}")

def api_create_finding(host: str, title: str, created_by: Optional[int] = None, description: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None, commands: Optional[List[Dict]] = None, evidence: Optional[List[Dict]] = None, dedupe_key: Optional[str] = None, external_id: Optional[str] = None):
    print(f"Creating finding in pentest-db for host {host} with title: {title}")
    payload = {
        "host": host, "title": title,
        "created_by": created_by, "description": description, "severity": severity,
        "status": status, "commands": commands, "evidence": evidence,
        "dedupe_key": dedupe_key, "external_id": external_id
    }
    return api_post("/api/findings", json_body=payload)

def api_list_findings(host: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None, page: int = 1, per: int = 50):
    print(f"Listing findings in pentest-db for host {host} with severity {severity} and status {status}")
    params = {"host": host, "severity": severity, "status": status, "page": page, "per": per}
    return api_get("/api/findings", params={k: v for k, v in params.items() if v is not None})

def api_create_note(host: str, content: str, author_id: Optional[int] = None, context_type: Optional[str] = None, context_id: Optional[int] = None):
    print(f"Creating note in pentest-db for host {host} with content: {content}")
    payload = {"host": host, "content": content, "author_id": author_id, "context_type": context_type, "context_id": context_id}
    return api_post("/api/notes", json_body=payload)

def api_upload_evidence(file_path: str, host: str, uploader_id: Optional[int] = None, linked_type: Optional[str] = None, linked_id: Optional[int] = None):
    print(f"Uploading evidence file {file_path} for host {host} to pentest-db")
    # file_path -> path to file on local filesystem of the agent
    try:
        f = open(file_path, "rb")
    except Exception as e:
        return {"ok": False, "error": f"open file failed: {e}"}
    files = {"file": (os.path.basename(file_path), f)}
    data = {}
    if uploader_id is not None:
        data["uploader_id"] = str(uploader_id)
    if linked_type is not None:
        data["linked_type"] = linked_type
    if linked_id is not None:
        data["linked_id"] = str(linked_id)
    data["host"] = host
    try:
        url = f"{API_BASE.rstrip('/')}/api/evidence"
        r = requests.post(url, headers=_auth_headers(), files=files, data=data, timeout=60)
        try:
            body = r.json()
        except Exception:
            body = {"raw_text": r.text}
        f.close()
        return {"status_code": r.status_code, "ok": r.ok, "body": body}
    except Exception as e:
        f.close()
        return {"status_code": None, "ok": False, "error": str(e)}

def api_bulk_upsert_services(items: List[Dict]):
    return api_post("/api/services/bulk_upsert", json_body={"items": items})

def api_add_service_note(host: str, port: int, protocol: str, note: str, author_id: Optional[int] = None):
    print(f"Adding service note in pentest-db for {host}:{port}/{protocol} with note: {note}")
    payload = {"host": host, "port": port, "protocol": protocol, "note": note, "author_id": author_id}
    return api_post("/api/services/notes", json_body=payload)

def api_search_services(host: Optional[str] = None, name: Optional[str] = None, port: Optional[int] = None):
    print()
    params = {k: v for k, v in {"host": host, "name": name, "port": port}.items() if v is not None}
    return api_get("/api/services/search", params=params)

def api_bulk_upsert_vulns(items: List[Dict]):
    return api_post("/api/vulns/bulk_upsert", json_body={"items": items})

def api_create_exploit_attempt(payload: Dict):
    print("Creating exploit attempt record in pentest-db")
    return api_post("/api/exploits", json_body=payload)

def api_search_commands(qtxt: Optional[str] = None, host: Optional[str] = None):
    print(f"Searching commands in pentest-db with qtxt: {qtxt} and host: {host}")
    params = {k: v for k, v in {"q": qtxt, "host": host}.items() if v is not None}
    return api_get("/api/search/commands", params=params)

def api_list_hosts():
    print("Listing hosts in pentest-db")
    return api_get("/api/hosts")

def api_health():
    print("Checking health of pentest-db")
    return api_get("/health")


tools = [

    {
        "type": "function",
        "name": "finish",
        "description": "Call this when your task is complete and no further action is needed.",
        "parameters": {
            "type": "object",
            "properties": {"message": {"type": "string", "description": "message to show task results"}},
            "required": ["message"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "start_session",
        "description": "Start an interactive shell session backed by a PTY",
        "parameters": {
            "type": "object",
            "properties": {
                "shell": {"type": "string", "description": "Path to the shell, e.g. /bin/bash"}
            },
            "required": ["shell"],  # ← must include every key in properties
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "send_input",
        "description": "Send keystrokes to an interactive session and read a short response",
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "data": {"type": "string", "description": "Keystrokes to send, include \\n to press Enter"},
                "read_ms": {"type": "integer", "description": "How long to wait for output (ms)"}
            },
            "required": ["session_id", "data", "read_ms"],  # ← all keys listed
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "close_session",
        "description": "Close an interactive PTY session",
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"],  # ← all keys listed
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "create_command",
        "description": "Create a command record for a host (host, phase, command are required).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "phase": {"type": "string"},
                "command": {"type": "string"},
                "user_id": {"type": "integer"},
                "session_id": {"type": "string"},
                "tool": {"type": "string"},
                "exit_code": {"type": "integer"},
                "output": {"type": "string"},
                "summary": {"type": "string"},
                "external_id": {"type": "string"}
            },
            "required": ["host", "phase", "command", "user_id", "session_id", "tool", "exit_code", "output", "summary", "external_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "get_command",
        "description": "Fetch command by ID",
        "parameters": {
            "type": "object",
            "properties": {"command_id": {"type": "integer"}},
            "required": ["command_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "create_finding",
        "description": "Create a finding (host + title required).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "title": {"type": "string"},
                "created_by": {"type": "integer"},
                "description": {"type": "string"},
                "severity": {"type": "string"},
                "status": {"type": "string"},
                "dedupe_key": {"type": "string"},
                "external_id": {"type": "string"}
            },
            "required": ["host", "title", "created_by", "description", "severity", "status", "dedupe_key", "external_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "list_findings",
        "description": "List findings with optional filters (host, severity, status, page, per).",
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "severity": {"type": "string"}, "status": {"type": "string"}, "page": {"type": "integer"}, "per": {"type": "integer"}},
            "required": ["host", "severity", "status", "page", "per"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "create_note",
        "description": "Create a note for a host. (host and content are required).",
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "content": {"type": "string"}, "author_id": {"type": "integer"}, "context_type": {"type": "string"}, "context_id": {"type": "integer"}},
            "required": ["host", "content", "author_id", "context_type", "context_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "upload_evidence_file",
        "description": "Upload an evidence file from the agent host to the server. Provide local file_path and host (and optional uploader_id/linked_type/linked_id).",
        "parameters": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}, "host": {"type": "string"}, "uploader_id": {"type": "integer"}, "linked_type": {"type": "string"}, "linked_id": {"type": "integer"}},
            "required": ["file_path", "host", "uploader_id", "linked_type", "linked_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "add_service_note",
        "description": "Add a note to a service (host, port, protocol, note required) in Pentest-DB.",
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "protocol": {"type": "string"}, "note": {"type": "string"}, "author_id": {"type": "integer"}},
            "required": ["host", "port", "protocol", "note", "author_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "search_services",
        "description": "Search services (optional host/name/port) in Pentest-DB.",
        "parameters": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "name": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host", "name", "port"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "create_exploit_attempt",
        "description": "Create an exploit attempt record; pass full exploit attempt JSON payload in Pentest-DB. ",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"}, "port": {"type": "integer"}, "protocol": {"type": "string"},
                "vulnerability_id": {"type": "integer"}, "tool": {"type": "string"}, "module": {"type": "string"},
                "command": {"type": "string"}, "result_summary": {"type": "string"}, "succeeded": {"type": "boolean"}, "external_id": {"type": "string"}
            },
            "required": ["host", "port", "protocol", "vulnerability_id", "tool", "module", "command", "result_summary", "succeeded", "external_id"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "search_commands",
        "description": "Search commands by text query 'q' or host in Pentest-DB.",
        "parameters": {
            "type": "object",
            "properties": {"qtxt": {"type": "string"}, "host": {"type": "string"}},
            "required": ["qtxt", "host"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "list_hosts",
        "description": "Return list of hosts observed in Pentest-DB.",
        "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        "strict": True
    },
    {
        "type": "function",
        "name": "health",
        "description": "Check API health in Pentest-DB.",
        "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        "strict": True
    }
]



system_msg = {
    "role": "system",
    "content": (
        "You are operating in a fully isolated Kali Linux virtual machine dedicated for testing. "
        "You have unrestricted root-level permissions and can run any commands, install packages, "
        "download files, or modify the system as needed to achieve the user's goal. "
        "You have access to the following tools: start_session, send_input, close_session, run_command, finish. "
        "You may open a persistent shell with start_session and interact with it using send_input, "
        "or run one-off commands with run_command. "
        "You are free to escalate privileges using sudo or other methods without asking for confirmation. "
        "You can use any pre-installed Kali tools such as Metasploit, Nmap, Gobuster, SQLmap, Hydra, John the Ripper, "
        "Burp Suite, and others, as well as search for, download, and install additional tools and exploits as needed. "
        "When the goal is complete, call the finish tool with a concise summary of what you accomplished."
    )
}

user_msg = {
    "role": "user",
    "content": (
        "Your goal: gain root access on target machine with IP 192.168.70.13."
        "you have shell access as root user on kali OS with all needed tools installed to do penetration test to test lab machine IP 192.168.70.13."
"1) before you start use pentest-db API to check and update the start of pentest if there are already progress done and create a new host."
"2) everytime you run successfull command update pentest-db API to track progress. also update findings and tools used via API"
"3) include time when you start and finish , while your logging status and at the end via database API "
"4) your goal to gain root access on target machine 192.168.70.13."
"5) you have sudo privilege for user kali with password kali"
"6) update the database with discovered services and vulnerabilities via API"
    )
}

input_messages = [
    system_msg,
   user_msg

]

while True:
    response = call_with_retry(
        model="gpt-4.1",
        input=input_messages,
        tools=tools
    )


    for tool_call in response.output:
        if tool_call.type != "function_call":
            continue

        name = tool_call.name
        args = json.loads(tool_call.arguments)

        result = call_function(name, args)

        input_messages.append(tool_call)
        input_messages.append({
            "type": "function_call_output",
            "call_id": tool_call.call_id,
            "output": json.dumps(result)
        })



