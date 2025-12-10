#!/usr/bin/env python3
from __future__ import annotations
import os, shlex, time, uuid, asyncio
from typing import Optional, Dict, Any

try:
    from fastmcp import FastMCP, Context
except Exception:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP  # type: ignore
    Context = Any  # type: ignore

mcp = FastMCP("remote-CMD-MCP")
_JOBS: Dict[str, Dict[str, Any]] = {}


def send_progress(ctx: Optional[Context], message: str, percent: Optional[int] = None) -> None:
    """
    Try several method names; ignore if none exist.
    Some FastMCP builds/clients don't offer progress APIs.
    """
    if not ctx:
        return
    try:
        if hasattr(ctx, "progress") and callable(getattr(ctx, "progress")):
            # Newer style
            if percent is None:  # some impls require int
                percent = 0
            ctx.progress(message=message, percent=int(percent))
            return
    except Exception:
        pass
    for name in ("send_progress", "report_progress", "notify_progress", "emit_progress"):
        try:
            meth = getattr(ctx, name, None)
            if callable(meth):
                # many variants accept just a message
                try:
                    meth(message=message, percent=int(percent or 0))
                except TypeError:
                    meth(message)  # fallback signature
                return
        except Exception:
            pass
    # If there is no progress API, silently do nothing.

# ---------- Process helpers ----------
async def _spawn_proc(command: str, shell: bool, cwd: Optional[str]):
    if shell:
        return await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    return await asyncio.create_subprocess_exec(
        *shlex.split(command),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )

async def _read_stream(stream: asyncio.StreamReader, sink: list[str]):
    while True:
        chunk = await stream.readline()
        if not chunk:
            break
        sink.append(chunk.decode(errors="replace"))

async def _run_with_keepalive(
    command: str,
    shell: bool,
    cwd: Optional[str],
    keepalive_s: int,
    ctx: Optional[Context],
) -> Dict[str, Any]:
    started = time.time()
    proc = await _spawn_proc(command, shell, cwd)
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    t_out = asyncio.create_task(_read_stream(proc.stdout, stdout_chunks))
    t_err = asyncio.create_task(_read_stream(proc.stderr, stderr_chunks))
    t_wait = asyncio.create_task(proc.wait())

    last_ping = 0.0
    while not t_wait.done():
        now = time.time()
        if keepalive_s > 0 and (now - last_ping) >= keepalive_s:
            elapsed = int(now - started)
            
            percent = min(95, max(0, int(elapsed / max(keepalive_s, 1) * 10)))
            send_progress(ctx, f"Running: {command[:120]} … (elapsed {elapsed}s)", percent)
            last_ping = now
        await asyncio.sleep(0.5)

    await asyncio.gather(t_out, t_err, return_exceptions=True)
    rc = t_wait.result()

    return {
        "ok": rc == 0,
        "code": rc,
        "stdout": "".join(stdout_chunks),
        "stderr": "".join(stderr_chunks),
        "duration_s": round(time.time() - started, 3),
        "pid": proc.pid,
    }

# ---------- Tools ----------
@mcp.tool
async def run_cmd(
    command: str,
    timeout_s: int = 200,
    shell: bool = False,
    cwd: Optional[str] = None,
    keepalive_s: int = 10,
    background: bool = False,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Execute an OS command and return stdout/stderr/exit code.
    - If your client doesn't support progress, calls are ignored safely.
    - For long commands, prefer background=True and poll get_job().
    """
    job_id = str(uuid.uuid4())
    started = time.time()

    async def _runner(store: Dict[str, Any]):
        try:
            res = await _run_with_keepalive(command, shell, cwd, keepalive_s, ctx)
            store.update(res)
            store["done"] = True
        except asyncio.CancelledError:
            store.update({"ok": False, "error": "cancelled", "done": True})
            raise
        except Exception as e:
            store.update({"ok": False, "error": str(e), "done": True})

    if background:
        _JOBS[job_id] = {"id": job_id, "cmd": command, "started_at": started, "done": False}
        async def _bg():
            try:
                await asyncio.wait_for(_runner(_JOBS[job_id]), timeout=timeout_s)
            except asyncio.TimeoutError:
                _JOBS[job_id].update(
                    {"ok": False, "error": "timeout", "done": True, "duration_s": round(time.time() - started, 3)}
                )
        asyncio.create_task(_bg())
        return {"job_id": job_id, "status": "started"}

    record: Dict[str, Any] = {"id": job_id, "cmd": command, "started_at": started, "done": False}
    try:
        await asyncio.wait_for(_runner(record), timeout=timeout_s)
    except asyncio.TimeoutError:
        record.update({"ok": False, "error": "timeout", "done": True, "duration_s": round(time.time() - started, 3)})
    return record

@mcp.tool
def get_job(job_id: str) -> Dict[str, Any]:
    j = _JOBS.get(job_id)
    if not j:
        return {"ok": False, "error": "not_found", "job_id": job_id}
    return j

@mcp.tool
def list_jobs() -> Dict[str, Any]:
    return {"jobs": list(_JOBS.values())}

@mcp.tool
def cancel_job(job_id: str) -> Dict[str, Any]:
    j = _JOBS.get(job_id)
    if not j:
        return {"ok": False, "error": "not_found"}
    pid = j.get("pid")
    if not pid:
        return {"ok": False, "error": "no_pid"}
    try:
        os.kill(pid, 15)
        j.update({"ok": False, "error": "cancelled", "done": True})
        return {"ok": True, "killed": pid}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@mcp.tool
def ps_aux() -> Dict[str, Any]:
    import subprocess
    out = subprocess.check_output(["ps", "aux"], text=True)
    return {"stdout": out}

@mcp.tool
def kill_process(pid: int, sig: int = 15) -> Dict[str, Any]:
    os.kill(pid, sig)
    return {"killed": pid, "signal": sig}

# Health probe (older FastMCP needs explicit methods)
@mcp.custom_route("/health", methods=["GET"])
async def health_route(_scope, _receive, send):
    body = b'{"status":"ok"}'
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"application/json"],
                [b"cache-control", b"no-store"],
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default=os.getenv("TRANSPORT", "http"), choices=["http", "sse"])
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))
    parser.add_argument("--path", default=os.getenv("PATH_PREFIX", "/mcp/"))
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "info"))
    args = parser.parse_args()

    mcp.run(
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path if args.transport == "http" else None,
        log_level=args.log_level,
    )
