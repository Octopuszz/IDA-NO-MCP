#!/usr/bin/env python3

import argparse
import json
import sys
import urllib.request
import urllib.error
import urllib.parse
from typing import Any

BASE_URL = ""
AUTH_TOKEN = ""


# ──────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────

def http_get(endpoint: str, params: dict = None, timeout: int = 30) -> dict:
    """Perform GET request against inp_http_server, return parsed JSON."""
    url = BASE_URL.rstrip("/") + endpoint
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url)
    if AUTH_TOKEN:
        req.add_header("Authorization", f"Bearer {AUTH_TOKEN}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:300]}"}
    except urllib.error.URLError as e:
        return {"error": f"Connection failed: {e.reason}. Is inp_http_server.py running in the VM?"}
    except Exception as e:
        return {"error": str(e)}


def get_text(result: dict, key: str = "content") -> str:
    """Extract text content from HTTP response, or format error."""
    if "error" in result:
        return f"[HTTP ERROR] {result['error']}"
    val = result.get(key, result)
    if isinstance(val, str):
        return val
    return json.dumps(val, ensure_ascii=False, indent=2)


def read_remote_file(rel_path: str, offset: int = 0, max_bytes: int = 512 * 1024) -> str:
    """Read a remote file and return its text content."""
    result = http_get("/file", {
        "path": rel_path,
        "offset": offset,
        "length": max_bytes
    })
    if "error" in result:
        return f"[HTTP ERROR] {result['error']}"

    text = result.get("content", "")
    if result.get("truncated"):
        total = result.get("total_size", "?")
        shown = result.get("offset", 0) + result.get("length", 0)
        text += f"\n\n[... TRUNCATED: showing {shown}/{total} bytes. Use read_raw with offset={shown} to continue ...]"
    return text


# ──────────────────────────────────────────────────────────────
# MCP stdio helpers
# ──────────────────────────────────────────────────────────────

def send(obj: dict):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def error_response(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def ok_response(req_id, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


# ──────────────────────────────────────────────────────────────
# Tool implementations
# ──────────────────────────────────────────────────────────────

def tool_list_overview(_args: dict) -> str:
    result = http_get("/overview")
    if "error" in result:
        return f"[HTTP ERROR] {result['error']}"
    lines = [
        f"VM Export Server : {BASE_URL}",
        f"Export directory : {result.get('export_dir', '?')}",
        "",
        f"Decompiled (.c)  : {result.get('decompiled_functions', 0)}",
        f"Disasm fallback  : {result.get('disasm_fallback', 0)}",
        f"Memory chunks    : {result.get('memory_chunks', 0)}",
        "",
        "── Metadata files ──"
    ]
    for fname, size in (result.get("files") or {}).items():
        status = f"{size:,} bytes" if size is not None else "(not exported yet)"
        lines.append(f"  {fname:35s}: {status}")
    return "\n".join(lines)


def tool_list_functions(_args: dict) -> str:
    # try function_index.txt first (rich info)
    result = http_get("/file", {"path": "function_index.txt", "length": 256 * 1024})
    if "error" not in result:
        return result.get("content", "")

    # fallback: list directory entries
    dc = http_get("/list", {"dir": "decompile"})
    da = http_get("/list", {"dir": "disassembly"})
    lines = []
    for entry in (dc.get("files") or []):
        if entry["name"].endswith(".c"):
            lines.append(f"{entry['name'][:-2]}  decompile  {entry.get('size', '?')} bytes")
    for entry in (da.get("files") or []):
        if entry["name"].endswith(".asm"):
            lines.append(f"{entry['name'][:-4]}  disasm  {entry.get('size', '?')} bytes")
    return "\n".join(lines) if lines else "[No exported functions found]"


def tool_read_function(args: dict) -> str:
    addr = args.get("address", "").strip().lower().replace("0x", "").upper()
    if not addr:
        return "[ERROR] 'address' is required."

    for subdir, ext in [("decompile", ".c"), ("disassembly", ".asm")]:
        result = http_get("/file", {"path": f"{subdir}/{addr}{ext}"})
        if "error" not in result:
            text = result.get("content", "")
            if result.get("truncated"):
                total = result.get("total_size", "?")
                text += f"\n\n[TRUNCATED — total {total} bytes. Use read_raw with offset to see more]"
            return text

    return (f"[NOT FOUND] No file for address {addr}. "
            "Use list_functions or search_functions to find valid addresses.")


def tool_read_function_batch(args: dict) -> str:
    addresses = args.get("addresses", [])
    if not addresses:
        return "[ERROR] 'addresses' must be a non-empty list."
    parts = []
    for raw in addresses:
        addr = raw.strip().lower().replace("0x", "").upper()
        found = False
        for subdir, ext in [("decompile", ".c"), ("disassembly", ".asm")]:
            result = http_get("/file", {"path": f"{subdir}/{addr}{ext}"})
            if "error" not in result:
                parts.append(f"{'='*60}\n[{addr}]\n{'='*60}")
                parts.append(result.get("content", ""))
                found = True
                break
        if not found:
            parts.append(f"[NOT FOUND: {addr}]")
    return "\n\n".join(parts)


def tool_search_functions(args: dict) -> str:
    query = args.get("query", "").strip()
    if not query:
        return "[ERROR] 'query' is required."
    result = http_get("/search", {"q": query, "type": "functions"})
    if "error" in result:
        return f"[HTTP ERROR] {result['error']}"
    items = result.get("results", [])
    if not items:
        return f"[NO MATCH] No functions found matching '{query}'."
    lines = [f"{r['address']}  {r['type']}  {r['name']}" for r in items]
    return "\n".join(lines)


def tool_read_strings(args: dict) -> str:
    flt = args.get("filter", "").strip()
    if flt:
        result = http_get("/search", {"q": flt, "type": "strings"})
        if "error" in result:
            return f"[HTTP ERROR] {result['error']}"
        items = result.get("results", [])
        if not items:
            return f"[NO MATCH] No strings containing '{flt}'."
        return "\n".join(r["line"] for r in items)
    return read_remote_file("strings.txt", max_bytes=256 * 1024)


def tool_read_imports(args: dict) -> str:
    flt = args.get("filter", "").strip()
    if flt:
        result = http_get("/search", {"q": flt, "type": "imports"})
        if "error" in result:
            return f"[HTTP ERROR] {result['error']}"
        items = result.get("results", [])
        if not items:
            return f"[NO MATCH] No imports containing '{flt}'."
        return "\n".join(r["line"] for r in items)
    return read_remote_file("imports.txt", max_bytes=128 * 1024)


def tool_read_exports(args: dict) -> str:
    flt = args.get("filter", "").strip()
    if flt:
        result = http_get("/search", {"q": flt, "type": "all"})
        if "error" in result:
            return f"[HTTP ERROR] {result['error']}"
        items = [r for r in result.get("results", []) if r.get("type") == "import"]
        return "\n".join(r["line"] for r in items) if items else f"[NO MATCH]"
    return read_remote_file("exports.txt", max_bytes=128 * 1024)


def tool_read_pointers(_args: dict) -> str:
    return read_remote_file("pointers.txt", max_bytes=256 * 1024)


def tool_list_memory_chunks(_args: dict) -> str:
    result = http_get("/list", {"dir": "memory"})
    if "error" in result:
        return f"[HTTP ERROR] {result['error']}"
    files = result.get("files", [])
    if not files:
        return "[NOT FOUND] No memory chunks exported yet."
    lines = ["Memory chunks:"]
    for f in files:
        lines.append(f"  {f['name']}  ({f.get('size', '?'):,} bytes)" if isinstance(f.get('size'), int)
                     else f"  {f['name']}")
    return "\n".join(lines)


def tool_read_memory_chunk(args: dict) -> str:
    filename = args.get("filename", "").strip()
    addr_raw = args.get("address", "").strip()

    if filename:
        return read_remote_file(f"memory/{filename}")

    if addr_raw:
        # find the right chunk via directory listing
        try:
            target = int(addr_raw.replace("0x", "").replace("0X", ""), 16)
        except ValueError:
            return "[ERROR] Invalid address format."

        result = http_get("/list", {"dir": "memory"})
        if "error" in result:
            return f"[HTTP ERROR] {result['error']}"

        for entry in (result.get("files") or []):
            name = entry["name"]
            if not name.endswith(".txt"):
                continue
            parts = name.replace(".txt", "").split("--")
            if len(parts) == 2:
                try:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    if start <= target < end:
                        return f"[Chunk: {name}]\n" + read_remote_file(f"memory/{name}")
                except ValueError:
                    continue
        return f"[NOT FOUND] No memory chunk contains address {addr_raw}."

    return "[ERROR] Provide 'filename' or 'address'."


def tool_read_log(args: dict) -> str:
    mapping = {
        "failed":   "decompile_failed.txt",
        "skipped":  "decompile_skipped.txt",
        "fallback": "disassembly_fallback.txt",
        "index":    "function_index.txt",
    }
    log_type = args.get("type", "failed").strip().lower()
    fname = mapping.get(log_type)
    if not fname:
        return f"[ERROR] Unknown log type '{log_type}'. Choose: failed, skipped, fallback, index."
    return read_remote_file(fname, max_bytes=256 * 1024)


def tool_read_raw(args: dict) -> str:
    rel = args.get("path", "").strip().lstrip("/\\")
    if not rel:
        return "[ERROR] 'path' is required."
    offset = int(args.get("offset", 0))
    max_b = int(args.get("max_bytes", 512 * 1024))
    return read_remote_file(rel, offset=offset, max_bytes=max_b)


def tool_ping(_args: dict) -> str:
    result = http_get("/ping")
    if "error" in result:
        return f"[UNREACHABLE] {result['error']}"
    return (f"VM server reachable: {BASE_URL}\n"
            f"Export dir: {result.get('export_dir', '?')}\n"
            f"Status: {result.get('status', '?')}")


# ──────────────────────────────────────────────────────────────
# MCP tool registry
# ──────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "ping",
        "description": "Test connectivity to the VM's HTTP server. Use this first to confirm the connection works.",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "list_overview",
        "description": "Show a summary of all exported IDA Pro files (function counts, file sizes, etc.).",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "list_functions",
        "description": "List all exported functions with hex addresses and export type (decompile / disasm-fallback).",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "read_function",
        "description": "Read decompiled C pseudocode or disassembly of one function by hex address (e.g. '401000').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Hex address, e.g. '401000' or '0x401000'."}
            },
            "required": ["address"]
        }
    },
    {
        "name": "read_function_batch",
        "description": "Read multiple functions at once. Useful for call-graph analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addresses": {"type": "array", "items": {"type": "string"},
                              "description": "List of hex addresses, e.g. ['401000', '4012AB']."}
            },
            "required": ["addresses"]
        }
    },
    {
        "name": "search_functions",
        "description": "Search functions by name substring (case-insensitive), e.g. 'crypto', 'socket', 'main'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Name substring to search for."}
            },
            "required": ["query"]
        }
    },
    {
        "name": "read_strings",
        "description": "Read strings.txt. Optional 'filter' parameter to grep for keywords like 'password', 'http'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional keyword filter."}
            },
            "required": []
        }
    },
    {
        "name": "read_imports",
        "description": "Read imports.txt. Optional 'filter' for keywords like 'Crypt', 'socket', 'Reg'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional keyword filter."}
            },
            "required": []
        }
    },
    {
        "name": "read_exports",
        "description": "Read exports.txt. Optional 'filter' for keywords.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional keyword filter."}
            },
            "required": []
        }
    },
    {
        "name": "read_pointers",
        "description": "Read pointer reference analysis (pointers.txt).",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "list_memory_chunks",
        "description": "List all memory hexdump chunks in memory/ directory.",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "read_memory_chunk",
        "description": "Read a memory hexdump by filename or by an address within the chunk range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Chunk filename e.g. '00401000--00402000.txt'."},
                "address":  {"type": "string", "description": "Hex address inside a chunk, e.g. '401500'."}
            },
            "required": []
        }
    },
    {
        "name": "read_log",
        "description": "Read export logs: 'failed'|'skipped'|'fallback'|'index'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["failed", "skipped", "fallback", "index"]}
            },
            "required": ["type"]
        }
    },
    {
        "name": "read_raw",
        "description": ("Read any file under the export dir by relative path. "
                        "Supports 'offset' and 'max_bytes' for pagination of large files."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":      {"type": "string", "description": "Relative path, e.g. 'decompile/401000.c'."},
                "offset":    {"type": "integer", "description": "Byte offset (default 0)."},
                "max_bytes": {"type": "integer", "description": "Max bytes to read (default 524288)."}
            },
            "required": ["path"]
        }
    },
]

DISPATCH = {
    "ping":                tool_ping,
    "list_overview":       tool_list_overview,
    "list_functions":      tool_list_functions,
    "read_function":       tool_read_function,
    "read_function_batch": tool_read_function_batch,
    "search_functions":    tool_search_functions,
    "read_strings":        tool_read_strings,
    "read_imports":        tool_read_imports,
    "read_exports":        tool_read_exports,
    "read_pointers":       tool_read_pointers,
    "list_memory_chunks":  tool_list_memory_chunks,
    "read_memory_chunk":   tool_read_memory_chunk,
    "read_log":            tool_read_log,
    "read_raw":            tool_read_raw,
}


# ──────────────────────────────────────────────────────────────
# MCP request handler
# ──────────────────────────────────────────────────────────────

def handle(req: dict) -> dict | None:
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params", {})

    if method == "initialize":
        return ok_response(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "ida-inp-http-mcp", "version": "1.0.0"},
            "capabilities": {"tools": {}}
        })

    if method == "tools/list":
        return ok_response(req_id, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        tool_args = params.get("arguments", {})
        fn = DISPATCH.get(name)
        if fn is None:
            return error_response(req_id, -32601, f"Unknown tool: {name}")
        try:
            text = fn(tool_args)
            return ok_response(req_id, {"content": [{"type": "text", "text": text}]})
        except Exception as exc:
            return error_response(req_id, -32603, str(exc))

    if req_id is None or method.startswith("notifications/"):
        return None

    return error_response(req_id, -32601, f"Method not found: {method}")


def main():
    parser = argparse.ArgumentParser(
        description="INP HTTP MCP Server — bridges Claude Code to VM's IDA export HTTP server"
    )
    parser.add_argument("--server", "-s", required=True,
                        help="Base URL of inp_http_server.py, e.g. http://192.168.1.100:18080")
    parser.add_argument("--token", "-t", default="",
                        help="Bearer token (must match --token on inp_http_server.py)")
    args = parser.parse_args()

    global BASE_URL, AUTH_TOKEN
    BASE_URL = args.server.rstrip("/")
    AUTH_TOKEN = args.token

    sys.stderr.write(f"[INP-MCP] Connecting to VM server: {BASE_URL}\n")
    sys.stderr.write(f"[INP-MCP] MCP server ready (stdio transport).\n")
    sys.stderr.flush()

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            send(error_response(None, -32700, "Parse error"))
            continue
        resp = handle(req)
        if resp is not None:
            send(resp)


if __name__ == "__main__":
    main()
