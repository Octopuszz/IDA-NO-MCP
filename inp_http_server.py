#!/usr/bin/env python3

import argparse
import json
import os
import sys
import mimetypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

EXPORT_DIR = ""
AUTH_TOKEN = ""


class INPHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[INP-HTTP] {self.address_string()} - {fmt % args}\n")

    def _check_auth(self) -> bool:
        if not AUTH_TOKEN:
            return True
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {AUTH_TOKEN}":
            return True
        params = parse_qs(urlparse(self.path).query)
        if params.get("token", [""])[0] == AUTH_TOKEN:
            return True
        return False

    def _send_json(self, code: int, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization")
        self.end_headers()

    def do_GET(self):
        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized. Pass ?token=... or Authorization: Bearer ..."})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # ── /ping ──────────────────────────────────────
        if path == "" or path == "/ping":
            self._send_json(200, {"status": "ok", "export_dir": EXPORT_DIR})
            return

        # ── /overview ──────────────────────────────────
        if path == "/overview":
            self._send_json(200, self._build_overview())
            return

        # ── /list?dir=decompile ────────────────────────
        if path == "/list":
            params = parse_qs(parsed.query)
            subdir = params.get("dir", [""])[0].strip().strip("/\\")
            target = os.path.normpath(os.path.join(EXPORT_DIR, subdir)) if subdir else EXPORT_DIR
            if not target.startswith(EXPORT_DIR):
                self._send_json(400, {"error": "Path traversal denied"}); return
            if not os.path.isdir(target):
                self._send_json(404, {"error": f"Directory not found: {subdir}"}); return
            files = []
            for fname in sorted(os.listdir(target)):
                fpath = os.path.join(target, fname)
                entry = {"name": fname, "is_dir": os.path.isdir(fpath)}
                if not entry["is_dir"]:
                    entry["size"] = os.path.getsize(fpath)
                files.append(entry)
            self._send_json(200, {"dir": subdir or ".", "files": files})
            return

        # ── /file?path=decompile/401000.c ─────────────
        if path == "/file":
            params = parse_qs(parsed.query)
            rel = unquote(params.get("path", [""])[0]).strip().lstrip("/\\")
            if not rel:
                self._send_json(400, {"error": "'path' parameter required"}); return
            full = os.path.normpath(os.path.join(EXPORT_DIR, rel))
            if not full.startswith(EXPORT_DIR):
                self._send_json(400, {"error": "Path traversal denied"}); return
            if not os.path.isfile(full):
                self._send_json(404, {"error": f"File not found: {rel}"}); return
            # optional range (bytes)
            offset = int(params.get("offset", ["0"])[0])
            length = int(params.get("length", [str(512 * 1024)])[0])
            length = min(length, 2 * 1024 * 1024)  # hard cap 2 MB
            try:
                with open(full, "rb") as f:
                    f.seek(offset)
                    data = f.read(length)
                total_size = os.path.getsize(full)
                text = data.decode("utf-8", errors="replace")
                self._send_json(200, {
                    "path": rel,
                    "offset": offset,
                    "length": len(data),
                    "total_size": total_size,
                    "truncated": (offset + len(data)) < total_size,
                    "content": text
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        # ── /search?q=crypto&type=functions|strings ────
        if path == "/search":
            params = parse_qs(parsed.query)
            query = params.get("q", [""])[0].strip().lower()
            stype = params.get("type", ["functions"])[0].strip().lower()
            if not query:
                self._send_json(400, {"error": "'q' parameter required"}); return
            results = self._do_search(query, stype)
            self._send_json(200, {"query": query, "type": stype, "results": results})
            return

        self._send_json(404, {"error": f"Unknown endpoint: {path}"})

    # ── helpers ──────────────────────────────────────────────────

    def _build_overview(self) -> dict:
        def count_files(d, ext=None):
            if not os.path.isdir(d):
                return 0
            return sum(1 for f in os.listdir(d)
                       if os.path.isfile(os.path.join(d, f))
                       and (ext is None or f.endswith(ext)))

        def fsize(fname):
            p = os.path.join(EXPORT_DIR, fname)
            return os.path.getsize(p) if os.path.isfile(p) else None

        return {
            "export_dir": EXPORT_DIR,
            "decompiled_functions": count_files(os.path.join(EXPORT_DIR, "decompile"), ".c"),
            "disasm_fallback": count_files(os.path.join(EXPORT_DIR, "disassembly"), ".asm"),
            "memory_chunks": count_files(os.path.join(EXPORT_DIR, "memory")),
            "files": {
                fname: fsize(fname) for fname in [
                    "strings.txt", "imports.txt", "exports.txt", "pointers.txt",
                    "function_index.txt", "decompile_failed.txt",
                    "decompile_skipped.txt", "disassembly_fallback.txt",
                ]
            }
        }

    def _do_search(self, query: str, stype: str) -> list:
        results = []
        MAX = 100

        if stype in ("functions", "all"):
            for base, ext, kind in [
                (os.path.join(EXPORT_DIR, "decompile"), ".c", "decompile"),
                (os.path.join(EXPORT_DIR, "disassembly"), ".asm", "disasm"),
            ]:
                if not os.path.isdir(base):
                    continue
                for fname in sorted(os.listdir(base)):
                    if not fname.endswith(ext):
                        continue
                    fpath = os.path.join(base, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            header = f.read(512)
                        for line in header.splitlines():
                            if "func-name:" in line.lower():
                                func_name = line.split("func-name:", 1)[1].strip()
                                if query in func_name.lower():
                                    addr = fname.replace(ext, "")
                                    results.append({
                                        "address": addr,
                                        "name": func_name,
                                        "type": kind,
                                        "file": f"{kind}/{fname}"
                                    })
                                break
                    except Exception:
                        continue
                    if len(results) >= MAX:
                        break

        if stype in ("strings", "all"):
            spath = os.path.join(EXPORT_DIR, "strings.txt")
            if os.path.isfile(spath):
                with open(spath, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if query in line.lower() and not line.startswith("#"):
                            results.append({"type": "string", "line": line.rstrip()})
                        if len(results) >= MAX:
                            break

        if stype in ("imports", "all"):
            ipath = os.path.join(EXPORT_DIR, "imports.txt")
            if os.path.isfile(ipath):
                with open(ipath, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if query in line.lower() and not line.startswith("#"):
                            results.append({"type": "import", "line": line.rstrip()})
                        if len(results) >= MAX:
                            break

        return results


def main():
    parser = argparse.ArgumentParser(description="INP HTTP File Server — serves IDA export dir over HTTP")
    parser.add_argument("--export-dir", "-d", required=True,
                        help="Path to *_export_for_ai directory generated by INP.py")
    parser.add_argument("--port", "-p", type=int, default=18080,
                        help="HTTP port to listen on (default: 18080)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Host to bind to (default: 0.0.0.0, all interfaces)")
    parser.add_argument("--token", default="",
                        help="Optional Bearer token for auth (leave empty to disable)")
    args = parser.parse_args()

    global EXPORT_DIR, AUTH_TOKEN
    EXPORT_DIR = os.path.abspath(args.export_dir)
    AUTH_TOKEN = args.token

    if not os.path.isdir(EXPORT_DIR):
        sys.stderr.write(
            f"[INP-HTTP] WARNING: Export dir does not exist yet: {EXPORT_DIR}\n"
            f"[INP-HTTP] Run INP.py inside IDA Pro first, then this server will serve its output.\n"
        )

    sys.stderr.write(f"[INP-HTTP] Serving: {EXPORT_DIR}\n")
    sys.stderr.write(f"[INP-HTTP] Listening on http://{args.host}:{args.port}/\n")
    if AUTH_TOKEN:
        sys.stderr.write(f"[INP-HTTP] Auth token: {AUTH_TOKEN}\n")
    else:
        sys.stderr.write(f"[INP-HTTP] No auth token (open access on local network)\n")

    httpd = HTTPServer((args.host, args.port), INPHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[INP-HTTP] Stopped.\n")


if __name__ == "__main__":
    main()
