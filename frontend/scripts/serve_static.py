#!/usr/bin/env python3
"""Production-grade static file server without nginx.

Serves frontend assets with SPA fallback, security headers, and an optional
same-origin reverse proxy to the local API (keeps gb_session / gb_csrf cookies
on the UI origin so login does not bounce).
"""

from __future__ import annotations

import argparse
import http.server
import os
import socketserver
import time
import urllib.error
import urllib.request
from pathlib import Path

# Paths forwarded to API_UPSTREAM when present. Keep broad enough for the console.
_API_PREFIXES = (
    "/auth",
    "/gateway",
    "/keys",
    "/v1",
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/cost",
    "/audit",
    "/observability",
    "/discovery",
    "/agentic",
    "/modules",
    "/providers",
    "/secrets",
    "/route-drafts",
    "/rag",
    "/compliance",
    "/orchestration",
    "/runtime",
    "/governance",
    "/browser-security",
    "/browser",
    "/agents",
    "/playground",
    "/benchmark",
    "/scan",
    "/memory",
    "/mcp",
    "/nhi",
    "/jit",
    "/plane",
    "/ui",
    "/feedback",
    "/cpli",
    "/leadership",
)


def _build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve frontend assets with SPA fallback + API proxy.")
    parser.add_argument("--host", default=os.getenv("UI_HOST", "0.0.0.0"), help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("UI_PORT", "80")), help="Bind port")
    parser.add_argument(
        "--web-root",
        default=os.getenv("WEB_ROOT", "/srv/frontend"),
        help="Directory to serve",
    )
    parser.add_argument(
        "--api-upstream",
        default=os.getenv("API_UPSTREAM", "http://127.0.0.1:8000"),
        help="Upstream API base for same-origin proxy (empty to disable)",
    )
    return parser.parse_args()


def _should_proxy(path: str) -> bool:
    normalized = path.split("?", 1)[0] or "/"
    if normalized == "/":
        return False
    for prefix in _API_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return True
    return False


class StaticHandler(http.server.SimpleHTTPRequestHandler):
    api_upstream: str = ""

    def __init__(self, *args, web_root: Path, api_upstream: str = "", **kwargs):
        self._web_root = web_root
        self.api_upstream = (api_upstream or "").rstrip("/")
        super().__init__(*args, directory=str(web_root), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' http: https:; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        path = (self.path or "").split("?", 1)[0]
        no_store_suffixes = (
            "/login.html",
            "/login.js",
            "/login.css",
            "/index.html",
            "/app.js",
            "/js/api-client.js",
        )
        if path == "/" or any(path.endswith(suffix) for suffix in no_store_suffixes):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
        super().end_headers()

    def _proxy_to_api(self) -> None:
        if not self.api_upstream:
            self.send_error(502, "API proxy is not configured")
            return
        upstream = f"{self.api_upstream}{self.path}"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else None
        headers = {}
        for key, value in self.headers.items():
            lowered = key.lower()
            if lowered in {"host", "content-length", "connection", "transfer-encoding"}:
                continue
            headers[key] = value
        request = urllib.request.Request(upstream, data=body, headers=headers, method=self.command)
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                with urllib.request.urlopen(request, timeout=120) as resp:
                    payload = resp.read()
                    self.send_response(resp.status)
                    for key, value in resp.headers.items():
                        lowered = key.lower()
                        if lowered in {"transfer-encoding", "connection", "content-length"}:
                            continue
                        # Rewrite cookie scope to the UI origin (no Domain attribute).
                        if lowered == "set-cookie":
                            parts = [part.strip() for part in value.split(";")]
                            filtered = [parts[0]] if parts else []
                            for part in parts[1:]:
                                pl = part.lower()
                                if pl.startswith("domain="):
                                    continue
                                filtered.append(part)
                            self.send_header("Set-Cookie", "; ".join(filtered))
                        else:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(payload)
                    return
            except urllib.error.HTTPError as exc:
                payload = exc.read() if exc.fp else b""
                self.send_response(exc.code)
                for key, value in (exc.headers or {}).items():
                    lowered = key.lower()
                    if lowered in {"transfer-encoding", "connection", "content-length"}:
                        continue
                    if lowered == "set-cookie":
                        parts = [part.strip() for part in value.split(";")]
                        filtered = [parts[0]] if parts else []
                        for part in parts[1:]:
                            if part.lower().startswith("domain="):
                                continue
                            filtered.append(part)
                        self.send_header("Set-Cookie", "; ".join(filtered))
                    else:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
                return
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.35)
                    # Rebuild request: body may only be sent once on some Python versions.
                    request = urllib.request.Request(upstream, data=body, headers=headers, method=self.command)
                    continue
            except Exception as exc:
                last_error = exc
                break
        self.send_error(502, f"API proxy error: {last_error}")

    def _dispatch(self) -> bool:
        if self.api_upstream and _should_proxy(self.path or "/"):
            self._proxy_to_api()
            return True
        return False

    def do_HEAD(self):
        if self._dispatch():
            return
        rel_path = self.path.split("?", 1)[0].lstrip("/")
        requested = (self._web_root / rel_path).resolve()
        has_file_extension = "." in Path(rel_path).name
        if rel_path and not has_file_extension and not requested.exists():
            self.path = "/index.html"
        return super().do_HEAD()

    def do_GET(self):
        if self._dispatch():
            return
        rel_path = self.path.split("?", 1)[0].lstrip("/")
        requested = (self._web_root / rel_path).resolve()
        has_file_extension = "." in Path(rel_path).name
        if rel_path and not has_file_extension and not requested.exists():
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if not self._dispatch():
            self.send_error(405, "Method not allowed")

    def do_PUT(self):
        if not self._dispatch():
            self.send_error(405, "Method not allowed")

    def do_PATCH(self):
        if not self._dispatch():
            self.send_error(405, "Method not allowed")

    def do_DELETE(self):
        if not self._dispatch():
            self.send_error(405, "Method not allowed")

    def do_OPTIONS(self):
        if not self._dispatch():
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
            self.end_headers()

    def list_directory(self, path):
        self.send_error(403, "Directory listing is disabled")
        return None


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    args = _build_args()
    web_root = Path(args.web_root).resolve()
    if not web_root.exists() or not web_root.is_dir():
        raise SystemExit(f"Invalid --web-root: {web_root}")
    api_upstream = str(args.api_upstream or "").strip()

    def _handler(*h_args, **h_kwargs):
        return StaticHandler(*h_args, web_root=web_root, api_upstream=api_upstream, **h_kwargs)

    with ThreadingTCPServer((args.host, args.port), _handler) as httpd:
        print(f"Serving frontend from {web_root} on {args.host}:{args.port}")
        if api_upstream:
            print(f"Same-origin API proxy → {api_upstream}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
