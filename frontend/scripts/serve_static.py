#!/usr/bin/env python3
"""Production-grade static file server without nginx.

Serves frontend assets with SPA fallback and security headers.
"""

import argparse
import http.server
import os
import socketserver
from pathlib import Path


def _build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve static frontend assets with SPA fallback.")
    parser.add_argument("--host", default=os.getenv("UI_HOST", "0.0.0.0"), help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("UI_PORT", "80")), help="Bind port")
    parser.add_argument(
        "--web-root",
        default=os.getenv("WEB_ROOT", "/srv/frontend"),
        help="Directory to serve",
    )
    return parser.parse_args()


class StaticHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, web_root: Path, **kwargs):
        self._web_root = web_root
        super().__init__(*args, directory=str(web_root), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' http: https:; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        super().end_headers()

    def do_GET(self):
        # SPA fallback: serve index.html for client-side routes.
        rel_path = self.path.split("?", 1)[0].lstrip("/")
        requested = (self._web_root / rel_path).resolve()
        has_file_extension = "." in Path(rel_path).name
        if rel_path and not has_file_extension and not requested.exists():
            self.path = "/index.html"
        return super().do_GET()

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

    def _handler(*h_args, **h_kwargs):
        return StaticHandler(*h_args, web_root=web_root, **h_kwargs)

    with ThreadingTCPServer((args.host, args.port), _handler) as httpd:
        print(f"Serving frontend from {web_root} on {args.host}:{args.port}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
