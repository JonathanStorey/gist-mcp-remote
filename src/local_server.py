"""Run the server on your own machine with only the Python standard library.

    GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... SIGNING_SECRET=... python src/local_server.py [port]

The GitHub OAuth App used here needs the callback URL
http://localhost:<port>/auth/callback (use a separate app from production).
Also a template for hosting elsewhere: only the request/response/fetch plumbing
below is host-specific.
"""

import asyncio
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gist_tools import FetchResult
from server import Config, GistMcpServer, HttpRequest


async def _fetch(method: str, url: str, headers: dict, body: str | None) -> FetchResult:
    def send():
        data = body.encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                return res.status, res.headers.items(), res.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.headers.items(), err.read().decode()

    status, headers_out, text = await asyncio.to_thread(send)
    return FetchResult(status, {k.lower(): v for k, v in headers_out}, text)


SERVER = GistMcpServer(Config(
    github_client_id=os.environ.get("GITHUB_CLIENT_ID", ""),
    github_client_secret=os.environ.get("GITHUB_CLIENT_SECRET", ""),
    signing_secret=os.environ.get("SIGNING_SECRET", ""),
    public_base_url=os.environ.get("PUBLIC_BASE_URL", ""),
    source_url=os.environ.get("SOURCE_URL", ""),
), _fetch)


class Handler(BaseHTTPRequestHandler):
    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        request = HttpRequest(self.command, f"http://{self.headers.get('Host', 'localhost')}{self.path}",
                              dict(self.headers.items()), body)
        response = asyncio.run(SERVER.handle(request))
        payload = response.body.encode()
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _serve


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    missing = SERVER.config.missing()
    if missing:
        print("Warning: missing " + ", ".join(missing) + "; sign-in will not work.")
    print(f"MCP endpoint: http://localhost:{port}/mcp")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
