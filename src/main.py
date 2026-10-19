"""Entry point for Pyodide-based Python edge runtimes (deployed with wrangler).

This is the only module that touches the host platform: it converts the
runtime's request, fetch and response objects to and from the plain-Python
types in server.py. To run on another host, write an equivalent adapter
(see local_server.py for a standard-library example).
"""

from js import Object, fetch as js_fetch
from pyodide.ffi import to_js
from workers import Response, WorkerEntrypoint

from gist_tools import FetchResult
from server import Config, GistMcpServer, HttpRequest

REQUEST_HEADERS = ("authorization", "content-type", "accept", "origin",
                   "mcp-protocol-version", "mcp-session-id")
UPSTREAM_RESPONSE_HEADERS = ("content-type", "link", "retry-after",
                             "x-ratelimit-remaining", "x-ratelimit-reset")


def _js_object(data: dict):
    return to_js(data, dict_converter=Object.fromEntries)


def _pick_headers(js_headers, names) -> dict:
    picked = {}
    for name in names:
        value = js_headers.get(name)
        if value is not None:
            picked[name] = value
    return picked


async def _fetch(method: str, url: str, headers: dict, body: str | None) -> FetchResult:
    init = {"method": method, "headers": headers}
    if body is not None:
        init["body"] = body
    res = await js_fetch(url, _js_object(init))
    return FetchResult(res.status, _pick_headers(res.headers, UPSTREAM_RESPONSE_HEADERS), await res.text())


def _config(env) -> Config:
    def var(name: str) -> str:
        return str(getattr(env, name, None) or "")

    return Config(
        github_client_id=var("GITHUB_CLIENT_ID"),
        github_client_secret=var("GITHUB_CLIENT_SECRET"),
        signing_secret=var("SIGNING_SECRET"),
        public_base_url=var("PUBLIC_BASE_URL"),
        source_url=var("SOURCE_URL"),
    )


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        raw = getattr(request, "js_object", request)  # underlying runtime Request
        method = str(raw.method)
        body = await raw.text() if method in ("POST", "PUT", "PATCH") else ""
        server = GistMcpServer(_config(self.env), _fetch)
        response = await server.handle(
            HttpRequest(method, str(raw.url), _pick_headers(raw.headers, REQUEST_HEADERS), body))
        return Response(response.body or None, status=response.status, headers=response.headers)
