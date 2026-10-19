"""Host-neutral HTTP core: OAuth 2.1 endpoints that delegate sign-in to GitHub,
plus the MCP (Streamable HTTP, JSON response mode) endpoint.

Stateless by design. Anything that must survive between requests (registered
clients, the in-flight sign-in, authorization codes) travels inside
HMAC-signed values, so no database is needed and any instance can serve any
request. After sign-in, the user's GitHub token is handed to the MCP client as
its bearer token and is never stored server-side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from gist_tools import TOOLS, TOOLS_BY_NAME, Fetch, GitHubAuthError, GitHubClient, GitHubError, ToolInputError
from home_page import render_endpoint_notice, render_home_page

SERVER_NAME = "remote-serverless-gist-mcp"
SERVER_VERSION = "0.1.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
SCOPE = "gist"
STATE_TTL = 600  # seconds a user has to finish signing in on GitHub
CODE_TTL = 300   # seconds a client has to redeem its authorization code
MAX_REDIRECT_URIS = 10

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id",
    "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
    "Access-Control-Max-Age": "86400",
}

INSTRUCTIONS = (
    "Tools for the signed-in user's GitHub Gists: list, read, create, update, delete, fork and star. "
    "New gists are secret unless public=true. delete_gist is permanent; confirm with the user first."
)


@dataclass
class Config:
    github_client_id: str = ""
    github_client_secret: str = ""
    signing_secret: str = ""
    public_base_url: str = ""  # optional: override the origin seen in requests (e.g. behind a proxy)
    source_url: str = ""       # optional: link to the source code, shown on the home page
    user_agent: str = SERVER_NAME

    def missing(self) -> list[str]:
        required = {"GITHUB_CLIENT_ID": self.github_client_id,
                    "GITHUB_CLIENT_SECRET": self.github_client_secret,
                    "SIGNING_SECRET": self.signing_secret}
        return [name for name, value in required.items() if not value]


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def __post_init__(self):
        self.method = self.method.upper()
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        parts = urlsplit(self.url)
        self.path = parts.path.rstrip("/") or "/"
        self.query = dict(parse_qsl(parts.query))
        self.origin = f"{parts.scheme}://{parts.netloc}"

    def form(self) -> dict[str, str]:
        if "json" in self.headers.get("content-type", ""):
            try:
                data = json.loads(self.body or "{}")
            except ValueError:
                return {}
            return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        return dict(parse_qsl(self.body or ""))


@dataclass
class HttpResponse:
    status: int
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def json_response(data, status: int = 200, headers: dict | None = None) -> HttpResponse:
    return HttpResponse(status, json.dumps(data), {"Content-Type": "application/json", **(headers or {})})


def text_response(message: str, status: int) -> HttpResponse:
    return HttpResponse(status, message, {"Content-Type": "text/plain; charset=utf-8"})


def html_response(page: str, status: int = 200) -> HttpResponse:
    return HttpResponse(status, page, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache"})


def _wants_html(request: HttpRequest) -> bool:
    return "text/html" in request.headers.get("accept", "")


def redirect(url: str) -> HttpResponse:
    return HttpResponse(302, "", {"Location": url, "Cache-Control": "no-store"})


def oauth_error(error: str, description: str, status: int = 400) -> HttpResponse:
    return json_response({"error": error, "error_description": description}, status,
                         {"Cache-Control": "no-store"})


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def pkce_challenge(verifier: str) -> str:
    return _b64e(hashlib.sha256(verifier.encode()).digest())


def _client_ref(client_id: str) -> str:
    return hashlib.sha256(client_id.encode()).hexdigest()[:24]


def _add_query(url: str, params: dict) -> str:
    params = {k: v for k, v in params.items() if v is not None}
    return url + ("&" if "?" in url else "?") + urlencode(params)


def _valid_redirect_uri(uri) -> bool:
    if not isinstance(uri, str) or len(uri) > 2000:
        return False
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if not scheme or parts.fragment or scheme in ("javascript", "data", "file", "vbscript"):
        return False
    if scheme == "http":
        return parts.hostname in ("localhost", "127.0.0.1", "::1")
    if scheme == "https":
        return bool(parts.netloc)
    return True  # private-use schemes used by native apps, e.g. myapp://callback


class Signer:
    """Issues and verifies tamper-proof, optionally expiring values.

    Values are signed, not encrypted: never put a secret in one.
    """

    def __init__(self, secret: str, clock: Callable[[], float]):
        self._key = secret.encode()
        self._clock = clock

    def seal(self, purpose: str, payload: dict, ttl: int | None = None) -> str:
        body = {**payload, "p": purpose}
        if ttl:
            body["x"] = int(self._clock()) + ttl
        raw = _b64e(json.dumps(body, separators=(",", ":")).encode())
        return f"{raw}.{self._sign(raw)}"

    def unseal(self, purpose: str, token) -> dict | None:
        if not isinstance(token, str) or token.count(".") != 1:
            return None
        raw, signature = token.split(".")
        if not hmac.compare_digest(signature, self._sign(raw)):
            return None
        try:
            body = json.loads(_b64d(raw))
        except ValueError:
            return None
        if not isinstance(body, dict) or body.get("p") != purpose:
            return None
        if "x" in body and body["x"] < self._clock():
            return None
        return body

    def _sign(self, raw: str) -> str:
        return _b64e(hmac.new(self._key, raw.encode(), hashlib.sha256).digest())


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _rpc_result(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


class GistMcpServer:
    """Routes one HTTP request. Create per request or reuse; it holds no user state."""

    def __init__(self, config: Config, fetch: Fetch, clock: Callable[[], float] = time.time):
        self.config = config
        self._fetch = fetch
        self._clock = clock
        self._signer = Signer(config.signing_secret, clock)
        self._routes = {
            "/": {"GET": self._index},
            "/.well-known/oauth-protected-resource": {"GET": self._resource_metadata},
            "/.well-known/oauth-protected-resource/mcp": {"GET": self._resource_metadata},
            "/.well-known/oauth-authorization-server": {"GET": self._auth_server_metadata},
            "/register": {"POST": self._register},
            "/authorize": {"GET": self._authorize},
            "/auth/callback": {"GET": self._callback},
            "/token": {"POST": self._token},
            "/mcp": {"POST": self._mcp, "GET": self._mcp_get},
        }

    async def handle(self, request: HttpRequest) -> HttpResponse:
        if request.method == "OPTIONS":
            response = HttpResponse(204)
        else:
            try:
                response = await self._route(request)
            except Exception:
                traceback.print_exc()
                response = json_response({"error": "server_error",
                                          "error_description": "Unexpected server error."}, 500)
        response.headers.update(CORS_HEADERS)
        return response

    async def _route(self, request: HttpRequest) -> HttpResponse:
        methods = self._routes.get(request.path)
        if methods is None:
            return json_response({"error": "not_found"}, 404)
        handler = methods.get(request.method)
        if handler is None:
            return HttpResponse(405, "", {"Allow": ", ".join(methods)})
        if request.path in ("/register", "/authorize", "/auth/callback", "/token"):
            missing = self.config.missing()
            if missing:
                return oauth_error("temporarily_unavailable",
                                   "Server is not configured; missing: " + ", ".join(missing), 503)
        return await handler(request)

    def _base(self, request: HttpRequest) -> str:
        return self.config.public_base_url.rstrip("/") or request.origin

    # --- discovery -----------------------------------------------------------

    async def _index(self, request):
        endpoint = f"{self._base(request)}/mcp"
        if _wants_html(request):
            return html_response(render_home_page(endpoint, SERVER_VERSION, self.config.missing(),
                                                  self.config.source_url))
        return json_response({"name": SERVER_NAME, "version": SERVER_VERSION, "mcp_endpoint": endpoint,
                              "signin_configured": not self.config.missing()})

    async def _resource_metadata(self, request):
        base = self._base(request)
        return json_response({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": SERVER_NAME,
        })

    async def _auth_server_metadata(self, request):
        base = self._base(request)
        return json_response({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
        })

    # --- OAuth ----------------------------------------------------------------

    async def _register(self, request):
        """Dynamic Client Registration (RFC 7591). The client_id is a signed list of redirect URIs."""
        try:
            meta = json.loads(request.body or "{}")
        except ValueError:
            return oauth_error("invalid_client_metadata", "Body must be JSON.")
        uris = meta.get("redirect_uris") if isinstance(meta, dict) else None
        if not isinstance(uris, list) or not uris or len(uris) > MAX_REDIRECT_URIS:
            return oauth_error("invalid_redirect_uri", f"Provide 1-{MAX_REDIRECT_URIS} redirect_uris.")
        bad = [u for u in uris if not _valid_redirect_uri(u)]
        if bad:
            return oauth_error("invalid_redirect_uri",
                               f"Unsupported redirect URI: {bad[0]!r}. Use https, a loopback http URL, or an app scheme.")
        client_id = self._signer.seal("client", {"r": uris})
        response = {
            "client_id": client_id,
            "client_id_issued_at": int(self._clock()),
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        if isinstance(meta.get("client_name"), str):
            response["client_name"] = meta["client_name"]
        return json_response(response, 201, {"Cache-Control": "no-store"})

    async def _authorize(self, request):
        q = request.query
        client = self._signer.unseal("client", q.get("client_id"))
        if not client:
            return text_response("Unknown client_id. Re-add this server in your MCP client.", 400)
        redirect_uri = q.get("redirect_uri") or (client["r"][0] if len(client["r"]) == 1 else None)
        if redirect_uri not in client["r"]:
            return text_response("redirect_uri does not match the registered client.", 400)

        def fail(error: str, description: str) -> HttpResponse:
            return redirect(_add_query(redirect_uri, {"error": error, "error_description": description,
                                                      "state": q.get("state")}))

        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "Only response_type=code is supported.")
        if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required.")

        state = self._signer.seal("state", {
            "c": _client_ref(q["client_id"]),
            "ru": redirect_uri,
            "st": q.get("state"),
            "cc": q["code_challenge"],
        }, STATE_TTL)
        return redirect(_add_query(GITHUB_AUTHORIZE_URL, {
            "client_id": self.config.github_client_id,
            "redirect_uri": f"{self._base(request)}/auth/callback",
            "scope": SCOPE,
            "state": state,
        }))

    async def _callback(self, request):
        q = request.query
        state = self._signer.unseal("state", q.get("state"))
        if not state:
            return text_response("This sign-in link is invalid or has expired. "
                                 "Start again from your MCP client.", 400)
        if q.get("error") or not q.get("code"):
            return redirect(_add_query(state["ru"], {
                "error": "access_denied",
                "error_description": q.get("error_description") or "GitHub sign-in was not completed.",
                "state": state.get("st"),
            }))
        code = self._signer.seal("code", {
            "g": q["code"], "c": state["c"], "r": state["ru"], "cc": state["cc"],
        }, CODE_TTL)
        return redirect(_add_query(state["ru"], {"code": code, "state": state.get("st")}))

    async def _token(self, request):
        form = request.form()
        grant = form.get("grant_type")
        if grant == "authorization_code":
            code = self._signer.unseal("code", form.get("code"))
            if not code:
                return oauth_error("invalid_grant", "Authorization code is invalid or expired.")
            if form.get("client_id") and _client_ref(form["client_id"]) != code["c"]:
                return oauth_error("invalid_grant", "Code was issued to a different client.")
            if "redirect_uri" in form and form["redirect_uri"] != code["r"]:
                return oauth_error("invalid_grant", "redirect_uri does not match.")
            verifier = form.get("code_verifier") or ""
            if not hmac.compare_digest(pkce_challenge(verifier), code["cc"]):
                return oauth_error("invalid_grant", "PKCE verification failed.")
            return await self._github_token(
                {"code": code["g"], "redirect_uri": f"{self._base(request)}/auth/callback"})
        if grant == "refresh_token":
            if not form.get("refresh_token"):
                return oauth_error("invalid_request", "refresh_token is required.")
            return await self._github_token(
                {"grant_type": "refresh_token", "refresh_token": form["refresh_token"]})
        return oauth_error("unsupported_grant_type", "Use authorization_code or refresh_token.")

    async def _github_token(self, params: dict) -> HttpResponse:
        """Exchange with GitHub and pass the resulting token straight through to the client."""
        body = urlencode({"client_id": self.config.github_client_id,
                          "client_secret": self.config.github_client_secret, **params})
        res = await self._fetch("POST", GITHUB_TOKEN_URL, {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.config.user_agent,
        }, body)
        try:
            data = json.loads(res.text)
        except ValueError:
            data = None
        if not isinstance(data, dict) or res.status >= 500:
            return oauth_error("server_error", f"GitHub token endpoint returned HTTP {res.status}.", 502)
        if "error" in data or not data.get("access_token"):
            return oauth_error("invalid_grant", data.get("error_description") or data.get("error") or
                               "GitHub did not issue a token.")
        token = {"access_token": data["access_token"], "token_type": "Bearer",
                 "scope": data.get("scope") or SCOPE}
        for key in ("expires_in", "refresh_token", "refresh_token_expires_in"):
            if data.get(key):
                token[key] = data[key]
        return json_response(token, 200, {"Cache-Control": "no-store", "Pragma": "no-cache"})

    # --- MCP ------------------------------------------------------------------

    def _unauthorized(self, request, description: str, error: str | None = None) -> HttpResponse:
        metadata = f"{self._base(request)}/.well-known/oauth-protected-resource/mcp"
        challenge = f'Bearer resource_metadata="{metadata}", scope="{SCOPE}"'
        if error:
            challenge += f', error="{error}", error_description="{description}"'
        return json_response({"error": error or "unauthorized", "error_description": description},
                             401, {"WWW-Authenticate": challenge})

    async def _mcp_get(self, request):
        # No server-initiated stream is offered, so GET is 405 per the spec; browsers get a pointer home.
        if _wants_html(request):
            response = html_response(render_endpoint_notice(f"{self._base(request)}/"), 405)
        else:
            response = HttpResponse(405)
        response.headers["Allow"] = "POST"
        return response

    async def _mcp(self, request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return self._unauthorized(request, "Sign in with GitHub to use this server.")
        try:
            message = json.loads(request.body)
        except ValueError:
            return json_response(_rpc_error(None, -32700, "Parse error"), 400)

        # The token lives only in this client object for the duration of the request.
        client = GitHubClient(self._fetch, token, self.config.user_agent)
        try:
            if isinstance(message, list):
                if not message:
                    return json_response(_rpc_error(None, -32600, "Empty batch"), 400)
                replies = [r for r in [await self._dispatch(m, client) for m in message] if r]
                return json_response(replies) if replies else HttpResponse(202)
            reply = await self._dispatch(message, client)
        except GitHubAuthError:
            return self._unauthorized(request, "GitHub rejected the token. Sign in again.", "invalid_token")
        return json_response(reply) if reply else HttpResponse(202)

    async def _dispatch(self, message, client: GitHubClient) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _rpc_error(None, -32600, "Invalid Request")
        if "method" not in message:
            return None  # a response from the client; nothing to do
        msg_id = message.get("id")
        if "id" not in message:
            return None  # notification (e.g. notifications/initialized)
        handlers = {
            "initialize": self._initialize,
            "ping": self._ping,
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
        }
        handler = handlers.get(message["method"])
        if handler is None:
            return _rpc_error(msg_id, -32601, f"Method not found: {message['method']}")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _rpc_error(msg_id, -32602, "params must be an object")
        try:
            return _rpc_result(msg_id, await handler(params, client))
        except RpcError as e:
            return _rpc_error(msg_id, e.code, str(e))

    async def _initialize(self, params, client):
        try:
            await client.request("GET", "/user")  # surfaces a stale token now, not mid-task
        except GitHubError:
            pass
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "GitHub Gists", "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        }

    async def _ping(self, params, client):
        return {}

    async def _tools_list(self, params, client):
        return {"tools": [t.describe() for t in TOOLS]}

    async def _tools_call(self, params, client):
        tool = TOOLS_BY_NAME.get(params.get("name"))
        if tool is None:
            raise RpcError(-32602, f"Unknown tool: {params.get('name')}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise RpcError(-32602, "arguments must be an object")
        try:
            data = await tool.handler(client, arguments)
        except (ToolInputError, GitHubError) as e:
            return {"content": [{"type": "text", "text": str(e)}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(data, indent=2)}], "isError": False}
