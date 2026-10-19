"""Tests for the OAuth flow, MCP endpoint and gist tools.

Standard library only; GitHub is replaced by an in-memory fake.
Run with:  python -m unittest discover -s tests   (or: pytest)
"""

import json
import os
import sys
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from gist_tools import TOOLS, FetchResult  # noqa: E402
from server import Config, GistMcpServer, HttpRequest, pkce_challenge  # noqa: E402

BASE = "https://mcp.example.com"
CLIENT_REDIRECT = "https://client.example/callback"
API = "https://api.github.com"
VERIFIER = "test-verifier-" + "x" * 40
NOW = 1_700_000_000


def run(coro):
    """Drive a coroutine that never truly suspends (the fake fetch completes immediately)."""
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    raise RuntimeError("coroutine suspended unexpectedly")


class FakeFetch:
    def __init__(self):
        self.routes = {}
        self.calls = []

    def add(self, method, url, status=200, body=None, headers=None):
        text = body if isinstance(body, str) else ("" if body is None else json.dumps(body))
        self.routes[(method, url)] = FetchResult(status, headers or {}, text)

    async def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return self.routes.get((method, url.split("?")[0]),
                               FetchResult(404, {}, '{"message": "Not Found"}'))


def query_of(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


GIST = {
    "id": "aa5a315d61ae9438b18d", "description": "demo", "public": False,
    "owner": {"login": "octocat"}, "html_url": "https://gist.github.com/aa5a315d61ae9438b18d",
    "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z", "comments": 0,
    "files": {"hello.py": {"filename": "hello.py", "language": "Python", "size": 11,
                           "content": "print('hi')", "raw_url": "https://gist.example/raw", "truncated": False}},
    "history": [{"version": "abc123", "committed_at": "2026-01-02T00:00:00Z"}],
}


class Base(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.fetch = FakeFetch()
        self.server = GistMcpServer(Config("gh-client", "gh-secret", "signing-secret"),
                                    self.fetch, clock=lambda: self.now)

    def request(self, method, path, body="", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        return run(self.server.handle(HttpRequest(method, BASE + path, headers or {}, body)))

    def json_of(self, response):
        return json.loads(response.body)


class DiscoveryTests(Base):
    def test_protected_resource_metadata(self):
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            data = self.json_of(self.request("GET", path))
            self.assertEqual(data["resource"], BASE + "/mcp")
            self.assertEqual(data["authorization_servers"], [BASE])

    def test_authorization_server_metadata(self):
        data = self.json_of(self.request("GET", "/.well-known/oauth-authorization-server"))
        self.assertEqual(data["issuer"], BASE)
        self.assertEqual(data["registration_endpoint"], BASE + "/register")
        self.assertEqual(data["code_challenge_methods_supported"], ["S256"])

    def test_public_base_url_override(self):
        self.server.config.public_base_url = "https://public.example/"
        data = self.json_of(self.request("GET", "/.well-known/oauth-authorization-server"))
        self.assertEqual(data["token_endpoint"], "https://public.example/token")

    def test_cors_preflight(self):
        res = self.request("OPTIONS", "/mcp")
        self.assertEqual(res.status, 204)
        self.assertEqual(res.headers["Access-Control-Allow-Origin"], "*")
        self.assertIn("WWW-Authenticate", res.headers["Access-Control-Expose-Headers"])

    def test_unknown_path_and_wrong_method(self):
        self.assertEqual(self.request("GET", "/nope").status, 404)
        res = self.request("GET", "/mcp")
        self.assertEqual(res.status, 405)
        self.assertEqual(res.headers["Allow"], "POST")
        self.assertEqual(res.body, "")
        self.assertEqual(self.request("PUT", "/mcp").status, 405)


class HomePageTests(Base):
    BROWSER = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

    def test_browser_gets_home_page(self):
        res = self.request("GET", "/", headers=self.BROWSER)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.headers["Content-Type"].startswith("text/html"))
        self.assertIn(f"<code id=\"endpoint\">{BASE}/mcp</code>", res.body)
        self.assertIn("Sign-in ready", res.body)
        self.assertNotIn("Setup incomplete", res.body)
        self.assertIn("github.com/settings/applications", res.body)
        for tool in TOOLS:
            self.assertIn(f"<code>{tool.name}</code>", res.body)
        self.assertNotIn("{{", res.body)

    def test_home_page_flags_missing_configuration(self):
        self.server = GistMcpServer(Config(github_client_id="only-id"), self.fetch)
        body = self.request("GET", "/", headers=self.BROWSER).body
        self.assertIn("Sign-in not configured", body)
        self.assertIn("<code>GITHUB_CLIENT_SECRET</code>", body)
        self.assertIn("<code>SIGNING_SECRET</code>", body)
        self.assertNotIn("<code>GITHUB_CLIENT_ID</code>", body)

    def test_home_page_escapes_and_links_source(self):
        self.server.config.source_url = "https://github.com/me/repo?a=1&b=<x>"
        body = self.request("GET", "/", headers=self.BROWSER).body
        self.assertIn('href="https://github.com/me/repo?a=1&amp;b=&lt;x&gt;"', body)

    def test_programmatic_clients_get_json(self):
        data = self.json_of(self.request("GET", "/"))
        self.assertEqual(data["mcp_endpoint"], BASE + "/mcp")
        self.assertTrue(data["signin_configured"])

    def test_browser_on_mcp_endpoint_is_pointed_home(self):
        res = self.request("GET", "/mcp", headers=self.BROWSER)
        self.assertEqual((res.status, res.headers["Allow"]), (405, "POST"))
        self.assertIn(f'href="{BASE}/"', res.body)


class OAuthTests(Base):
    def register(self, uris=(CLIENT_REDIRECT,)):
        return self.request("POST", "/register", {"redirect_uris": list(uris), "client_name": "Test"})

    def authorize(self, client_id, **overrides):
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
                  "code_challenge": pkce_challenge(VERIFIER), "code_challenge_method": "S256",
                  "state": "client-state"}
        params.update(overrides)
        return self.request("GET", "/authorize?" + urlencode({k: v for k, v in params.items() if v is not None}))

    def sign_in(self):
        """Run register -> authorize -> GitHub callback; return (client_id, code)."""
        client_id = self.json_of(self.register())["client_id"]
        github_state = query_of(self.authorize(client_id).headers["Location"])["state"]
        res = self.request("GET", "/auth/callback?" + urlencode({"code": "gh-code", "state": github_state}))
        return client_id, query_of(res.headers["Location"])["code"]

    def redeem(self, client_id, code, verifier=VERIFIER):
        return self.request("POST", "/token", urlencode({
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
            "redirect_uri": CLIENT_REDIRECT, "code_verifier": verifier}),
            {"Content-Type": "application/x-www-form-urlencoded"})

    def test_full_flow_returns_github_token(self):
        self.fetch.add("POST", "https://github.com/login/oauth/access_token",
                       body={"access_token": "gho_abc", "token_type": "bearer", "scope": "gist"})
        client_id, code = self.sign_in()
        res = self.redeem(client_id, code)
        self.assertEqual(res.status, 200, res.body)
        self.assertEqual(self.json_of(res), {"access_token": "gho_abc", "token_type": "Bearer", "scope": "gist"})
        self.assertEqual(res.headers["Cache-Control"], "no-store")
        sent = query_of("?" + self.fetch.calls[-1]["body"])
        self.assertEqual(sent["client_secret"], "gh-secret")
        self.assertEqual(sent["code"], "gh-code")
        self.assertEqual(sent["redirect_uri"], BASE + "/auth/callback")

    def test_authorize_redirects_to_github(self):
        client_id = self.json_of(self.register())["client_id"]
        res = self.authorize(client_id)
        self.assertEqual(res.status, 302)
        self.assertTrue(res.headers["Location"].startswith("https://github.com/login/oauth/authorize?"))
        q = query_of(res.headers["Location"])
        self.assertEqual(q["client_id"], "gh-client")
        self.assertEqual(q["scope"], "gist")
        self.assertEqual(q["redirect_uri"], BASE + "/auth/callback")

    def test_callback_returns_client_state(self):
        client_id = self.json_of(self.register())["client_id"]
        github_state = query_of(self.authorize(client_id).headers["Location"])["state"]
        res = self.request("GET", "/auth/callback?" + urlencode({"code": "gh-code", "state": github_state}))
        self.assertTrue(res.headers["Location"].startswith(CLIENT_REDIRECT + "?"))
        self.assertEqual(query_of(res.headers["Location"])["state"], "client-state")

    def test_wrong_pkce_verifier_rejected_without_calling_github(self):
        client_id, code = self.sign_in()
        res = self.redeem(client_id, code, verifier="wrong-verifier-" + "y" * 40)
        self.assertEqual(self.json_of(res)["error"], "invalid_grant")
        self.assertEqual(self.fetch.calls, [])

    def test_expired_code_rejected(self):
        client_id, code = self.sign_in()
        self.now += 301
        self.assertEqual(self.json_of(self.redeem(client_id, code))["error"], "invalid_grant")

    def test_code_bound_to_client(self):
        _, code = self.sign_in()
        other_client = self.json_of(self.register(["https://other.example/cb"]))["client_id"]
        self.assertEqual(self.json_of(self.redeem(other_client, code))["error"], "invalid_grant")

    def test_tampered_client_id_rejected(self):
        client_id = self.json_of(self.register())["client_id"]
        res = self.authorize(client_id[:-3] + "xyz")
        self.assertEqual(res.status, 400)

    def test_unregistered_redirect_uri_not_followed(self):
        client_id = self.json_of(self.register())["client_id"]
        res = self.authorize(client_id, redirect_uri="https://evil.example/cb")
        self.assertEqual(res.status, 400)
        self.assertNotIn("Location", res.headers)

    def test_pkce_required(self):
        client_id = self.json_of(self.register())["client_id"]
        res = self.authorize(client_id, code_challenge=None, code_challenge_method=None)
        self.assertEqual(res.status, 302)
        q = query_of(res.headers["Location"])
        self.assertEqual(q["error"], "invalid_request")
        self.assertEqual(q["state"], "client-state")

    def test_github_denial_reported_to_client(self):
        client_id = self.json_of(self.register())["client_id"]
        github_state = query_of(self.authorize(client_id).headers["Location"])["state"]
        res = self.request("GET", "/auth/callback?" + urlencode({"error": "access_denied", "state": github_state}))
        self.assertEqual(query_of(res.headers["Location"])["error"], "access_denied")

    def test_expired_sign_in_state(self):
        client_id = self.json_of(self.register())["client_id"]
        github_state = query_of(self.authorize(client_id).headers["Location"])["state"]
        self.now += 601
        res = self.request("GET", "/auth/callback?" + urlencode({"code": "c", "state": github_state}))
        self.assertEqual(res.status, 400)

    def test_register_validates_redirect_uris(self):
        self.assertEqual(self.register(["http://evil.example/cb"]).status, 400)
        self.assertEqual(self.register(["javascript:alert(1)"]).status, 400)
        self.assertEqual(self.register([]).status, 400)
        for ok in ("http://localhost:6274/cb", "http://127.0.0.1/cb", "myapp://oauth"):
            self.assertEqual(self.register([ok]).status, 201, ok)

    def test_github_token_error_passed_back(self):
        self.fetch.add("POST", "https://github.com/login/oauth/access_token",
                       body={"error": "bad_verification_code", "error_description": "The code is incorrect."})
        client_id, code = self.sign_in()
        data = self.json_of(self.redeem(client_id, code))
        self.assertEqual(data, {"error": "invalid_grant", "error_description": "The code is incorrect."})

    def test_refresh_token_passthrough(self):
        self.fetch.add("POST", "https://github.com/login/oauth/access_token",
                       body={"access_token": "ghu_new", "refresh_token": "ghr_new", "expires_in": 28800})
        res = self.request("POST", "/token", urlencode({"grant_type": "refresh_token", "refresh_token": "ghr_old"}))
        data = self.json_of(res)
        self.assertEqual((data["access_token"], data["refresh_token"], data["expires_in"]),
                         ("ghu_new", "ghr_new", 28800))
        self.assertEqual(query_of("?" + self.fetch.calls[-1]["body"])["refresh_token"], "ghr_old")

    def test_unsupported_grant(self):
        res = self.request("POST", "/token", urlencode({"grant_type": "password"}))
        self.assertEqual(self.json_of(res)["error"], "unsupported_grant_type")

    def test_unconfigured_server(self):
        self.server = GistMcpServer(Config(), self.fetch)
        res = self.register()
        self.assertEqual(res.status, 503)
        self.assertIn("GITHUB_CLIENT_SECRET", self.json_of(res)["error_description"])


class McpTests(Base):
    AUTH = {"Authorization": "Bearer gho_test"}

    def rpc(self, method, params=None, msg_id=1, headers=None):
        message = {"jsonrpc": "2.0", "method": method, "id": msg_id}
        if params is not None:
            message["params"] = params
        return self.request("POST", "/mcp", message, self.AUTH if headers is None else headers)

    def call(self, name, arguments):
        res = self.rpc("tools/call", {"name": name, "arguments": arguments})
        self.assertEqual(res.status, 200, res.body)
        result = self.json_of(res)["result"]
        text = result["content"][0]["text"]
        return result["isError"], (text if result["isError"] else json.loads(text))

    def test_missing_token_challenges_client(self):
        res = self.rpc("initialize", {}, headers={})
        self.assertEqual(res.status, 401)
        self.assertIn(f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"',
                      res.headers["WWW-Authenticate"])

    def test_initialize(self):
        self.fetch.add("GET", API + "/user", body={"login": "octocat"})
        result = self.json_of(self.rpc("initialize", {"protocolVersion": "2025-03-26"}))["result"]
        self.assertEqual(result["protocolVersion"], "2025-03-26")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(self.fetch.calls[0]["headers"]["Authorization"], "Bearer gho_test")
        result = self.json_of(self.rpc("initialize", {"protocolVersion": "1999-01-01"}))["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_revoked_token_triggers_reauth(self):
        self.fetch.add("GET", API + "/user", status=401, body={"message": "Bad credentials"})
        res = self.rpc("initialize", {})
        self.assertEqual(res.status, 401)
        self.assertIn('error="invalid_token"', res.headers["WWW-Authenticate"])

    def test_revoked_token_during_tool_call(self):
        self.fetch.add("GET", API + "/gists", status=401, body={"message": "Bad credentials"})
        self.assertEqual(self.rpc("tools/call", {"name": "list_gists", "arguments": {}}).status, 401)

    def test_notification_accepted(self):
        message = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        res = self.request("POST", "/mcp", message, self.AUTH)
        self.assertEqual((res.status, res.body), (202, ""))

    def test_ping_and_batch(self):
        res = self.request("POST", "/mcp", [
            {"jsonrpc": "2.0", "method": "ping", "id": 1},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "method": "ping", "id": 2},
        ], self.AUTH)
        self.assertEqual([r["id"] for r in self.json_of(res)], [1, 2])

    def test_protocol_errors(self):
        self.assertEqual(self.json_of(self.rpc("resources/list"))["error"]["code"], -32601)
        res = self.json_of(self.rpc("tools/call", {"name": "nope", "arguments": {}}))
        self.assertEqual(res["error"]["code"], -32602)
        res = self.request("POST", "/mcp", "{not json", self.AUTH)
        self.assertEqual((res.status, self.json_of(res)["error"]["code"]), (400, -32700))

    def test_tools_list(self):
        tools = self.json_of(self.rpc("tools/list"))["result"]["tools"]
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {
            "get_current_user", "list_gists", "list_user_gists", "list_starred_gists", "list_public_gists",
            "get_gist", "get_gist_revision", "list_gist_commits", "list_gist_forks", "create_gist",
            "update_gist", "delete_gist", "fork_gist", "star_gist", "unstar_gist", "is_gist_starred"})
        by_name = {t["name"]: t for t in tools}
        self.assertTrue(by_name["delete_gist"]["annotations"]["destructiveHint"])
        self.assertTrue(by_name["get_gist"]["annotations"]["readOnlyHint"])
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
            for req in t["inputSchema"].get("required", []):
                self.assertIn(req, t["inputSchema"]["properties"])
        self.assertEqual(len(TOOLS), len(tools))

    def test_list_gists_paging(self):
        self.fetch.add("GET", API + "/gists", body=[GIST],
                       headers={"link": f'<{API}/gists?page=3>; rel="next"'})
        error, data = self.call("list_gists", {"per_page": 5, "page": 2})
        self.assertFalse(error)
        self.assertTrue(data["has_more"])
        self.assertEqual(data["gists"][0]["files"], [{"filename": "hello.py", "language": "Python", "size": 11}])
        self.assertNotIn("content", json.dumps(data))
        self.assertEqual(query_of(self.fetch.calls[0]["url"]), {"per_page": "5", "page": "2"})

    def test_get_gist_accepts_url(self):
        self.fetch.add("GET", API + "/gists/aa5a315d61ae9438b18d", body=GIST)
        error, data = self.call("get_gist", {"gist_id": "https://gist.github.com/octocat/aa5a315d61ae9438b18d"})
        self.assertFalse(error)
        self.assertEqual(data["files"][0]["content"], "print('hi')")
        self.assertEqual(data["revision_count"], 1)

    def test_invalid_ids_never_reach_github(self):
        for bad in ("../../user", "a b", ""):
            error, text = self.call("get_gist", {"gist_id": bad})
            self.assertTrue(error, bad)
        error, _ = self.call("list_user_gists", {"username": "bad/name"})
        self.assertTrue(error)
        self.assertEqual(self.fetch.calls, [])

    def test_create_gist(self):
        self.fetch.add("POST", API + "/gists", status=201, body=GIST)
        error, data = self.call("create_gist", {"files": {"hello.py": "print('hi')"}, "description": "demo"})
        self.assertFalse(error)
        self.assertEqual(data["id"], GIST["id"])
        self.assertEqual(json.loads(self.fetch.calls[0]["body"]), {
            "files": {"hello.py": {"content": "print('hi')"}}, "public": False, "description": "demo"})

    def test_create_gist_validation(self):
        self.assertTrue(self.call("create_gist", {"files": {}})[0])
        self.assertTrue(self.call("create_gist", {"files": {"a.txt": "   "}})[0])
        self.assertTrue(self.call("create_gist", {"files": {"a/b.txt": "x"}})[0])
        self.assertTrue(self.call("create_gist", {"files": {"a.txt": "x"}, "public": "maybe"})[0])
        self.assertEqual(self.fetch.calls, [])

    def test_update_gist_builds_patch(self):
        self.fetch.add("PATCH", API + "/gists/abc", body=GIST)
        error, _ = self.call("update_gist", {
            "gist_id": "abc", "description": "new", "files": {"a.py": "x = 1"},
            "rename": {"a.py": "b.py", "c.txt": "d.txt"}, "delete_files": ["old.md"]})
        self.assertFalse(error)
        self.assertEqual(json.loads(self.fetch.calls[0]["body"]), {
            "description": "new",
            "files": {"a.py": {"content": "x = 1", "filename": "b.py"},
                      "c.txt": {"filename": "d.txt"}, "old.md": None}})

    def test_update_gist_conflicts_and_empty(self):
        self.assertTrue(self.call("update_gist", {"gist_id": "abc", "files": {"a": "x"}, "delete_files": ["a"]})[0])
        self.assertTrue(self.call("update_gist", {"gist_id": "abc"})[0])
        self.assertEqual(self.fetch.calls, [])

    def test_delete_fork_star(self):
        self.fetch.add("DELETE", API + "/gists/abc", status=204)
        self.fetch.add("POST", API + "/gists/abc/forks", status=201, body=GIST)
        self.fetch.add("PUT", API + "/gists/abc/star", status=204)
        self.fetch.add("DELETE", API + "/gists/abc/star", status=204)
        self.assertEqual(self.call("delete_gist", {"gist_id": "abc"})[1], {"gist_id": "abc", "deleted": True})
        self.assertEqual(self.call("fork_gist", {"gist_id": "abc"})[1]["id"], GIST["id"])
        self.assertTrue(self.call("star_gist", {"gist_id": "abc"})[1]["starred"])
        self.assertFalse(self.call("unstar_gist", {"gist_id": "abc"})[1]["starred"])
        self.assertEqual(self.fetch.calls[2]["body"], "")  # PUT with empty body

    def test_is_gist_starred(self):
        self.fetch.add("GET", API + "/gists/abc/star", status=204)
        self.assertTrue(self.call("is_gist_starred", {"gist_id": "abc"})[1]["starred"])
        self.fetch.add("GET", API + "/gists/abc/star", status=404)
        self.assertFalse(self.call("is_gist_starred", {"gist_id": "abc"})[1]["starred"])

    def test_revisions_commits_forks_user(self):
        self.fetch.add("GET", API + "/gists/abc/abc123", body=GIST)
        self.fetch.add("GET", API + "/gists/abc/commits",
                       body=[{"version": "abc123", "committed_at": "t", "user": {"login": "octocat"},
                              "change_status": {"additions": 1}}])
        self.fetch.add("GET", API + "/gists/abc/forks", body=[GIST])
        self.fetch.add("GET", API + "/users/octocat/gists", body=[GIST])
        self.fetch.add("GET", API + "/user", body={"login": "octocat", "private_gists": 3})
        self.assertFalse(self.call("get_gist_revision", {"gist_id": "abc", "sha": "abc123"})[0])
        self.assertTrue(self.call("get_gist_revision", {"gist_id": "abc", "sha": "not-a-sha"})[0])
        self.assertEqual(self.call("list_gist_commits", {"gist_id": "abc"})[1]["commits"][0]["user"], "octocat")
        self.assertEqual(len(self.call("list_gist_forks", {"gist_id": "abc"})[1]["forks"]), 1)
        self.assertEqual(len(self.call("list_user_gists", {"username": "octocat"})[1]["gists"]), 1)
        self.assertEqual(self.call("get_current_user", {})[1]["private_gists"], 3)

    def test_github_errors_become_tool_errors(self):
        error, text = self.call("get_gist", {"gist_id": "missing"})
        self.assertTrue(error)
        self.assertIn("Not found", text)
        self.fetch.add("GET", API + "/gists", status=403, body={"message": "rate limited"},
                       headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "123"})
        error, text = self.call("list_gists", {})
        self.assertIn("rate limit", text)
        self.assertTrue(self.call("list_gists", {"per_page": 500})[0])


if __name__ == "__main__":
    unittest.main()
