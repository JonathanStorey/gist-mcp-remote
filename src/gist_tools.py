"""GitHub Gist REST client and the MCP tool catalogue that wraps it.

Standard library only. Outbound HTTP goes through an injected async ``fetch``
callable, so the same code runs on any host (edge isolates, containers, local).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


@dataclass
class FetchResult:
    """Minimal HTTP response returned by a host's fetch implementation."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names
    text: str = ""


# fetch(method, url, headers, body) -> FetchResult
Fetch = Callable[[str, str, dict, "str | None"], Awaitable[FetchResult]]


class GitHubAuthError(Exception):
    """GitHub rejected the access token; the MCP client has to sign in again."""


class GitHubError(Exception):
    """GitHub returned an error other than 401."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ToolInputError(ValueError):
    """Tool arguments failed validation."""


class GitHubClient:
    """Thin GitHub REST client bound to one user's token for one request."""

    def __init__(self, fetch: Fetch, token: str, user_agent: str):
        self._fetch = fetch
        self._token = token
        self._user_agent = user_agent

    async def request(self, method: str, path: str, *, query: dict | None = None,
                      body: Any = None, allow: tuple[int, ...] = ()):
        """Call the API and return ``(status, parsed_json, headers)``.

        ``allow`` lists error statuses the caller handles itself (e.g. 404).
        """
        url = GITHUB_API + path
        params = {k: v for k, v in (query or {}).items() if v is not None}
        if params:
            url += "?" + urlencode(params)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": self._user_agent,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body)
        elif method in ("PUT", "POST", "PATCH"):
            data = ""

        res = await self._fetch(method, url, headers, data)
        if res.status == 401:
            raise GitHubAuthError("GitHub rejected the access token.")
        if res.status >= 400 and res.status not in allow:
            raise GitHubError(res.status, _describe_error(res))
        return res.status, _parse_json(res.text), res.headers


def _parse_json(text: str):
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def _describe_error(res: FetchResult) -> str:
    data = _parse_json(res.text)
    message = data.get("message") if isinstance(data, dict) else None
    if res.status in (403, 429) and res.headers.get("x-ratelimit-remaining") == "0":
        reset = res.headers.get("x-ratelimit-reset", "unknown")
        return f"GitHub API rate limit exceeded (resets at Unix time {reset})."
    if res.status == 404:
        return "Not found: the gist or user does not exist, or this account cannot access it."
    if res.status == 422 and isinstance(data, dict) and data.get("errors"):
        message = f"{message}: {json.dumps(data['errors'])}"
    return f"GitHub API error {res.status}: {message or 'request failed'}"


# --- argument validation ----------------------------------------------------

_GIST_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")
_USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_SHA = re.compile(r"^[0-9a-fA-F]{4,40}$")


def _text_arg(args: dict, key: str, pattern: re.Pattern | None = None,
              required: bool = True) -> str | None:
    value = args.get(key)
    if value is None or value == "":
        if required:
            raise ToolInputError(f"'{key}' is required.")
        return None
    if not isinstance(value, str):
        raise ToolInputError(f"'{key}' must be a string.")
    if pattern and not pattern.match(value):
        raise ToolInputError(f"'{key}' has an invalid format: {value!r}.")
    return value


def _gist_id(args: dict) -> str:
    value = args.get("gist_id")
    if isinstance(value, str) and value.strip().lower().startswith(("https://", "http://")):
        # Accept a full gist URL as well as a bare ID.
        args = {**args, "gist_id": value.strip().rstrip("/").rsplit("/", 1)[-1]}
    return _text_arg(args, "gist_id", _GIST_ID)


def _int_arg(args: dict, key: str, default: int, low: int, high: int | None = None) -> int:
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise ToolInputError(f"'{key}' must be an integer.")
    value = int(value)
    if value < low or (high is not None and value > high):
        bound = f"between {low} and {high}" if high is not None else f"at least {low}"
        raise ToolInputError(f"'{key}' must be {bound}.")
    return value


def _bool_arg(args: dict, key: str, default: bool) -> bool:
    value = args.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ToolInputError(f"'{key}' must be true or false.")


def _optional_str(args: dict, key: str) -> str | None:
    value = args.get(key)
    if value is not None and not isinstance(value, str):
        raise ToolInputError(f"'{key}' must be a string.")
    return value


def _check_filename(name: Any) -> None:
    if not isinstance(name, str) or not name.strip() or "/" in name:
        raise ToolInputError(f"Invalid filename {name!r}: must be non-empty and contain no '/'.")


def _files_arg(args: dict, key: str, required: bool) -> dict[str, str]:
    value = args.get(key)
    if value is None:
        if required:
            raise ToolInputError(f"'{key}' is required.")
        return {}
    if not isinstance(value, dict) or (required and not value):
        raise ToolInputError(f"'{key}' must be an object mapping filename to content.")
    for name, content in value.items():
        _check_filename(name)
        if not isinstance(content, str):
            raise ToolInputError(f"Content of '{name}' must be a string.")
        if not content.strip():
            raise ToolInputError(f"'{name}' has empty content; GitHub does not allow empty files.")
    return value


def _paging(args: dict) -> dict:
    return {"per_page": _int_arg(args, "per_page", 30, 1, 100),
            "page": _int_arg(args, "page", 1, 1)}


def _has_next(headers: dict) -> bool:
    return 'rel="next"' in (headers or {}).get("link", "")


# --- response shaping (keeps tool output compact for the model) -------------

def _gist_summary(g: dict) -> dict:
    files = g.get("files") or {}
    return {
        "id": g.get("id"),
        "description": g.get("description"),
        "public": g.get("public"),
        "owner": (g.get("owner") or {}).get("login"),
        "html_url": g.get("html_url"),
        "created_at": g.get("created_at"),
        "updated_at": g.get("updated_at"),
        "comments": g.get("comments"),
        "files": [{"filename": f.get("filename") or name, "language": f.get("language"),
                   "size": f.get("size")} for name, f in files.items()],
    }


def _gist_detail(g: dict) -> dict:
    out = _gist_summary(g)
    out["files"] = [{
        "filename": f.get("filename") or name,
        "language": f.get("language"),
        "size": f.get("size"),
        "truncated": f.get("truncated", False),
        "raw_url": f.get("raw_url"),
        "content": f.get("content"),
    } for name, f in (g.get("files") or {}).items()]
    if isinstance(g.get("fork_of"), dict):
        out["fork_of"] = g["fork_of"].get("id")
    history = g.get("history") or []
    out["revision_count"] = len(history)
    out["recent_revisions"] = [{"version": h.get("version"), "committed_at": h.get("committed_at")}
                               for h in history[:10]]
    return out


# --- tool registry ----------------------------------------------------------

Handler = Callable[[GitHubClient, dict], Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict
    handler: Handler
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True

    def describe(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": True,
            },
        }


TOOLS: list[Tool] = []


def tool(name: str, title: str, description: str, properties: dict | None = None,
         required: tuple[str, ...] = (), **flags):
    def register(fn: Handler) -> Handler:
        schema = {"type": "object", "properties": properties or {}}
        if required:
            schema["required"] = list(required)
        TOOLS.append(Tool(name, title, description, schema, fn, **flags))
        return fn
    return register


GIST_ID = {"gist_id": {"type": "string",
                       "description": "Gist ID (the hex string at the end of a gist URL). A full gist URL also works."}}
PAGING = {
    "per_page": {"type": "integer", "minimum": 1, "maximum": 100, "default": 30,
                 "description": "Results per page."},
    "page": {"type": "integer", "minimum": 1, "default": 1, "description": "Page number, starting at 1."},
}
SINCE = {"since": {"type": "string", "format": "date-time",
                   "description": "Only gists updated at or after this ISO 8601 timestamp."}}
FILE_MAP = {"type": "object", "additionalProperties": {"type": "string"}}


async def _list_gists(client: GitHubClient, path: str, args: dict) -> dict:
    query = _paging(args)
    query["since"] = _text_arg(args, "since", required=False)
    _, data, headers = await client.request("GET", path, query=query)
    return {"page": query["page"], "has_more": _has_next(headers),
            "gists": [_gist_summary(g) for g in data or []]}


@tool("get_current_user", "Who am I",
      "Show the GitHub account this server is signed in as, with gist counts.")
async def get_current_user(client, args):
    _, data, _ = await client.request("GET", "/user")
    return {k: data.get(k) for k in ("login", "name", "html_url", "public_gists", "private_gists")}


@tool("list_gists", "List my gists",
      "List gists owned by the signed-in user (public and secret), most recently updated first.",
      {**PAGING, **SINCE})
async def list_gists(client, args):
    return await _list_gists(client, "/gists", args)


@tool("list_user_gists", "List a user's public gists",
      "List public gists owned by any GitHub user.",
      {"username": {"type": "string", "description": "GitHub username."}, **PAGING, **SINCE},
      ("username",))
async def list_user_gists(client, args):
    username = _text_arg(args, "username", _USERNAME)
    return await _list_gists(client, f"/users/{username}/gists", args)


@tool("list_starred_gists", "List starred gists",
      "List gists the signed-in user has starred.", {**PAGING, **SINCE})
async def list_starred_gists(client, args):
    return await _list_gists(client, "/gists/starred", args)


@tool("list_public_gists", "List recent public gists",
      "List recently created public gists from across GitHub.", {**PAGING, **SINCE})
async def list_public_gists(client, args):
    return await _list_gists(client, "/gists/public", args)


@tool("get_gist", "Get a gist",
      "Fetch a gist with the contents of its files. Files over about 1 MB come back truncated; "
      "use raw_url for the full content.", GIST_ID, ("gist_id",))
async def get_gist(client, args):
    _, data, _ = await client.request("GET", f"/gists/{_gist_id(args)}")
    return _gist_detail(data)


@tool("get_gist_revision", "Get a gist revision",
      "Fetch a gist as it was at a specific revision (see list_gist_commits).",
      {**GIST_ID, "sha": {"type": "string", "description": "Revision SHA (version)."}},
      ("gist_id", "sha"))
async def get_gist_revision(client, args):
    gist_id, sha = _gist_id(args), _text_arg(args, "sha", _SHA)
    _, data, _ = await client.request("GET", f"/gists/{gist_id}/{sha}")
    return _gist_detail(data)


@tool("list_gist_commits", "List gist revisions",
      "List the revision history of a gist, newest first.", {**GIST_ID, **PAGING}, ("gist_id",))
async def list_gist_commits(client, args):
    query = _paging(args)
    _, data, headers = await client.request("GET", f"/gists/{_gist_id(args)}/commits", query=query)
    return {"page": query["page"], "has_more": _has_next(headers), "commits": [{
        "version": c.get("version"),
        "committed_at": c.get("committed_at"),
        "user": (c.get("user") or {}).get("login"),
        "change_status": c.get("change_status"),
    } for c in data or []]}


@tool("list_gist_forks", "List gist forks",
      "List forks of a gist.", {**GIST_ID, **PAGING}, ("gist_id",))
async def list_gist_forks(client, args):
    query = _paging(args)
    _, data, headers = await client.request("GET", f"/gists/{_gist_id(args)}/forks", query=query)
    return {"page": query["page"], "has_more": _has_next(headers),
            "forks": [_gist_summary(g) for g in data or []]}


@tool("create_gist", "Create a gist",
      "Create a new gist. Gists are secret (unlisted) unless public is true.",
      {
          "files": {**FILE_MAP, "minProperties": 1,
                    "description": "Map of filename to file content, e.g. {\"hello.py\": \"print('hi')\"}."},
          "description": {"type": "string", "description": "Gist description."},
          "public": {"type": "boolean", "default": False,
                     "description": "true for a public gist; false (default) for a secret gist."},
      },
      ("files",), read_only=False, idempotent=False)
async def create_gist(client, args):
    files = _files_arg(args, "files", required=True)
    body = {"files": {name: {"content": content} for name, content in files.items()},
            "public": _bool_arg(args, "public", False)}
    description = _optional_str(args, "description")
    if description is not None:
        body["description"] = description
    _, data, _ = await client.request("POST", "/gists", body=body)
    return _gist_summary(data)


@tool("update_gist", "Update a gist",
      "Change a gist's description, add or overwrite files, rename files, or remove files. "
      "Only the files named are touched.",
      {
          **GIST_ID,
          "description": {"type": "string", "description": "New description."},
          "files": {**FILE_MAP, "description": "Files to add or overwrite: map of filename to full new content."},
          "rename": {**FILE_MAP, "description": "Files to rename: map of current filename to new filename."},
          "delete_files": {"type": "array", "items": {"type": "string"},
                           "description": "Filenames to remove from the gist."},
      },
      ("gist_id",), read_only=False, destructive=True)
async def update_gist(client, args):
    gist_id = _gist_id(args)
    files = _files_arg(args, "files", required=False)
    rename = args.get("rename") or {}
    delete = args.get("delete_files") or []
    if not isinstance(rename, dict):
        raise ToolInputError("'rename' must be an object mapping current filename to new filename.")
    if not isinstance(delete, list):
        raise ToolInputError("'delete_files' must be a list of filenames.")

    changes: dict[str, Any] = {name: {"content": content} for name, content in files.items()}
    for old, new in rename.items():
        _check_filename(old)
        _check_filename(new)
        changes.setdefault(old, {})["filename"] = new
    for name in delete:
        _check_filename(name)
        if name in changes:
            raise ToolInputError(f"'{name}' cannot be both deleted and modified.")
        changes[name] = None

    body: dict[str, Any] = {}
    if changes:
        body["files"] = changes
    description = _optional_str(args, "description")
    if description is not None:
        body["description"] = description
    if not body:
        raise ToolInputError("Nothing to update: give description, files, rename or delete_files.")
    _, data, _ = await client.request("PATCH", f"/gists/{gist_id}", body=body)
    return _gist_summary(data)


@tool("delete_gist", "Delete a gist",
      "Permanently delete a gist owned by the signed-in user. This cannot be undone.",
      GIST_ID, ("gist_id",), read_only=False, destructive=True)
async def delete_gist(client, args):
    gist_id = _gist_id(args)
    await client.request("DELETE", f"/gists/{gist_id}")
    return {"gist_id": gist_id, "deleted": True}


@tool("fork_gist", "Fork a gist",
      "Fork someone else's gist into the signed-in user's account.",
      GIST_ID, ("gist_id",), read_only=False, idempotent=False)
async def fork_gist(client, args):
    _, data, _ = await client.request("POST", f"/gists/{_gist_id(args)}/forks")
    return _gist_summary(data)


@tool("star_gist", "Star a gist", "Star a gist.", GIST_ID, ("gist_id",), read_only=False)
async def star_gist(client, args):
    gist_id = _gist_id(args)
    await client.request("PUT", f"/gists/{gist_id}/star")
    return {"gist_id": gist_id, "starred": True}


@tool("unstar_gist", "Unstar a gist", "Remove a star from a gist.", GIST_ID, ("gist_id",), read_only=False)
async def unstar_gist(client, args):
    gist_id = _gist_id(args)
    await client.request("DELETE", f"/gists/{gist_id}/star")
    return {"gist_id": gist_id, "starred": False}


@tool("is_gist_starred", "Check gist star",
      "Check whether the signed-in user has starred a gist.", GIST_ID, ("gist_id",))
async def is_gist_starred(client, args):
    gist_id = _gist_id(args)
    status, _, _ = await client.request("GET", f"/gists/{gist_id}/star", allow=(404,))
    return {"gist_id": gist_id, "starred": status == 204}


TOOLS_BY_NAME: dict[str, Tool] = {t.name: t for t in TOOLS}
