# remote-serverless-gist-mcp

A remote [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants manage your **GitHub Gists**. Users sign in with **GitHub in the browser**. There are no personal access tokens to copy and paste.

- **Pure Python, standard library only.** It runs on serverless Python isolates (Pyodide), in containers, or on a laptop.
- **Stateless.** There's no database: every request is self-contained, so it scales horizontally for free.
- **Follows the MCP authorization spec** (OAuth 2.1, PKCE, Dynamic Client Registration and protected-resource metadata), so clients such as Claude can connect with just the URL.

## Tools

| Tool | What it does | GitHub API |
| --- | --- | --- |
| `get_current_user` | Who am I, plus gist counts | `GET /user` |
| `list_gists` | My gists, public and secret | `GET /gists` |
| `list_user_gists` | Any user's public gists | `GET /users/{user}/gists` |
| `list_starred_gists` | Gists I starred | `GET /gists/starred` |
| `list_public_gists` | Recent public gists on GitHub | `GET /gists/public` |
| `get_gist` | One gist, including file contents | `GET /gists/{id}` |
| `get_gist_revision` | A gist at a past revision | `GET /gists/{id}/{sha}` |
| `list_gist_commits` | Revision history | `GET /gists/{id}/commits` |
| `list_gist_forks` | Forks of a gist | `GET /gists/{id}/forks` |
| `create_gist` | New gist (secret by default) | `POST /gists` |
| `update_gist` | Edit description; add, overwrite, rename or remove files | `PATCH /gists/{id}` |
| `delete_gist` ⚠️ | Permanent delete (flagged as destructive) | `DELETE /gists/{id}` |
| `fork_gist` | Fork into my account | `POST /gists/{id}/forks` |
| `star_gist` / `unstar_gist` | Star or unstar | `PUT` / `DELETE /gists/{id}/star` |
| `is_gist_starred` | Check star | `GET /gists/{id}/star` |

List tools take `per_page` (1–100), `page` and, where GitHub supports it, `since`. They return `has_more` so the assistant knows when to fetch the next page. Gist IDs can be given as bare IDs or as full gist URLs.

## How sign-in works

```
MCP client                 This server                         GitHub
    │  POST /mcp (no token)    │                                  │
    │ ◄── 401 + WWW-Authenticate (points at metadata)             │
    │  GET /.well-known/...    │                                  │
    │  POST /register ───────► │ client_id = signed redirect URIs │
    │  browser: /authorize ──► │ ── 302 ───────────────────────► │ user approves "gist" scope
    │                          │ ◄── /auth/callback?code ──────── │
    │ ◄── 302 redirect_uri?code=(signed, 5 min) ─                 │
    │  POST /token + PKCE ───► │ ── exchange code + secret ────► │
    │ ◄── access_token (the user's GitHub token) ◄─────────────── │
    │  POST /mcp  Bearer … ──► │ ── GitHub REST API calls ─────► │
```

- **Token passthrough.** The bearer token the client holds *is* the user's GitHub OAuth token, scoped to `gist` only. The server never stores it. It lives only for the duration of each request.
- **Stateless OAuth.** Client registrations, sign-in state and authorization codes are HMAC-signed values (keyed by `SIGNING_SECRET`), with short expiry times. These values are signed, not encrypted: they contain no secrets, and the GitHub code inside one can't be redeemed without the server's client secret.
- **Expired or revoked tokens.** If GitHub rejects a token, the server answers `401` with `error="invalid_token"`, and the MCP client signs the user in again.
- **Revoking access.** Users revoke access at <https://github.com/settings/applications>. The server keeps no token list, so it can't revoke tokens itself.
- **Rotating `SIGNING_SECRET`** invalidates existing client registrations; clients simply register again.

## Setup

### 1. Create a GitHub OAuth App

Go to GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**:

- **Homepage URL:** `https://YOUR-HOST`
- **Authorization callback URL:** `https://YOUR-HOST/auth/callback`

Copy the **Client ID**, then generate a **Client secret**. Use a separate OAuth App for local development, with the callback `http://localhost:8787/auth/callback`.

### 2. Configuration

| Name | Kind | Purpose |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | variable | OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | **secret** | OAuth App client secret |
| `SIGNING_SECRET` | **secret** | Random string, 32+ bytes, for signing OAuth values |
| `PUBLIC_BASE_URL` | optional | Public URL, if it differs from the URL requests arrive on |
| `SOURCE_URL` | optional | Link to the source code, shown on the home page |

Generate a signing secret with one of these:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

```bash
openssl rand -hex 32
```

### 3. Deploy (wrangler-based Python runtime)

`wrangler.toml` points at `src/main.py`.

1. Put your client ID in `[vars]`.
2. Set the secrets:

   ```bash
   npx wrangler secret put GITHUB_CLIENT_SECRET
   ```

   ```bash
   npx wrangler secret put SIGNING_SECRET
   ```

3. Deploy:

   ```bash
   npx wrangler deploy
   ```

For local runs with `npx wrangler dev`, create a git-ignored `.dev.vars` file with `GITHUB_CLIENT_SECRET=...` and `SIGNING_SECRET=...`.

### 4. Check the deployment

Open `https://YOUR-HOST/` in a browser. The home page confirms the server is running and shows whether sign-in is configured. If anything is missing, it lists which settings to add. It also shows the MCP address to copy, how to connect, why users sign in with GitHub, and the available tools. Clients that don't ask for HTML get a short JSON status from the same URL instead.

### 5. Connect a client

The MCP endpoint is **`https://YOUR-HOST/mcp`**.

- **Claude (web, desktop or mobile):** go to Customize → Connectors → *Add custom connector*, paste the URL, leave *Advanced settings* empty, then click *Add*, *Connect* and approve on GitHub.
- **MCP Inspector:** run `npx @modelcontextprotocol/inspector`, choose transport *Streamable HTTP*, and enter the URL.
- **Any other client** that supports remote MCP servers with OAuth works the same way.

## Running elsewhere

All the logic is in `src/server.py`, `src/gist_tools.py` and `src/home_page.py`, written against three plain types: `HttpRequest`, `HttpResponse` and an async `fetch(method, url, headers, body)` function. Hosting it somewhere new means writing a small adapter:

- `src/main.py` is the adapter for Pyodide edge isolates.
- `src/local_server.py` is a standard-library adapter (uses `http.server` and `urllib`) that runs anywhere Python 3.11+ runs:

```bash
python src/local_server.py 8787
```

It reads `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` and `SIGNING_SECRET` from the environment.

## Tests

The tests use the standard library only, and GitHub is faked in memory:

```bash
python -m unittest discover -s tests -v
```

`pytest` also works.

## Layout

```
src/main.py          host adapter (edge runtime entry point)
src/local_server.py  host adapter (standard-library HTTP server)
src/server.py        OAuth endpoints, MCP JSON-RPC, routing, CORS
src/gist_tools.py    GitHub REST client and tool definitions
src/home_page.py     browser home page at the root URL
tests/test_server.py unit tests
wrangler.toml        deployment manifest
```

## License

MIT. See [LICENSE](LICENSE).
