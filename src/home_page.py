"""The human-readable page served at the server's root URL in a browser.

Confirms the deployment is live, shows the address to give an MCP client, and
explains why connecting asks the user to sign in with GitHub.
"""

from __future__ import annotations

from html import escape

from gist_tools import TOOLS

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitHub Gists MCP Server</title>
<style>
:root{--bg:#f6f8fa;--card:#fff;--text:#1f2328;--muted:#59636e;--border:#d1d9e0;--accent:#0969da;
--ok:#1a7f37;--warn:#9a6700;--danger:#cf222e;--code:#eff2f5}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#151b23;--text:#e6edf3;--muted:#9198a1;
--border:#3d444d;--accent:#4493f8;--ok:#3fb950;--warn:#d29922;--danger:#f85149;--code:#212830}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",
Helvetica,Arial,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 16px 56px}
h1{font-size:1.8rem;margin:0 0 6px}
h2{font-size:1.15rem;margin:0 0 10px}
section{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;margin:16px 0}
.status{display:flex;flex-wrap:wrap;gap:8px 18px;color:var(--muted);font-size:.95rem;margin:0 0 4px}
.dot{font-weight:600}.ok{color:var(--ok)}.warn{color:var(--warn)}
.lead{font-size:1.05rem}
.endpoint{display:flex;gap:8px;align-items:stretch}
.endpoint code{flex:1;min-width:0;overflow-wrap:anywhere;padding:10px 12px;font-size:.95rem}
code{background:var(--code);border-radius:6px;padding:1px 6px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
button{font:inherit;cursor:pointer;border:1px solid var(--border);background:var(--accent);color:#fff;border-radius:6px;
padding:0 16px}
a{color:var(--accent)}
li{margin:6px 0}
.notice{border-color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:8px 6px;border-top:1px solid var(--border);vertical-align:top}
th{border-top:0;color:var(--muted);font-weight:600}
td:first-child{white-space:nowrap}
.badge{display:inline-block;font-size:.75rem;border:1px solid currentColor;border-radius:999px;padding:0 8px;
white-space:nowrap}
.b-read{color:var(--ok)}.b-write{color:var(--warn)}.b-destructive{color:var(--danger)}
footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:24px}
@media (max-width:560px){td:nth-child(2){display:none}th:nth-child(2){display:none}}
</style>
</head>
<body>
<main>
<h1>GitHub Gists MCP Server</h1>
<p class="status"><span class="dot ok">&#9679; Running</span><span>Version {{VERSION}}</span>{{SIGNIN_STATUS}}</p>
<p class="lead">This is a remote <a href="https://modelcontextprotocol.io">Model Context Protocol</a> server.
It lets AI assistants such as Claude list, read, create, edit and delete your GitHub Gists.
There is nothing to do on this page: give the address below to your AI assistant.</p>
{{CONFIG_NOTICE}}
<section>
<h2>Server address</h2>
<div class="endpoint"><code id="endpoint">{{ENDPOINT}}</code><button id="copy" type="button">Copy</button></div>
</section>
<section>
<h2>How to connect</h2>
<ol>
<li><strong>Claude</strong> (web, desktop and mobile): open <em>Customize &rarr; Connectors &rarr; Add custom
connector</em>, paste the address above, leave <em>Advanced settings</em> empty, click <em>Add</em>, then
<em>Connect</em>.</li>
<li><strong>Other MCP clients:</strong> add a remote server with the <em>Streamable HTTP</em> transport and the
address above. Clients that support MCP sign-in will open GitHub for you.</li>
<li>Approve the request on GitHub. You return to your assistant, ready to go.</li>
</ol>
</section>
<section>
<h2>Why you sign in with GitHub</h2>
<ul>
<li>Your gists belong to your GitHub account, so your assistant needs your permission to work with them.
Connecting opens GitHub's own sign-in page, so this server never sees your password.</li>
<li>GitHub asks you to approve the <code>gist</code> permission. It lets the assistant read and change your gists,
including secret ones. It does not give access to your repositories or account settings.</li>
<li>The resulting access token is held by your AI assistant. This server uses it only while handling each request
and never stores it.</li>
<li>You can revoke access at any time at
<a href="https://github.com/settings/applications">github.com/settings/applications</a>.</li>
</ul>
</section>
<section>
<h2>Available tools</h2>
<table>
<thead><tr><th>Tool</th><th>What it does</th><th>Effect</th></tr></thead>
<tbody>
{{TOOL_ROWS}}
</tbody>
</table>
</section>
<footer>{{FOOTER}}</footer>
</main>
<script>
document.getElementById("copy").addEventListener("click", function () {
  var button = this;
  navigator.clipboard.writeText(document.getElementById("endpoint").textContent).then(function () {
    button.textContent = "Copied";
    setTimeout(function () { button.textContent = "Copy"; }, 1500);
  });
});
</script>
</body>
</html>
"""


def _tool_row(tool) -> str:
    if tool.destructive:
        badge = '<span class="badge b-destructive">Changes or deletes</span>'
    elif not tool.read_only:
        badge = '<span class="badge b-write">Makes changes</span>'
    else:
        badge = '<span class="badge b-read">Read-only</span>'
    return (f"<tr><td><code>{escape(tool.name)}</code></td>"
            f"<td>{escape(tool.description)}</td><td>{badge}</td></tr>")


def render_home_page(endpoint: str, version: str, missing_config: list[str], source_url: str = "") -> str:
    if missing_config:
        signin_status = '<span class="dot warn">&#9679; Sign-in not configured</span>'
        notice = ('<section class="notice"><h2>Setup incomplete</h2><p>The server is running, but sign-in will fail '
                  "until the operator sets: " + ", ".join(f"<code>{escape(n)}</code>" for n in missing_config)
                  + ".</p></section>")
    else:
        signin_status = '<span class="dot ok">&#9679; Sign-in ready</span>'
        notice = ""
    footer = "Open source, MIT licensed."
    if source_url:
        footer += f' <a href="{escape(source_url)}">Source code</a>'
    replacements = {
        "{{VERSION}}": escape(version),
        "{{SIGNIN_STATUS}}": signin_status,
        "{{CONFIG_NOTICE}}": notice,
        "{{ENDPOINT}}": escape(endpoint),
        "{{TOOL_ROWS}}": "\n".join(_tool_row(t) for t in TOOLS),
        "{{FOOTER}}": footer,
    }
    page = _PAGE
    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)
    return page


def render_endpoint_notice(home_url: str) -> str:
    """Shown when someone opens the MCP endpoint itself in a browser."""
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>MCP endpoint</title>"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>"
            "<body style=\"font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px\">"
            "<h1>This is an MCP endpoint</h1><p>It is meant for AI assistants, not browsers. "
            f"See <a href=\"{escape(home_url)}\">the home page</a> for how to connect.</p></body></html>")
