# EduPage MCP

A local, read-only MCP server for EduPage school messages and PDF attachments. It uses a browser-authenticated session stored in the **macOS login keychain** and exposes four narrowly scoped tools over stdio. It is not affiliated with or endorsed by EduPage/Asc.

This is a technical integration for one locally configured parent account. EduPage's observed web endpoints are not a documented public API; they can change without notice. The server does not promise a complete message archive or verified child attribution.

## What it provides

| Tool | Result |
| --- | --- |
| `auth_status` | Checks whether the saved session still works. |
| `list_messages(since)` | Lists IDs, dates, content versions and attachment counts in a requested window of at most 90 days. |
| `get_message(message_id)` | Returns the full text and attachment references for an ID from the latest listing. For messages that request a read receipt, the body comes from the timeline data instead of EduPage's "open the message" placeholder, and `receipt_requested` is `true`. No receipt is sent. |
| `get_attachment(message_id, reference)` | Returns a known PDF as Base64, up to 2 MB. |

All tools are read-only at the MCP level. EduPage itself may record that a message or document was viewed. The returned school content is untrusted input, including any instructions it may contain. There are no free-form URL, password, cookie, school-switching, send-message or write tools.

## Requirements

- macOS with its login keychain and Google Chrome
- Python 3.12 or newer (the implementation uses the macOS Security framework)
- Node.js for the **separate, interactive browser sign-in**
- Network access to your school's `*.edupage.org` site
- An EduPage account you are authorized to use

The MCP server itself is local and communicates through stdio. It does not listen on a public port.

## Install

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm install --no-save playwright
```

Keep this checkout private on your computer. The project `.gitignore` excludes local environments, keychain-related runtime files, `.env`, browser state, and logs. Never add real school data, cookies, tokens or credentials to a Git commit.

Set your EduPage account name as a **nonsecret local label**. Use your actual school subdomain in later commands (for `https://example.edupage.org`, use `example`):

```sh
export EDUPAGE_USERNAME='your-edupage-account-name'
```

If you prefer, place only `EDUPAGE_USERNAME=...` in a local `.env`; this file is ignored by Git. Never put `EDUPAGE_PASSWORD` there or in the environment. The implementation rejects that setting. The browser sign-in handles the password and any second factor directly in EduPage.

## Sign in once through Chrome

```sh
node scripts/probes/edupage_browser_login.cjs example
```

The script opens a fresh isolated Chrome context. Sign in on EduPage and complete its normal two-factor prompt there. When EduPage reaches its account page, the script verifies the session through the connector, saves only the session cookies to the macOS keychain under the service `family-operation-system`, then closes Chrome. Cookies travel to Python through a process pipe; no HAR, screenshot, browser profile or cookie file is produced. macOS may ask for your Mac login-keychain password in a system dialog. Enter it there, never in a chat or project file.

If `.venv/bin/python` is not your desired interpreter, set `EDUPAGE_MCP_PYTHON` to the absolute interpreter path for this sign-in command.

The saved session is account- and school-bound. An expired session returns `AUTH_REQUIRED`; repeat the browser sign-in. This is a browser-session workflow, **not OAuth**. No password or second-factor code is requested by an MCP tool.

## Connect an MCP client

Configure your local MCP client to start this program from the repository root:

```json
{
  "command": "/absolute/path/to/edupage-mcp/.venv/bin/python",
  "args": ["-m", "src.edupage_mcp", "--school", "example"],
  "cwd": "/absolute/path/to/edupage-mcp"
}
```

The client process must have `EDUPAGE_USERNAME` set or run from a checkout with the local `.env` described above. Do not place a password or cookie in the MCP configuration. The standalone server disables interactive keychain dialogs so a headless client fails with a visible `KEYCHAIN_ACCESS_REQUIRED` status instead of waiting forever. If macOS asks during the explicit browser sign-in, grant access there.

Some attachments redirect to EduPage CDN hosts. The connector accepts only the school host and an explicit allowlist of `*.edupage.org` PDF download hosts. If a known attachment returns `UNSAFE_REDIRECT`, inspect its destination before adding its exact host:

```sh
.venv/bin/python -m src.edupage_mcp --school example --download-host cloud-4.edupage.org
```

`cloud-4.edupage.org` is an **example**, not a universal requirement. Never add an arbitrary external host just to make a download succeed.

To remove the local keychain session (this does not revoke the server-side EduPage session):

```sh
.venv/bin/python -m src.edupage_mcp --school example --forget-session
```

## Verify

Offline tests use synthetic data only:

```sh
.venv/bin/python -m pip install pytest==8.3.3
.venv/bin/python -m pytest -q tests
node --check scripts/probes/edupage_browser_login.cjs
```

After signing in, this optional live probe starts two independent MCP processes and prints only statuses and aggregate counts; it never prints message text or PDF content:

```sh
.venv/bin/python scripts/probes/edupage_mcp_probe.py --school example --since 2026-09-01
```

Choose a `--since` date within the last 90 days and add individually approved `--download-host` values if needed. A successful old test does not establish ongoing portal compatibility or complete source coverage.

## Security and operational limits

- Single local account and school per server process. There is no multi-family permission model or hosted authentication layer.
- The macOS keychain service name is `family-operation-system`, retained for compatibility with existing local FOS sessions. Secrets are never persisted in this repository.
- An MCP client receives private school text and PDFs. Only connect clients you trust to handle that data. The server labels source content as untrusted, but the consuming agent must still resist prompt injection.
- The `list_messages` window is limited to 90 days. An empty result does not prove there were no messages outside that window or in other EduPage modules.
- Attachment responses are limited to 2 MB through MCP. Larger PDFs yield `ATTACHMENT_TOO_LARGE_FOR_MCP`.
- Portal changes, expired sessions, keychain access rules and EduPage CDN hosts can interrupt access. There is no automatic sign-in or background synchronization in this repository.

If you discover a vulnerability, use GitHub's private security reporting for this repository rather than posting credentials or family content in a public issue.
