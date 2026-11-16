# classroom-mcp (Classroom + Gmail, headless fork)

A read-only [MCP](https://modelcontextprotocol.io) server for a student's **Google Classroom** and **Gmail**, built to
run on a server (for example in [Obot](https://obot.ai)) without a browser.

Fork of [Mattlo0546/classroom-mcp](https://github.com/Mattlo0546/classroom-mcp) (MIT). Changes from upstream:

- Credentials come from environment variables, and the access token is kept in memory only.
- **No Google Drive access**: the slide download and sync tools are removed.
- Adds **read-only Gmail** tools (`gmail.readonly`: it can't send, delete, or mark mail as read).
- Tool ids are validated before they go into a request URL, and in-flight calls finish when stdin closes.

It is still a single Python file with no dependencies, and it only talks to `accounts.google.com`,
`oauth2.googleapis.com`, `classroom.googleapis.com` and `gmail.googleapis.com`.

## Tools

| Tool | What it does |
| --- | --- |
| `gc_status` | Signed in or not, which account, whether Classroom and Gmail are allowed |
| `gc_courses` | Active courses |
| `gc_upcoming` | Assignments due in the next N days (default 14) across all courses, with submission status |
| `gc_coursework` | Every assignment in one course: due date, status, grade, description, attachments |
| `gc_announcements` | Recent stream posts in one course |
| `gc_materials` | Class materials in one course, grouped by topic |
| `gmail_search` | Search mail with Gmail syntax (`is:unread newer_than:7d`, `from:prof@uni.edu`) |
| `gmail_read` | One email: headers, text body, attachment list |
| `gmail_thread` | A whole conversation |
| `gmail_labels` | Labels |

## Setup

### 1. Google OAuth client (once)

1. [Google Cloud Console](https://console.cloud.google.com/): create or pick a project. A personal Gmail account
   is fine; it doesn't have to be the school account.
2. APIs & Services → Library: enable **Google Classroom API** and **Gmail API**.
3. Google Auth Platform → Audience: **External**, and add the school address under **Test users**. Then press
   **Publish app** so the sign-in doesn't expire every 7 days (it stays private; you'll see an "unverified app"
   warning once).
4. Clients → Create client → **Desktop app** → download the JSON to `~/.config/classroom-mcp/client_secret.json`.

### 2. Sign in on your own computer (once)

```bash
uvx --from git+https://github.com/zxsleebu/classroom-mcp.git@<commit> classroom-mcp login
# without mail:      … classroom-mcp login --no-gmail
```

A browser opens: choose the school account and allow access. The token lands in
`~/.config/classroom-mcp/token.json`; its `refresh_token` is what the server needs.

If Google says *"Access blocked: … not approved by your admin"* / *"admin_policy_enforced"*, the school blocks
third-party apps. Gmail is a "restricted" scope, so try `--no-gmail`: some schools allow Classroom but not mail.

### 3. Run it

Environment variables:

| Variable | Value |
| --- | --- |
| `GOOGLE_OAUTH_CLIENT_ID` | `client_id` from the client JSON |
| `GOOGLE_OAUTH_CLIENT_SECRET` | `client_secret` from the client JSON |
| `GOOGLE_REFRESH_TOKEN` | `refresh_token` from `token.json` |
| `TZ` (optional) | e.g. `Europe/Warsaw`, for due dates in local time (otherwise UTC) |

Command: `classroom-mcp` (stdio). Without the variables it falls back to the local `client_secret.json` and
`token.json`, so `claude mcp add classroom -- classroom-mcp` works on your own computer too.

## Security notes

- Email and announcement text is written by other people. An AI client can be steered by text inside a message
  (prompt injection), so be careful about giving the same agent tools that send messages elsewhere.
- Revoke access any time at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).

## Development

```bash
python3 tests/test_classroom.py   # offline: MCP protocol and all tools against canned Google responses
```

MIT licensed. Not affiliated with Google.
