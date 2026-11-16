"""Offline tests: MCP protocol over stdio, Classroom and Gmail tools against canned Google responses.

Run: python3 tests/test_classroom.py
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fixtures():
    d = json.loads((ROOT / "tests" / "fixtures.json").read_text())
    soon = datetime.now(timezone.utc) + timedelta(days=3)
    for cw in d["/v1/courses/111/courseWork"]["courseWork"]:
        cw["dueDate"] = {"year": soon.year, "month": soon.month, "day": soon.day}
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(d, f)
    f.close()
    return f.name


def rpc(messages, env_extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GOOGLE_")}
    env.update(env_extra)
    env["CLASSROOM_MCP_HOME"] = tempfile.mkdtemp()
    p = subprocess.run([sys.executable, "-I", str(ROOT / "classroom_mcp.py")], input="".join(json.dumps(m) + "\n" for m in messages),
                       capture_output=True, text=True, env=env, timeout=30)
    out = {}
    for line in p.stdout.splitlines():
        r = json.loads(line)
        out[r["id"]] = r
    return out


def call(i, name, args=None):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}


def text(r):
    return r["result"]["content"][0]["text"]


def main():
    fx = fixtures()
    r = rpc([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"},
             {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
             call(3, "gc_courses"), call(4, "gc_upcoming", {"days": 7}), call(5, "gc_coursework", {"course": "bio"}),
             call(6, "gc_announcements", {"course": "biology"}), call(7, "gmail_search", {"query": "is:unread"}),
             call(8, "gmail_read", {"message_id": "m100"}), call(9, "gmail_thread", {"thread_id": "t100"}),
             call(10, "gmail_labels"), call(11, "gmail_read", {"message_id": "../../evil"}), call(12, "gc_status"),
             call(13, "nope"), {"jsonrpc": "2.0", "id": 14, "method": "ping"}], {"CLASSROOM_MCP_FAKE": fx})

    assert r[1]["result"]["serverInfo"]["name"] == "google-classroom-gmail"
    names = {t["name"] for t in r[2]["result"]["tools"]}
    assert names == {"gc_status", "gc_courses", "gc_upcoming", "gc_coursework", "gc_announcements", "gc_materials",
                     "gmail_search", "gmail_read", "gmail_thread", "gmail_labels"}, names
    assert all(t["annotations"]["readOnlyHint"] for t in r[2]["result"]["tools"])
    assert [c["name"] for c in json.loads(text(r[3]))] == ["Year 12 Biology", "Year 12 History"]
    up = json.loads(text(r[4]))
    assert [u["title"] for u in up] == ["Mitosis essay"] and up[0]["status"] == "CREATED", up
    cw = json.loads(text(r[5]))
    assert cw["course"] == "Year 12 Biology" and cw["coursework"][0]["topic"] == "Unit 3 - Cell Biology"
    assert json.loads(text(r[6]))["announcements"][0]["text"] == "Test on Friday!"

    s = json.loads(text(r[7]))
    assert s["count"] == 2 and s["more"] is True
    assert s["messages"][0]["subject"] == "Exam" and s["messages"][0]["unread"] is True
    assert s["messages"][0]["snippet"] == 'Exam moved to "Friday"'
    m = json.loads(text(r[8]))
    assert m["body"] == "Exam moved to Friday.\nRoom 101.", m["body"]  # text/plain wins over html
    assert m["attachments"] == [{"filename": "rules.pdf", "mimeType": "application/pdf", "size": 1234}]
    t = json.loads(text(r[9]))
    assert len(t["messages"]) == 2
    html_body = t["messages"][1]["body"]
    assert html_body == "Thanks & see you\n\n Bye" or ("Thanks & see you" in html_body and "p{}" not in html_body), html_body
    assert {lb["name"] for lb in json.loads(text(r[10]))} == {"INBOX", "Uni"}
    assert r[11]["result"]["isError"] and "Invalid message id" in text(r[11])
    st = json.loads(text(r[12]))
    assert st["signed_in"] and st["classroom"] and st["gmail"], st
    assert r[13]["result"]["isError"]
    assert r[14]["result"] == {}

    # Google can grant coursework.me under its alias student-submissions.me.
    sys.path.insert(0, str(ROOT))
    import classroom_mcp as gc
    alias = " ".join(s for s in gc.CLASSROOM_SCOPES if "coursework.me" not in s) + \
        " https://www.googleapis.com/auth/classroom.student-submissions.me.readonly"
    assert gc._covers(alias, gc.CLASSROOM_SCOPES) and not gc._covers(alias, gc.GMAIL_SCOPES)

    # No credentials at all: tools report login_required instead of crashing.
    r = rpc([call(1, "gc_courses"), call(2, "gc_status")], {})
    assert json.loads(text(r[1]))["login_required"] is True
    assert json.loads(text(r[2]))["signed_in"] is False

    # Unknown CLI command exits non-zero.
    p = subprocess.run([sys.executable, "-I", str(ROOT / "classroom_mcp.py"), "bogus"], capture_output=True, text=True)
    assert p.returncode != 0
    print("ok")


if __name__ == "__main__":
    main()
