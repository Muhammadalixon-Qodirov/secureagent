"""v5: deterministic injection-sink scan (secagent/sinks.py). No model, no framework knowledge."""

from secagent.authz import _classify
from secagent.sinks import scan

APP = '''
import os
import sqlite3
from pathlib import Path

BASE = Path("/srv/exports")


def report(request):
    ref = request.GET.get("ref", "daily")
    return (BASE / ref).read_text()


def stored(request, doc_id):
    doc = load_document(doc_id)
    return open(os.path.join(BASE, doc.stored_name)).read()


def safe(request):
    name = os.path.basename(request.GET["name"])
    return open(os.path.join(BASE, name)).read()


def find_user(conn, username):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % username).fetchone()


def find_user_bound(conn, username):
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchone()


def by_id(conn, request):
    uid = int(request.args["id"])
    return conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()


def banner():
    return open(os.path.join(os.path.dirname(__file__), "banner.txt")).read()


class Download:
    def get(self, name):
        with open("/srv/files/" + name) as fh:
            return fh.read()
'''

SCRIPT = '''import sys
from sqlalchemy import text
name = input('user: ')
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
def lookup(session, request):
    q = request.args.get('q')
    return session.execute(text(f"SELECT * FROM notes WHERE body LIKE '%{q}%'")).all()
'''


def test_scan_seeds_request_and_parameter_values_only():
    seeds = {s.func: s for s in scan({"app.py": APP})}
    assert set(seeds) == {"report", "find_user", "get"}
    assert seeds["report"].family == "path_traversal" and seeds["report"].priority == 0
    assert seeds["find_user"].family == "sql_injection" and seeds["find_user"].priority == 1   # parameter
    assert seeds["get"].priority == 0                       # HTTP-verb method: its parameters are the request


def test_scan_reads_module_level_scripts_and_wrapped_sql():
    seeds = scan({"script.py": SCRIPT})
    assert [(s.func, s.line, s.family) for s in seeds] == [("<module>", 4, "sql_injection"), ("lookup", 7, "sql_injection")]


def test_scan_skips_seed_scripts_and_unparsable_files():
    assert scan({"app/management/commands/load.py": APP, "broken.py": "def x(:\n"}) == []


def test_boolean_credential_gate_is_authentication():
    body = ('def _gate(request):\n'
            '    secret = os.environ.get("OPS_TOKEN")\n'
            '    return bool(secret and request.headers.get("x-internal-token") == secret)\n')
    assert _classify(body, set(), v5=True) == "login"
    assert _classify(body, set()) is None                   # v4 behaviour is unchanged
