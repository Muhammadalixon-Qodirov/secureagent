# demo_app — expected results (dev/demo only, not an evaluation set)

Kept outside `targets/demo_app/` (the authorized root) so the agent cannot read it.

| Location | Issue | Expected |
|---|---|---|
| `notes_by_tag` / `GET /notes/tag` | SQL built with `%` from request `tag`, through a helper | **SQLi, CWE-89** (cross-function: Semgrep CE misses it) |
| `find_notes` / `GET /notes/search` | `ORDER BY` concatenation, but `order` is allow-listed in the route; `q` is bound | **not** a vulnerability |
| `GET /notes/<id>` | looks up by id without owner check (`@login_required` only) | **IDOR, CWE-639** |
| `DELETE /notes/<id>` | filters by `owner_id = current_user.id` | **not** a vulnerability |
| `GET /reports/<path:name>` | `send_file(os.path.join(REPORTS_DIR, name))` | **path traversal, CWE-22** |
| `GET /exports/<path:name>` | `send_from_directory` | **not** a vulnerability |
