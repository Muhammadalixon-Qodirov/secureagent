import copy
import json

import pytest
from pydantic import ValidationError

from secagent.schemas import ActionDecision, FinalDecision, parse_decision

EV = {"file": "app/views.py", "line_start": 10, "line_end": 12, "tool_event_id": "E3"}


def action(**over):
    d = {"kind": "action", "tool": "read_file",
         "arguments": {"path": "app/views.py", "start_line": 1, "end_line": 80},
         "hypothesis_id": "H001",
         "hypothesis_update": {"id": "H001", "family": "sql_injection", "analysis_status": "inconclusive"},
         "purpose": "Does the q parameter reach cursor.execute?"}
    d.update(over)
    return d


FINDING = {
    "id": "F001", "hypothesis_ids": ["H001"], "title": "SQL built from request parameter",
    "cwe_id": "CWE-89", "analysis_status": "candidate", "verification_status": "not_run",
    "severity": "high", "severity_rationale": "unauthenticated read of all notes",
    "confidence": "medium", "confidence_rationale": "single-function flow, no sanitizer seen",
    "entrypoint": "GET /search", "source_to_sink": "request.args['q'] -> f-string -> db.execute",
    "trust_boundary": "HTTP request -> database", "controls": [], "preconditions": [],
    "impact": "read arbitrary rows",
    "evidence": [{**{k: EV[k] for k in ("file", "line_start", "line_end", "tool_event_id")},
                  "excerpt": "db.execute(f\"...{q}...\")", "supports": "query string built from q"}],
    "counterevidence": [], "sources": [{"id": "card-sql_injection#sinks", "title": "SQLi card", "url": None, "version": None}],
    "verification": {"method": None, "event_ids": [], "observations": [], "limits": []},
    "remediation": "use a ? placeholder", "regression_tests": ["quote in q is literal"], "unknowns": [],
}


def final(**over):
    d = {"kind": "final", "status": "complete", "findings": [copy.deepcopy(FINDING)],
         "coverage": {"reviewed_paths": ["app/views.py"], "reviewed_entrypoints": ["GET /search"], "checks": [],
                      "hypotheses": [{"id": "H001", "question": "q reaches SQL?", "analysis_status": "candidate",
                                      "verification_status": "not_run", "reason": "flow observed", "finding_id": "F001"}],
                      "omitted_areas": []},
         "limitations": [], "hypothesis_updates": []}
    d.update(over)
    return d


def test_valid_action_parses():
    assert isinstance(parse_decision(json.dumps(action())), ActionDecision)


def test_valid_final_parses():
    assert isinstance(parse_decision(json.dumps(final())), FinalDecision)


def test_inventory_action_with_null_ids():
    d = action(hypothesis_id=None, hypothesis_update=None)
    assert parse_decision(json.dumps(d)).hypothesis_id is None


def test_update_id_must_match_hypothesis():
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(action(hypothesis_update={"id": "H002"})))


def test_inventory_action_cannot_carry_update():
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(action(hypothesis_id=None)))


def test_unknown_top_level_key_is_rejected():
    # e.g. a model trying to slip in a policy change
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(action(enabled_tools=["shell"])))


def test_unknown_kind_is_rejected():
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(action(kind="shell")))


def test_findings_must_be_candidates():
    f = final()
    f["findings"][0]["analysis_status"] = "rejected"
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(f))


def test_not_run_with_stray_observations_parses():
    # cleared by the controller (test_agent), not a schema error: see T05 run 5
    f = final()
    f["findings"][0]["verification"]["observations"] = ["code uses string formatting"]
    assert parse_decision(json.dumps(f)).findings[0].verification.observations


def test_reproduced_requires_lab_event():
    f = final()
    f["findings"][0]["verification_status"] = "reproduced"
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(f))


def test_finding_requires_evidence():
    f = final()
    f["findings"][0]["evidence"] = []
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(f))


def test_reversed_line_range_is_rejected():
    f = final()
    f["findings"][0]["evidence"][0]["line_start"] = 20
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(f))


def test_bad_cwe_format_is_rejected():
    f = final()
    f["findings"][0]["cwe_id"] = "SQLi"
    with pytest.raises(ValidationError):
        parse_decision(json.dumps(f))


def test_trace_edge_uses_from_key():
    upd = {"id": "H001", "trace_edges": [{"from": EV, "to": {**EV, "line_start": 30, "line_end": 30},
                                          "relation": "argument flows to", "status": "observed"}]}
    d = parse_decision(json.dumps(action(hypothesis_update=upd)))
    assert d.hypothesis_update.trace_edges[0].from_.line_start == 10


def test_malformed_json_is_rejected():
    with pytest.raises(ValidationError):
        parse_decision('{"kind": "action", "tool": ')
