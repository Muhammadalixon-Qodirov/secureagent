"""SARIF 2.1.0 export of a FinalDecision (v6, docs/V6_REJA.md step 9).

SARIF is what GitHub code scanning and most IDEs read. Only what the report already states is
exported: the finding, its evidence lines and the controller's confidence. Rejected hypotheses are
not results; they stay in report.md and final.json.
"""

from __future__ import annotations

from .schemas import FinalDecision

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
         "undetermined": "warning"}
RULES = {
    "CWE-89": ("SqlInjection", "SQL or NoSQL query built from caller-controlled values"),
    "CWE-22": ("PathTraversal", "File operation on a path built from caller-controlled values"),
    "CWE-639": ("BrokenObjectLevelAuthorization", "Object accessed by a caller-supplied id without an ownership check, "
                                                  "or a sensitive operation without authentication"),
}


def to_sarif(final: FinalDecision, version: str = "0") -> dict:
    used = sorted({f.cwe_id for f in final.findings})
    rules = [{"id": c, "name": RULES.get(c, (c, c))[0],
              "shortDescription": {"text": RULES.get(c, (c, c))[1]},
              "helpUri": f"https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html",
              "properties": {"tags": ["security", f"external/cwe/{c.lower()}"]}} for c in used]
    results = []
    for f in final.findings:
        results.append({
            "ruleId": f.cwe_id,
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.source_to_sink}"[:1000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": e.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": e.line_start, "endLine": e.line_end,
                           "snippet": {"text": e.excerpt[:400]}}}} for e in f.evidence[:1]],
            "relatedLocations": [{"physicalLocation": {
                "artifactLocation": {"uri": e.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": e.line_start, "endLine": e.line_end}},
                "message": {"text": e.supports[:200]}} for e in f.evidence[1:5]],
            "partialFingerprints": {"secagent/v1": f"{f.cwe_id}:{f.evidence[0].file}:{f.evidence[0].line_start}"},
            "properties": {"confidence": f.confidence, "confidenceRationale": f.confidence_rationale[:600],
                           "analysisStatus": f.analysis_status, "verificationStatus": f.verification_status},
        })
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "secagent", "version": version, "rules": rules,
                            "informationUri": "https://github.com/Muhammadalixon-Qodirov/secureagent"}},
        "results": results,
        "properties": {"status": final.status, "reviewedPaths": len(final.coverage.reviewed_paths),
                       "note": "Findings are evidence-backed candidates from static review, not proof of exploitability."},
    }]}
