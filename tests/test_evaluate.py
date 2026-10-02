from secagent.evaluate import Norm, load_holdout, metrics, score_app, wilson


def setup_module():
    global CASES, CWE
    CASES, CWE = load_holdout()


def span(app, case_id):
    c = next(c for c in CASES if c.id == case_id)
    return c.loci[0]


def test_holdout_is_frozen_and_complete():
    assert len(CASES) == 48 and sum(c.vulnerable for c in CASES) == 22


def test_matching_rule_branches():
    f, a, b = span("bookshelf", "B1")
    _, a2, b2 = span("bookshelf", "B2")
    findings = [
        Norm("CWE-89", f, [(a + 3, a + 3)], "tp"),               # B1 vulnerable -> TP
        Norm("CWE-89", f, [(a + 4, a + 4)], "dup"),              # same case again -> duplicate
        Norm("CWE-89", f, [(a2 + 3, a2 + 3)], "lookalike"),      # B2 safe -> FP look-alike
        Norm("CWE-22", f, [(a + 3, a + 3)], "wrong family"),     # no path case there -> FP unmatched
        Norm("CWE-79", f, [(a + 3, a + 3)], "xss"),              # outside MVP families -> out of scope
    ]
    s = score_app("bookshelf", findings, CASES, CWE)
    assert s.tp == ["B1"] and s.fp_safe == ["B2"] and len(s.duplicates) == 1
    assert len(s.fp_unmatched) == 1 and len(s.out_of_scope) == 1
    assert set(s.fn) == {"B4", "B6"}


def test_cross_file_locus_and_line_slack():
    f, a, b = next(l for l in next(c for c in CASES if c.id == "C1").loci if l[0] == "queries.py")
    s = score_app("clinic", [Norm("CWE-89", "queries.py", [(b + 2, b + 2)])], CASES, CWE)
    assert s.tp == ["C1"]                                        # within +2 lines of the helper span
    s = score_app("clinic", [Norm("CWE-89", "queries.py", [(b + 3, b + 3)])], CASES, CWE)
    assert s.tp == [] or s.tp == ["C2"]                          # +3 is outside C1's slack


def test_metrics_and_wilson():
    f, a, b = span("bookshelf", "B1")
    s = score_app("bookshelf", [Norm("CWE-89", f, [(a, a)])], CASES, CWE)
    for x in s.fp_unmatched:
        x["family"] = CWE.get(x["cwe"] or "")
    m = metrics({"bookshelf": s}, [c for c in CASES if c.app == "bookshelf"])
    assert m["sql_injection"]["tp"] == 1 and m["sql_injection"]["precision"] == 1.0
    assert m["micro"]["recall"] == round(1 / 3, 3)
    assert wilson(0, 0) is None and wilson(5, 10) == (0.237, 0.763)
