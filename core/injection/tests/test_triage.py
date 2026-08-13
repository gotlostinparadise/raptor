"""Tests for core.injection.triage — the mechanical pre-score + LLM ranking (T1).

The triage layer only *selects and orders* (point, class) pairs; a mechanical
oracle still decides findings. These tests pin the safety-relevant properties:
deterministic mechanical scoring, static-asset drop, coverage-preserving LLM
fallback (invented ids ignored, omitted pairs appended), and the flywheel prior.
"""

import json

from core.injection.config import InjectionPoint
from core.injection.triage import mechanical_score, triage_points

_CLASSES = ["ssti", "cmdi", "sqli", "nosqli", "path_traversal", "xss",
            "ssrf_metadata"]


def _pt(path, param, location="query", content_type="form"):
    return InjectionPoint(method="GET", path=path, param=param,
                          location=location, content_type=content_type)


def test_static_asset_scores_zero_for_every_class():
    asset = _pt("/assets/app.js", "v")
    for cls in _CLASSES:
        score, reason = mechanical_score(asset, cls)
        assert score == 0.0, cls
        assert "asset" in reason


def test_search_param_outranks_id_param_for_sqli():
    # N8 (found in the N4 authenticated Juice Shop run): a search/query param is
    # prime SQLi surface and must rank at/above an id param, else a budget is
    # spent on non-injectable /resource?id= endpoints before reaching the real one.
    search = mechanical_score(_pt("/rest/products/search", "q"), "sqli")[0]
    idp = mechanical_score(_pt("/api/Addresss", "id"), "sqli")[0]
    assert search > idp
    # same for nosqli
    assert (mechanical_score(_pt("/rest/products/search", "q"), "nosqli")[0]
            >= mechanical_score(_pt("/api/Addresss", "id"), "nosqli")[0])


def test_mechanical_score_rewards_plausible_signals():
    # file/path param on a download path is a strong path-traversal candidate.
    strong = mechanical_score(_pt("/download", "file"), "path_traversal")[0]
    weak = mechanical_score(_pt("/home", "colour"), "path_traversal")[0]
    assert strong > weak
    # a url-ish param is a strong SSRF candidate.
    assert mechanical_score(_pt("/proxy", "url"), "ssrf")[0] > 0.7


def test_triage_is_deterministic_and_mechanical_without_a_model():
    pts = [_pt("/rest/products/search", "q"), _pt("/assets/x.css", "v"),
           _pt("/download", "file")]
    a = triage_points(pts, _CLASSES, llm_model=None, target="http://t")
    b = triage_points(pts, _CLASSES, llm_model=None, target="http://t")
    assert a.order == b.order            # reproducible
    assert a.llm_used is False
    # the asset point is fully dropped (no selected class), so it is not walked.
    assert a.classes_for(_pt("/assets/x.css", "v")) == []
    labels = [p.label for p in a.ordered_points(pts)]
    assert "GET /assets/x.css [query:v]" not in labels
    # the file/download point (highest score) is walked before the search point.
    assert labels[0] == "GET /download [query:file]"


def test_llm_ranking_ignores_invented_and_preserves_coverage(monkeypatch):
    pts = [_pt("/a", "id"), _pt("/b", "q")]
    classes = ["sqli", "xss"]

    mech = triage_points(pts, classes, llm_model=None, target="http://t")
    all_pairs = set(mech.order)
    # pick a real pair to promote and forge an invented one the model "returns"
    promoted = mech.order[-1]                     # a lower-ranked real pair
    promoted_key = f"{promoted[0]} :: {promoted[1]}"

    def fake_rank(survivors, target, model):
        return [f"{promoted_key}", "TOTALLY :: invented"], "forced", False

    monkeypatch.setattr("core.injection.triage._llm_rank_pairs", fake_rank)
    plan = triage_points(pts, classes, llm_model="stub-model", target="http://t")

    assert plan.llm_used is True
    assert plan.order[0] == promoted               # model's real pick floats up
    assert set(plan.order) == all_pairs            # coverage preserved
    assert ("TOTALLY", "invented") not in plan.order   # invented pair ignored


def test_llm_failure_degrades_to_mechanical(monkeypatch):
    pts = [_pt("/a", "id"), _pt("/b", "q")]
    classes = ["sqli", "xss"]
    mech = triage_points(pts, classes, llm_model=None, target="http://t")

    def boom(*a, **k):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr("core.injection.triage._llm_rank_pairs", boom)
    plan = triage_points(pts, classes, llm_model="stub", target="http://t")
    assert plan.llm_used is False
    assert plan.order == mech.order                # unchanged mechanical order
    assert any("LLM ranking failed" in n for n in plan.notes)


def test_flywheel_prior_promotes_a_previously_confirmed_class(tmp_path):
    fb = tmp_path / "feedback.jsonl"
    with fb.open("w", encoding="utf-8") as fh:
        for _ in range(2):
            fh.write(json.dumps({"entry_id": "builtin:sqli", "vuln_class": "sqli",
                                 "technique": "error", "target": "http://t",
                                 "timestamp": "x"}) + "\n")
    # a param with no class-specific signal: sqli and ssti tie mechanically…
    pts = [_pt("/x", "foo")]
    plan = triage_points(pts, ["sqli", "ssti"], llm_model=None, target="http://t",
                         feedback=str(fb))
    # …so the flywheel prior (2 prior sqli confirmations) breaks the tie for sqli.
    assert plan.order[0] == ("GET /x [query:foo]", "sqli")


def test_plan_to_dict_round_trips_decisions():
    pts = [_pt("/download", "file"), _pt("/assets/x.js", "v")]
    plan = triage_points(pts, ["sqli", "path_traversal"], llm_model=None,
                         target="http://t")
    d = plan.to_dict()
    assert d["selected_pairs"] >= 1 and d["rejected_pairs"] >= 1
    assert json.dumps(d)                             # serialisable for the run dir
    assert all({"point", "class", "score", "selected"} <= set(dec)
               for dec in d["decisions"])
