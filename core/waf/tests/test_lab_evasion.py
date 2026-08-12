"""End-to-end WAF-evasion validation (N3): a real loopback WAF-fronted vulnerable
server. run_injection must NOT confirm without adapt (raw keyword payloads are
403'd), and MUST confirm with adapt (an evasion-encoded variant slips the WAF and
reaches the vulnerable backend) — real sockets, real UrllibClient. Closes the
"evasion is unit-proven only" gap.
"""

from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.waf.lab import WafLab

_AUTH = "authorized loopback lab"


def _cfg(url, **extra):
    d = {"base_url": url, "authorization": _AUTH,
         "points": [{"method": "GET", "path": "/", "param": "q",
                     "location": "query"}],
         "classes": ["sqli"]}
    d.update(extra)
    return from_dict(d)


def test_waf_blocks_raw_but_evasion_confirms_end_to_end(tmp_path):
    with WafLab() as lab:
        # raw: every keyword-bearing payload is 403'd → nothing confirms
        r0 = run_injection(_cfg(lab.url), out_dir=tmp_path / "raw", active=True)
        assert not any(f["class"] == "sqli" for f in r0.findings)
        # adapt: an evasion-encoded variant slips the WAF, hits the backend, and
        # the mechanical oracle confirms — over real sockets.
        r1 = run_injection(_cfg(lab.url, adapt=True), out_dir=tmp_path / "adapt",
                           active=True)
        assert any(f["class"] == "sqli" and f.get("proof") for f in r1.findings)


def test_waf_lab_blocks_raw_keyword_and_allows_evasion():
    # unit-level sanity on the lab's WAF rule itself
    from core.waf.lab import _blocked
    assert _blocked("1' OR '1'='1") is True          # bare keyword → blocked
    assert _blocked("1' oR '1'='1") is False         # mixed-case → allowed
    assert _blocked("1'/**/OR/**/'1'='1") is False   # comment-split → allowed
