"""Tech → known-CVE correlation over the recon graph's fingerprints.

The recon graph already carries ``tech`` nodes (server software, frameworks,
libraries observed during fingerprinting). This cross-references them against a
curated table of well-known, high-signal CVEs. A version match is an *indicator*,
not a proof — so these findings are recorded as **suspected** (no oracle ran), to
be confirmed by `/inject`, a nuclei template, or manual work. That honesty is the
point: we never mark a version-string guess as verified.

The table is intentionally small and high-signal (the flagship CVE per widely
deployed technology); it is a starting set, not a vulnerability database.
"""

from __future__ import annotations

import re
from typing import Dict, List


# name (lowercased) -> advisories. ``affected`` is a list of version prefixes an
# empty list means "any version observed" (presence alone is the signal).
TECH_CVE: Dict[str, List[dict]] = {
    "log4j": [{"cve": "CVE-2021-44228", "severity": "critical",
               "title": "Log4Shell — JNDI RCE", "affected": ["2."]}],
    "struts": [{"cve": "CVE-2017-5638", "severity": "critical",
                "title": "Apache Struts2 OGNL RCE", "affected": []}],
    "openssl": [{"cve": "CVE-2014-0160", "severity": "high",
                 "title": "Heartbleed memory disclosure", "affected": ["1.0.1"]}],
    "jquery": [{"cve": "CVE-2020-11022", "severity": "medium",
                "title": "jQuery htmlPrefilter XSS", "affected": ["1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4"]}],
    "bootstrap": [{"cve": "CVE-2019-8331", "severity": "medium",
                   "title": "Bootstrap tooltip/popover XSS", "affected": ["3.", "4.0", "4.1", "4.2"]}],
    "spring": [{"cve": "CVE-2022-22965", "severity": "critical",
                "title": "Spring4Shell RCE", "affected": []}],
    "wordpress": [{"cve": "CVE-2022-21661", "severity": "high",
                   "title": "WordPress WP_Query SQLi", "affected": []}],
    "drupal": [{"cve": "CVE-2018-7600", "severity": "critical",
                "title": "Drupalgeddon2 RCE", "affected": ["7.", "8."]}],
    "php": [{"cve": "CVE-2019-11043", "severity": "critical",
             "title": "PHP-FPM underflow RCE", "affected": ["7."]}],
    "nginx": [{"cve": "CVE-2013-2028", "severity": "high",
               "title": "nginx chunked stack overflow", "affected": ["1.3", "1.4"]}],
    "apache": [{"cve": "CVE-2021-41773", "severity": "high",
                "title": "Apache path traversal / RCE", "affected": ["2.4.49", "2.4.50"]}],
}

# A version is a *dotted* numeric string — requiring the dot stops a bare digit
# inside a product name (log4j, oauth2, md5) from being mistaken for a version.
_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)*)")


def split_tech(s: str):
    """``"nginx/1.18.0"`` → ``("nginx", "1.18.0")``; ``"jQuery 3.4"`` → ``("jquery","3.4")``.

    The version is the first dotted-numeric run; the name is the rest,
    lowercased. Names with embedded digits (``log4j``) survive because the
    version must contain a dot.
    """
    s = (s or "").strip()
    m = _VERSION_RE.search(s)
    version = m.group(1) if m else ""
    name = (s[: m.start()] + s[m.end():]) if m else s
    name = name.strip(" /:-").lower()
    return name, version


def _matches(version: str, affected: List[str]) -> bool:
    """Component-wise prefix match: ``"1.3"`` matches ``"1.3.9"`` but not ``"1.30"``."""
    if not affected:
        return True
    vcomp = version.split(".")
    for pfx in affected:
        pcomp = pfx.rstrip(".").split(".")
        if vcomp[: len(pcomp)] == pcomp:
            return True
    return False


def correlate(tech_strings: List[str]) -> List[dict]:
    """Return advisory findings for ``tech_strings`` (from graph ``tech`` nodes).

    Matches a CVE-table key as a substring of the (lowercased) fingerprint — so
    ``"log4j-core-2.17.1.jar"`` still hits the ``log4j`` entry — and, when the
    entry declares affected versions, only reports it if a parsed version
    component-matches. An entry with a version constraint but no parseable
    version is skipped (can't substantiate the indicator).
    """
    out: List[dict] = []
    seen = set()
    for raw in tech_strings:
        low = (raw or "").lower()
        m = _VERSION_RE.search(raw or "")
        version = m.group(1) if m else ""
        for name, advs in TECH_CVE.items():
            if name not in low:
                continue
            for adv in advs:
                if adv["affected"]:
                    if not version or not _matches(version, adv["affected"]):
                        continue
                if (name, adv["cve"]) in seen:
                    continue
                seen.add((name, adv["cve"]))
                out.append({"tech": raw, "name": name, "version": version,
                            "cve": adv["cve"], "severity": adv["severity"],
                            "title": adv["title"]})
    return out


def tech_from_graph(graph_json: dict) -> List[str]:
    """Extract ``tech`` node ids (and any ``tech`` attrs) from a recon graph JSON."""
    out: List[str] = []
    for node in (graph_json.get("nodes") or []):
        if node.get("type") == "tech":
            out.append(node.get("label") or node.get("id", "").split(":", 1)[-1])
        for t in (node.get("tech") or []):
            out.append(t)
    return sorted(set(x for x in out if x))


__all__ = ["TECH_CVE", "split_tech", "correlate", "tech_from_graph"]
