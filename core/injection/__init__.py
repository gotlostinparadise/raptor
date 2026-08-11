"""Deep injection testing with real oracles — beyond the OWASP heuristic pass.

Covers SSTI, command injection, SQL injection (error + blind boolean), NoSQL
injection, path traversal, and SSRF (cloud-metadata + blind), with blind
variants (SSRF/XXE/RCE/OOB-SQLi) confirmed out-of-band via :mod:`core.oast`. The
verdict is always a tool's: a *computed* marker echoed back (SSTI/cmd), a
database error signature, a boolean response asymmetry, cloud-metadata content,
or an OAST callback — never an LLM guess. Confirmed findings become proven
:class:`VulnRecord` s + verified outcomes.

Pieces: :mod:`core.injection.markers`, :mod:`core.injection.payloads`,
:mod:`core.injection.oracles`, :mod:`core.injection.config`,
:mod:`core.injection.runner`, :mod:`core.injection.cli`.
"""

from core.injection.config import InjectionConfig, InjectionPoint, load_config
from core.injection.runner import InjectionRun, run_injection

__all__ = [
    "InjectionConfig", "InjectionPoint", "load_config", "InjectionRun",
    "run_injection",
]
