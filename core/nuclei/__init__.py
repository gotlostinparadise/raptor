"""Nuclei integration + tech→CVE correlation — cheap, high-signal coverage.

Two capabilities that reuse fingerprints RAPTOR already has:

  - :mod:`core.nuclei.techcve` — cross-reference the recon graph's ``tech`` nodes
    against a curated CVE table (offline; results are *suspected* indicators).
  - :mod:`core.nuclei.wrapper` — run the optional ``nuclei`` binary (sandboxed,
    egress-allowlisted) and ingest its matches as *confirmed* findings.

Degrades gracefully when nuclei is absent — the tech→CVE pass still runs. Pieces:
:mod:`core.nuclei.config`, :mod:`core.nuclei.runner`, :mod:`core.nuclei.cli`.
"""

from core.nuclei.config import NucleiConfig, load_config
from core.nuclei.runner import NucleiRun, run_nuclei_scan

__all__ = ["NucleiConfig", "load_config", "NucleiRun", "run_nuclei_scan"]
