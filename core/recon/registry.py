"""Deterministic source discovery for the recon registry.

``@register`` populates :data:`core.recon.source._REGISTRY` as a side effect of
*importing* a source module — so until something imports every source module,
:func:`core.recon.source.all_sources` is empty and the orchestrator has nothing
to schedule. This module is that "something": :func:`load_sources` imports each
known source module exactly once, in a fixed order, so the registry is fully
populated before a run.

Kept separate from :mod:`core.recon.source` on purpose. ``source.py`` is the
contract and the registry data structure; if it imported the concrete sources
it would create an import cycle (every source imports ``source``) and drag the
whole HTTP/sandbox stack in at contract-import time. The orchestrator CLI calls
:func:`load_sources` once at startup instead.

An import that fails because an *optional* dependency is missing (a tool-wrapper
module that imports something only present in some environments) is tolerated:
the module is skipped and its name recorded, never aborting the whole load. A
genuine bug (SyntaxError, a real ImportError inside our own code) still raises,
because those are not "this source is unavailable here" — they are defects.
"""

from __future__ import annotations

import importlib
from typing import Dict, List, Tuple

# Every source module, in a stable order. Passive (third-party) sources first,
# then the active tool wrappers. Adding a source is one line here plus the
# module — the orchestrator picks it up via ``all_sources()`` automatically.
_SOURCE_MODULES: Tuple[str, ...] = (
    # passive — no traffic to the target's own infrastructure
    "core.recon.crtsh",
    "core.recon.censys",
    "core.recon.subfinder",
    # active — DNS / port / HTTP probes against the target (profile-gated)
    "core.recon.dnsx",
    "core.recon.bruteforce",
    "core.recon.naabu",
    "core.recon.httpx",
    "core.recon.exposed_origin",
    "core.recon.vhost",
)

_loaded = False


def load_sources(force: bool = False) -> Dict[str, List[str]]:
    """Import every source module so the registry is populated.

    Idempotent: the real import work runs once per process unless ``force`` is
    set (tests that manipulate the registry use it to reload). Returns a small
    report ``{"loaded": [...], "skipped": [...]}`` — ``skipped`` names modules
    whose optional dependency was absent, which the caller may surface as a hint.
    """
    global _loaded
    report: Dict[str, List[str]] = {"loaded": [], "skipped": []}
    if _loaded and not force:
        return report
    for mod in _SOURCE_MODULES:
        try:
            importlib.import_module(mod)
            report["loaded"].append(mod)
        except ModuleNotFoundError as exc:
            # A tool wrapper whose optional third-party import is absent. The
            # source simply isn't available in this environment; its own module
            # not existing yet (mid-development) lands here too. Distinguish an
            # absent *sub*dependency from the source module itself being absent:
            # only tolerate the former for our own modules.
            if exc.name and exc.name.startswith("core.recon."):
                # Our own module genuinely missing — a packaging bug. Re-raise so
                # it is loud rather than silently dropping a source.
                raise
            report["skipped"].append(mod)
    _loaded = True
    return report


__all__ = ["load_sources"]
