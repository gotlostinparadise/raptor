"""App-layer request/traffic graph — the application twin of :mod:`core.recon`.

Where recon models an organisation's *infrastructure* surface, this subsystem
models its *application* surface: origins, pages, forms, endpoints (as templated
method+path nodes), their parameters, the identities traffic was sent as, and
the vulnerabilities found — with the captured request/response riding on the
graph as evidence. It is the connective tissue between crawl, API-spec import,
and proxy capture: all three feed one ``(type, id)`` merge graph.

The framework is the same four pieces as recon, plus an orchestrator recon
lacks:

  - :mod:`core.webgraph.graph` — the typed ``(type, id)`` graph + JSON/DOT/GraphML.
  - :mod:`core.webgraph.model` — normalised record schema + graph vocabulary.
  - :mod:`core.webgraph.source` — the source-plugin interface, registry, safety
    :class:`~core.webgraph.source.Profile`s (WAF-aware pacing), ``Surface``,
    ``RunContext``, ``SourceResult``.
  - :mod:`core.webgraph.builder` — the pure records → graph function.
  - :mod:`core.webgraph.orchestrator` — the run-loop, ``normalized/*.jsonl``
    persistence, and graph serialisation.

Egress discipline: every outbound HTTP call in a source goes through
:mod:`core.http` with an explicit host allowlist, and browser/subprocess sources
route through the sandbox egress proxy — the same constraints as recon.
"""

__all__ = ["builder", "graph", "model", "orchestrator", "scope", "source"]
