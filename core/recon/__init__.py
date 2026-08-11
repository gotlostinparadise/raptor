"""Infrastructure-recon subsystem — sources, graph, and normalised model.

RAPTOR's recon pipeline discovers and enriches an organisation's external
attack surface (domains, subdomains, IPs, ASNs, services, TLS certs, edge/WAF
providers) and assembles it into a typed graph.

The framework is three pieces:

  - :mod:`core.recon.graph` — the typed ``(type, id)`` asset graph and its
    JSON / DOT / GraphML exporters.
  - :mod:`core.recon.model` — the normalised record schema (one dataclass per
    record kind) and the graph vocabulary (node types, edge relations).
  - :mod:`core.recon.source` — the source-plugin interface. Every source
    declares its egress hosts, credential env vars, active/passive nature, and
    I/O kinds, then implements ``run(ctx) -> SourceResult``. The orchestrator
    schedules registered sources under a safety :class:`~core.recon.source.Profile`.

The engine that schedules sources lives in :mod:`core.recon.orchestrator`
(the discovery loop + record persistence + graph serialisation);
:mod:`core.recon.registry` imports every source module so the registry is
populated before a run; :mod:`core.recon.cli` backs ``/recon``.

Sources (each a :class:`~core.recon.source.Source`):

  - Passive (no traffic to the target): :mod:`core.recon.crtsh` (Certificate
    Transparency), :mod:`core.recon.censys` (Censys Platform asset lookups,
    free-tier compatible), :mod:`core.recon.subfinder` (passive-API aggregator).
  - Active (target-touching, profile-gated): :mod:`core.recon.dnsx` (resolve),
    :mod:`core.recon.bruteforce` (wordlist DNS bruteforce), :mod:`core.recon.naabu`
    (port scan), :mod:`core.recon.httpx` (HTTP probe), :mod:`core.recon.exposed_origin`
    (WAF-bypass origin discovery), :mod:`core.recon.vhost` (Host-header vhosts).

Active sources shell out to external binaries; :mod:`core.recon.toolrunner`
holds the two sandbox modes (egress-proxy for HTTP tools, network-open /
read-restricted for DNS/port tools) and the offline-test injection seam.

Egress discipline: every outbound HTTP call the passive sources make goes
through :mod:`core.http` with an explicit hostname allowlist, so recon traffic is
constrained by the same in-process proxy as the rest of RAPTOR, and a
compromised parser cannot exfiltrate off the declared host set.
"""

__all__ = [
    "builder", "bruteforce", "censys", "cli", "crtsh", "dnsx", "exposed_origin",
    "graph", "httpx", "model", "naabu", "orchestrator", "probe", "registry",
    "scope", "source", "subfinder", "toolrunner", "vhost", "webbridge",
]
