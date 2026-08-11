"""App-layer content discovery — the surface a crawl alone misses.

Mines a target's JavaScript for endpoints and (redacted) leaked secrets, probes a
curated list of sensitive paths (`.git`, `.env`, backups, framework debug
endpoints) with content signatures, and recovers source maps. Discovered
endpoints feed the web graph; secrets, exposed files, and source-map leaks become
proven findings. Secrets are never stored verbatim — only a redacted preview + a
fingerprint — so a finding cannot itself leak the credential.

Pieces: :mod:`core.discovery.extractors` (pure), :mod:`core.discovery.probes`,
:mod:`core.discovery.config`, :mod:`core.discovery.runner`, :mod:`core.discovery.cli`.
"""

from core.discovery.config import DiscoveryConfig, load_config
from core.discovery.runner import DiscoveryRun, run_discovery

__all__ = ["DiscoveryConfig", "load_config", "DiscoveryRun", "run_discovery"]
