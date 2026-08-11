"""WAF-aware pacing + evasion — the cross-cutting defensive-lessons layer.

Two utilities the active web commands lean on:

  - :mod:`core.waf.detect` — fingerprint a WAF from response headers/cookies/body
    so the operator knows the pacing envelope (rate limits, IP bans) they're up
    against, mirroring recon's edge-provider fingerprinting at the request layer.
  - :mod:`core.waf.evasion` — encode/mutate a payload into WAF-bypass variants;
    the injection runner can resend each and keep whichever the oracle still
    confirms.

Rate/concurrency pacing itself lives on the web-graph safety
:class:`~core.webgraph.source.Profile` (``rps``/``concurrency``/``waf_evasion``
knobs), so this module is detection + payload transforms.
"""

from core.waf import detect, evasion   # submodules (do not shadow with functions)
from core.waf.detect import detect_from_response, is_block
from core.waf.evasion import mutations

__all__ = ["detect", "evasion", "detect_from_response", "is_block", "mutations"]
