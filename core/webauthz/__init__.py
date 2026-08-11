"""`/webauthz` — access-control (IDOR/BOLA/BFLA) testing via multi-identity replay.

The #1 web *and* API risk, and the one scanners can't find, because it needs
something only the operator knows: who legitimately owns what. This capability
takes that ground truth (a config of identities + concrete tests), replays each
request as every identity through the :mod:`core.session` engine, and lets the
authorization diff — not an LLM — deliver the verdict. Confirmed breaks become
``PROOF_AUTHZ_DIFF`` findings in the :mod:`core.webgraph` graph and verified
outcomes on the framework's proof surface.

Built entirely on the Phase-A primitives: A3 (session engine + oracle), A4 (the
graph), A5 (verified outcomes). Safe by default — no request is sent without an
explicit ``--active`` flag and a declared authorization attestation.

Pieces: :mod:`core.webauthz.config` (schema + load), :mod:`core.webauthz.runner`
(the oracle engine + gate), :mod:`core.webauthz.template` (seed a config from an
API inventory), :mod:`core.webauthz.report` (render), :mod:`core.webauthz.cli`.
"""

from core.webauthz.config import AuthzConfig, AuthzTest, IdentityConfig, load_config
from core.webauthz.runner import AuthzRun, run_authz

__all__ = [
    "AuthzConfig", "AuthzTest", "IdentityConfig", "load_config",
    "AuthzRun", "run_authz",
]
