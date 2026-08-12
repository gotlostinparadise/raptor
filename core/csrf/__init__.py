"""CSRF (anti-CSRF-token absence) detection (M4 S5).

Replays a state-changing request first WITH its anti-CSRF token (a valid
baseline) and then with the token FIELD REMOVED. If the server still performs the
operation without the token, it does not validate an anti-CSRF token on that
request — a confirmed CSRF weakness (CWE-352,
:data:`core.webgraph.model.PROOF_STATE_ORACLE`). A token-less request that is
rejected means the token is enforced — no finding.
"""

from __future__ import annotations

from core.csrf.strip import strip_token

__all__ = ["strip_token"]
