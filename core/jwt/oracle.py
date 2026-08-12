"""The forged-token-accepted oracle — a mechanical verdict, not a guess.

A forged JWT is only a finding when three observations line up on a protected
endpoint:

  1. **baseline** — the *real* token is accepted (a 2xx), proving the endpoint is
     genuinely protected and reachable with valid auth;
  2. **negative control** — a token with a *corrupted signature* is **rejected**,
     proving the endpoint actually validates tokens (an endpoint that accepts
     anything is broken auth, not a JWT forgery, and must not be reported here);
  3. **forgery** — our forged token is **accepted**.

Only when (1) ∧ ¬(2) ∧ (3) hold is the forgery confirmed: the server treated a
token we controlled as authentic. Acceptance is a 2xx; rejection is anything else
(401/403 typically). This mirrors the authz-diff and OAST oracles — the tool, not
the model, decides.
"""

from __future__ import annotations

from typing import Optional


def is_accepted(status: Optional[int]) -> bool:
    """A 2xx means the endpoint served the protected resource for this token."""
    return status is not None and 200 <= status < 300


def forgery_confirmed(baseline_status: Optional[int],
                      control_status: Optional[int],
                      forged_status: Optional[int]) -> bool:
    """True iff the A/B/control triple proves the server accepted the forgery."""
    return (is_accepted(baseline_status)
            and not is_accepted(control_status)
            and is_accepted(forged_status))


__all__ = ["is_accepted", "forgery_confirmed"]
