"""Client-side / configuration weaknesses — CORS, CSP, clickjacking, cookies,
open redirect.

Mostly read straight off the wire: a reflected CORS origin, an ``unsafe-inline``
CSP, a framable page (no X-Frame-Options / frame-ancestors), a cookie missing
``Secure``/``HttpOnly``/``SameSite``, or a redirect parameter that sends the user
to an external host. The analyzers are pure functions over HTTP metadata; the
runner feeds them real probe responses and records confirmed misconfigurations as
proven ``vuln`` nodes.

Pieces: :mod:`core.clientside.analyzers` (pure), :mod:`core.clientside.config`,
:mod:`core.clientside.runner`, :mod:`core.clientside.cli`.
"""

from core.clientside.config import ClientSideConfig, load_config
from core.clientside.runner import ClientSideRun, run_clientside

__all__ = ["ClientSideConfig", "load_config", "ClientSideRun", "run_clientside"]
