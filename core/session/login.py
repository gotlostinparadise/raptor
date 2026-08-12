"""Login strategies — how an :class:`~core.session.identity.Identity` gets a
session.

Each strategy implements :meth:`LoginStrategy.apply(engine, identity)` and marks
the identity authenticated. The set that ships covers the cases a pentest
actually hits first:

  - :class:`BearerAuth` / :class:`ApiKeyAuth` — *bring your own token*. In
    practice you obtain a JWT/OAuth access token out of band (or via the
    provider's own flow) and inject it; this is the most common real path and
    the substrate every richer OAuth/OIDC/SAML strategy reduces to once it has a
    token.
  - :class:`BasicAuth` — HTTP Basic.
  - :class:`FormLogin` — POST credentials to a login endpoint and let the
    engine capture the resulting session cookie.

Full interactive OAuth2/OIDC/SAML dances are additional :class:`LoginStrategy`
subclasses (one file each) that end by calling ``identity.set_bearer(...)`` or
seeding a cookie — they slot in without touching the engine.

Credentials are read from the environment by name (never hard-coded), matching
recon's ``credential_env_vars`` discipline; :func:`resolve_credential` is the
single lookup point.
"""

from __future__ import annotations

import abc
import base64
import json
import os
import re
from typing import Any, Dict, Mapping, Optional

from core.http import Response
from core.session.identity import Identity


def resolve_credential(env_var: str, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Resolve a credential by env-var name from ``env`` (defaults to os.environ)."""
    source = env if env is not None else os.environ
    val = source.get(env_var)
    return val or None


class LoginStrategy(abc.ABC):
    """Establish a session for an identity. Returns the login :class:`Response`
    (or ``None`` for header-only strategies that send no request)."""

    @abc.abstractmethod
    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        raise NotImplementedError


class BearerAuth(LoginStrategy):
    """Inject a bearer token (JWT/OAuth access token obtained out of band)."""

    def __init__(self, token: str) -> None:
        self.token = token

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        identity.set_bearer(self.token)
        identity.authenticated = True
        return None


class ApiKeyAuth(LoginStrategy):
    """Inject an API key as a fixed header (e.g. ``X-API-Key``)."""

    def __init__(self, header: str, value: str) -> None:
        self.header = header
        self.value = value

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        identity.set_api_key(self.header, self.value)
        identity.authenticated = True
        return None


class BasicAuth(LoginStrategy):
    """HTTP Basic auth."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        raw = f"{self.username}:{self.password}".encode("utf-8")
        identity.auth_headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        identity.authenticated = True
        return None


class FormLogin(LoginStrategy):
    """POST credentials to a login endpoint; capture the session cookie.

    ``fields`` is the credential body (form-encoded by default, JSON when
    ``as_json=True``). ``success`` decides whether the login worked (default:
    status < 400). The engine folds any ``Set-Cookie`` into the identity's jar,
    so subsequent requests as this identity are authenticated.
    """

    def __init__(
        self,
        login_url: str,
        fields: Dict[str, str],
        *,
        method: str = "POST",
        as_json: bool = False,
        success=None,
    ) -> None:
        self.login_url = login_url
        self.fields = fields
        self.method = method.upper()
        self.as_json = as_json
        self.success = success or (lambda r: r.status < 400)

    def _encode(self) -> tuple:
        if self.as_json:
            return json.dumps(self.fields).encode("utf-8"), "application/json"
        from urllib.parse import urlencode
        return urlencode(self.fields).encode("utf-8"), "application/x-www-form-urlencoded"

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        body, content_type = self._encode()
        resp = engine.request(
            identity.name, self.method, self.login_url,
            body=body, headers={"Content-Type": content_type},
            follow_redirects=False,
        )
        identity.authenticated = bool(self.success(resp))
        return resp


def _parse_json_body(resp) -> Any:
    body = getattr(resp, "body", b"") or b""
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _dig(obj: Any, dot_path: str) -> Any:
    """Follow a dot-path (``authentication.token``) into nested dicts, or None."""
    cur = obj
    for key in dot_path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


class JsonLogin(LoginStrategy):
    """POST JSON credentials, extract a token from the JSON response, set a header.

    The auth pattern for token/JWT APIs — e.g. OWASP Juice Shop:
    ``POST /rest/user/login`` → ``{"authentication": {"token": "<JWT>"}}``.
    ``token_path`` is a dot-path into the response JSON (default
    ``"authentication.token"``); the extracted token is injected as
    ``Authorization: Bearer <token>`` (override with ``header`` / ``scheme``).
    Unlike :class:`FormLogin` (which relies on a ``Set-Cookie``), this reads the
    token from the response *body*, which is where JWT APIs return it.
    """

    def __init__(
        self,
        login_url: str,
        fields: Dict[str, str],
        *,
        token_path: str = "authentication.token",
        header: str = "Authorization",
        scheme: str = "Bearer",
    ) -> None:
        self.login_url = login_url
        self.fields = fields
        self.token_path = token_path
        self.header = header
        self.scheme = scheme

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        body = json.dumps(self.fields).encode("utf-8")
        resp = engine.request(
            identity.name, "POST", self.login_url, body=body,
            headers={"Content-Type": "application/json"}, follow_redirects=False,
        )
        token = _dig(_parse_json_body(resp), self.token_path)
        if token:
            value = f"{self.scheme} {token}".strip() if self.scheme else str(token)
            identity.auth_headers[self.header] = value
            identity.authenticated = True
        else:
            identity.authenticated = False
        return resp


_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(
    r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")


def _tag_attrs(tag: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag):
        val = m.group(2)
        if val is None:
            val = m.group(3)
        if val is None:
            val = m.group(4) or ""
        attrs[m.group(1).lower()] = val
    return attrs


def extract_input_value(html: str, name: str) -> Optional[str]:
    """Value of the first ``<input>`` whose ``name`` matches ``name``.

    Used to scrape a per-session hidden anti-CSRF token (e.g. DVWA's
    ``user_token``) out of a server-rendered login page so it can be echoed on
    submit. Attribute order/quoting-agnostic. Returns ``None`` when absent.
    """
    for tag in _INPUT_TAG_RE.findall(html or ""):
        a = _tag_attrs(tag)
        if a.get("name") == name and "value" in a:
            return a["value"]
    return None


def _resp_text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", errors="replace")
    return str(body)


class FormLoginWithToken(LoginStrategy):
    """GET a login page, scrape a hidden anti-CSRF token, then POST credentials.

    Covers the classic server-rendered login where the form embeds a per-session
    hidden field that must be echoed on submit (DVWA's ``user_token``, Django's
    ``csrfmiddlewaretoken``, Rails' ``authenticity_token``, …). ``FormLogin``
    can't do this because the token is a *hidden input value*, not a cookie.

    Flow: GET ``get_url`` (login page; cookies fold into the identity jar) →
    read the ``token_field`` value → merge it into ``fields`` → POST to
    ``login_url``. Cookie continuity across the two requests is automatic (same
    identity jar). ``success`` decides whether login worked; because many apps
    return the same 3xx/2xx on success and failure, pass a body/redirect-aware
    predicate (see the orchestrator's ``success_absent``/``success_present``).
    """

    def __init__(
        self,
        login_url: str,
        fields: Dict[str, str],
        *,
        token_field: str = "user_token",
        get_url: Optional[str] = None,
        method: str = "POST",
        as_json: bool = False,
        follow_redirects: bool = True,
        success=None,
    ) -> None:
        self.login_url = login_url
        self.fields = dict(fields)
        self.token_field = token_field
        self.get_url = get_url or login_url
        self.method = method.upper()
        self.as_json = as_json
        self.follow_redirects = follow_redirects
        self.success = success or (lambda r: r.status < 400)

    def _encode(self, fields: Dict[str, str]) -> tuple:
        if self.as_json:
            return json.dumps(fields).encode("utf-8"), "application/json"
        from urllib.parse import urlencode
        return urlencode(fields).encode("utf-8"), "application/x-www-form-urlencoded"

    def apply(self, engine: Any, identity: Identity) -> Optional[Response]:
        page = engine.request(
            identity.name, "GET", self.get_url, follow_redirects=True)
        fields = dict(self.fields)
        if self.token_field:
            tok = extract_input_value(_resp_text(page), self.token_field)
            if tok is not None:
                fields[self.token_field] = tok
        body, content_type = self._encode(fields)
        resp = engine.request(
            identity.name, self.method, self.login_url,
            body=body, headers={"Content-Type": content_type},
            follow_redirects=self.follow_redirects,
        )
        identity.authenticated = bool(self.success(resp))
        return resp


__all__ = [
    "resolve_credential", "LoginStrategy", "BearerAuth", "ApiKeyAuth",
    "BasicAuth", "FormLogin", "JsonLogin", "FormLoginWithToken",
    "extract_input_value",
]
