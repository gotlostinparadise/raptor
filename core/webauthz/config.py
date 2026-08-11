"""Configuration for a `/webauthz` run — identities + concrete authz tests.

Access-control testing needs something a scanner can't infer: *who legitimately
owns what*. This config is that ground truth. The operator declares each
identity (and how to authenticate it, by env-var reference — never a literal
secret) and each test case: a concrete request, and which identity legitimately
owns the object it touches. The runner replays that request as every other
identity and lets the response diff deliver the verdict.

The ``authorization`` field is the mechanical gate: active testing (real
requests) refuses to run unless it is a non-empty attestation, and the string is
stamped into every :class:`VerifiedOutcome` produced, so a proof always carries
its authorization provenance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from core.webgraph.scope import endpoint_id as _endpoint_id

try:  # YAML is optional; JSON always works
    import yaml
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


@dataclass
class LoginConfig:
    """How to authenticate one identity. Credentials are env-var *names*."""

    type: str = "none"          # none | bearer | api_key | basic | form
    token_env: str = ""         # bearer
    header: str = ""            # api_key header name
    value_env: str = ""         # api_key value env
    username_env: str = ""      # basic
    password_env: str = ""      # basic
    login_url: str = ""         # form / json
    fields: Dict[str, str] = field(default_factory=dict)   # form/json body (values may be "env:VAR")
    as_json: bool = False       # form encodes JSON
    token_path: str = "authentication.token"   # json: dot-path to the token in the response

    def credential_env_vars(self) -> List[str]:
        out = [self.token_env, self.value_env, self.username_env, self.password_env]
        for v in self.fields.values():
            if isinstance(v, str) and v.startswith("env:"):
                out.append(v[4:])
        return [v for v in out if v]


@dataclass
class IdentityConfig:
    name: str
    role: str = ""
    login: LoginConfig = field(default_factory=LoginConfig)


@dataclass
class AuthzTest:
    """One concrete access-control test case."""

    id: str
    method: str
    path: str                   # concrete path incl. the owner's object id
    owner: str                  # identity that legitimately owns the object
    vuln_class: str = "bola"    # bola | bfla | property_level
    owasp: str = "API1"
    others: Optional[List[str]] = None   # identities to replay as; default: all non-owner + anon
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    privileged: bool = False    # BFLA: endpoint is meant to be privileged-only
    # A path for an object the owner does NOT own (or a non-existent id). Used as
    # a negative control: if the owner's real object and this control return the
    # SAME body, the endpoint is not object-specific (constant/public) and a
    # body-match across identities is NOT a BOLA. Without it, a match is only
    # SUSPECTED, not confirmed.
    control_path: str = ""

    @property
    def endpoint_id(self) -> str:
        return _endpoint_id(self.method, self.path)


@dataclass
class AuthzConfig:
    base_url: str
    identities: List[IdentityConfig] = field(default_factory=list)
    tests: List[AuthzTest] = field(default_factory=list)
    authorization: str = ""     # REQUIRED for active testing (mechanical gate)
    csrf_cookie: Optional[str] = None
    csrf_header: Optional[str] = None

    def identity(self, name: str) -> Optional[IdentityConfig]:
        for i in self.identities:
            if i.name == name:
                return i
        return None

    def credential_env_vars(self) -> List[str]:
        out: List[str] = []
        for i in self.identities:
            out.extend(i.login.credential_env_vars())
        return sorted(set(out))


def _login_from(d: Mapping[str, Any]) -> LoginConfig:
    return LoginConfig(
        type=d.get("type", "none"), token_env=d.get("token_env", ""),
        header=d.get("header", ""), value_env=d.get("value_env", ""),
        username_env=d.get("username_env", ""), password_env=d.get("password_env", ""),
        login_url=d.get("login_url", ""), fields=dict(d.get("fields") or {}),
        as_json=bool(d.get("as_json", False)),
        token_path=d.get("token_path", "authentication.token"),
    )


def from_dict(data: Mapping[str, Any]) -> AuthzConfig:
    """Build an :class:`AuthzConfig` from a parsed dict, with validation."""
    idents = [
        IdentityConfig(name=i["name"], role=i.get("role", ""),
                       login=_login_from(i.get("login") or {}))
        for i in (data.get("identities") or [])
    ]
    tests = []
    for t in (data.get("tests") or []):
        if not (t.get("id") and t.get("method") and t.get("path") and t.get("owner")):
            raise ValueError(f"authz test missing id/method/path/owner: {t!r}")
        tests.append(AuthzTest(
            id=t["id"], method=t["method"], path=t["path"], owner=t["owner"],
            vuln_class=t.get("class") or t.get("vuln_class") or "bola",
            owasp=t.get("owasp", "API1"), others=t.get("others"),
            body=t.get("body", ""), headers=dict(t.get("headers") or {}),
            privileged=bool(t.get("privileged", False)),
            control_path=t.get("control_path", ""),
        ))
    cfg = AuthzConfig(
        base_url=(data.get("base_url") or "").rstrip("/"),
        identities=idents, tests=tests,
        authorization=data.get("authorization", ""),
        csrf_cookie=data.get("csrf_cookie"), csrf_header=data.get("csrf_header"),
    )
    if not cfg.base_url:
        raise ValueError("authz config requires a base_url")
    # every test's owner + others must be declared identities (or 'anonymous')
    known = {i.name for i in idents} | {"anonymous"}
    for t in tests:
        for who in [t.owner] + list(t.others or []):
            if who not in known:
                raise ValueError(f"test {t.id}: unknown identity {who!r}")
    return cfg


def load_config(path: Path) -> AuthzConfig:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        if not _HAVE_YAML:
            raise ValueError(f"{path}: not valid JSON and PyYAML unavailable")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return from_dict(data)


__all__ = [
    "LoginConfig", "IdentityConfig", "AuthzTest", "AuthzConfig",
    "from_dict", "load_config",
]
