"""The `/webauthz` engine — replay each request across identities, verdict the diff.

Ties A3 (the session engine + authorization oracle) to A4 (the graph) and A5
(verified outcomes). For each declared test it builds a
:class:`~core.session.replay.RequestTemplate`, replays it as the owner and every
other identity through the :class:`~core.session.engine.SessionEngine`, and runs
:func:`~core.session.replay.authorization_diff`. The **verdict is the tool's**,
not the LLM's: an identity that reads the owner's object (identical response
hash) is a confirmed horizontal break.

Safe by default: with ``active=False`` it only builds the plan + surface graph
and sends nothing. ``active=True`` requires a non-empty ``authorization`` in the
config (the mechanical gate) and a non-passive profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from core.session.authz import verdict_records
from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.login import (
    ApiKeyAuth, BasicAuth, BearerAuth, FormLogin, FormLoginWithToken, JsonLogin,
    resolve_credential,
)
from core.session.replay import RequestTemplate, authorization_diff, replay
from core.webauthz.config import AuthzConfig, LoginConfig
from core.webgraph import model as M
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.builder import build_graph
from core.webgraph.verified import record_confirmed


@dataclass
class AuthzRun:
    out_dir: str
    base_url: str
    active: bool
    tests_planned: int = 0
    tests_run: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0

    @property
    def violations(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get("violation")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url,
            "active": self.active, "tests_planned": self.tests_planned,
            "tests_run": self.tests_run, "violation_count": len(self.violations),
            "findings": self.findings, "warnings": self.warnings,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _strategy_for(login: LoginConfig, env) -> Tuple[Optional[Any], Optional[str]]:
    """Build a login strategy from config, resolving env creds.

    Returns ``(strategy, warning)``; ``strategy`` is None for anonymous / when a
    required credential is missing (with a warning explaining which).
    """
    t = (login.type or "none").lower()
    if t == "none":
        return None, None
    if t == "bearer":
        tok = resolve_credential(login.token_env, env)
        if not tok:
            return None, f"missing ${login.token_env} for bearer login"
        return BearerAuth(tok), None
    if t == "api_key":
        val = resolve_credential(login.value_env, env)
        if not val:
            return None, f"missing ${login.value_env} for api_key login"
        return ApiKeyAuth(login.header or "X-API-Key", val), None
    if t == "basic":
        u = resolve_credential(login.username_env, env)
        p = resolve_credential(login.password_env, env)
        if not (u and p):
            return None, f"missing basic creds (${login.username_env}/${login.password_env})"
        return BasicAuth(u, p), None
    if t in ("form", "json", "form_csrf", "form_token", "csrf"):
        fields = {}
        for k, v in login.fields.items():
            fields[k] = resolve_credential(v[4:], env) if isinstance(v, str) and v.startswith("env:") else v
        if t == "json":
            return JsonLogin(login.login_url, fields, token_path=login.token_path), None
        if t in ("form_csrf", "form_token", "csrf"):
            return FormLoginWithToken(
                login.login_url, fields,
                token_field=login.token_field or "user_token",
                get_url=login.get_url or None, as_json=login.as_json), None
        return FormLogin(login.login_url, fields, as_json=login.as_json), None
    return None, f"unknown login type {t!r}"


def build_engine(
    config: AuthzConfig, client: Any, env: Optional[Dict[str, str]] = None,
) -> Tuple[SessionEngine, List[str]]:
    """Construct a :class:`SessionEngine`, register + authenticate identities."""
    engine = SessionEngine(client, csrf_cookie=config.csrf_cookie,
                           csrf_header=config.csrf_header)
    warnings: List[str] = []
    for ic in config.identities:
        ident = Identity(name=ic.name, role=ic.role,
                         credential_env_vars=tuple(ic.login.credential_env_vars()))
        engine.add_identity(ident)
        strat, warn = _strategy_for(ic.login, env)
        if warn:
            warnings.append(f"identity {ic.name}: {warn}")
        if strat is not None:
            try:
                engine.authenticate(ic.name, strat)
            except Exception as exc:
                warnings.append(f"identity {ic.name}: login failed ({type(exc).__name__})")
    return engine, warnings


def _surface_records(config: AuthzConfig) -> Dict[str, List[Dict[str, Any]]]:
    """Endpoint + identity nodes for the graph, independent of any traffic."""
    recs: Dict[str, List[Dict[str, Any]]] = {}

    def add(rec):
        recs.setdefault(rec.KIND, []).append(rec.to_row())

    origin = config.base_url
    for ic in config.identities:
        add(M.IdentityRecord(name=ic.name, role=ic.role, authenticated=False,
                             source="webauthz"))
    add(M.IdentityRecord(name="anonymous", source="webauthz"))
    for t in config.tests:
        add(M.EndpointRecord(
            method=t.method, path=t.path, origin=origin,
            url=f"{origin}{t.path}" if t.path.startswith("/") else t.path,
            object_scoped=(t.vuln_class in ("bola", "property_level")),
            privileged=bool(t.privileged), owasp_focus=[t.owasp], source="webauthz",
        ))
    return recs


def run_authz(
    config: AuthzConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> AuthzRun:
    """Run the access-control tests. See module docstring for the gate."""
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = AuthzRun(out_dir=str(out), base_url=config.base_url, active=active,
                   tests_planned=len(config.tests))

    # --- mechanical authorization gate ---
    if active:
        if profile == "passive":
            raise ValueError("active testing cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError(
                "active testing refused: config.authorization is empty. Declare "
                "written authorization (it is recorded on every proof) or run "
                "without --active for a dry-run plan."
            )

    accumulated: Dict[str, List[Dict[str, Any]]] = _surface_records(config)

    if not active:
        # Dry run: plan only, no requests.
        run.findings = [
            {"id": t.id, "endpoint": t.endpoint_id, "class": t.vuln_class,
             "owner": t.owner, "others": t.others, "planned": True}
            for t in config.tests
        ]
        graph = build_graph(accumulated, [config.base_url])
        persist_records(out / "normalized", accumulated)
        _finalize(out, graph, run, accumulated)
        return run

    # --- active: build engine + replay ---
    host = urlsplit(config.base_url).hostname or ""
    if client_factory is not None:
        client = client_factory([host] if host else [])
    else:
        client = _client_for(config.base_url)
    engine, warns = build_engine(config, client, env=env)
    run.warnings.extend(warns)

    known = set(engine.names())
    confirmed_vulns: List[Dict[str, Any]] = []
    for t in config.tests:
        if t.owner not in known:
            run.warnings.append(f"test {t.id}: owner {t.owner!r} not registered; skipped")
            continue
        template = RequestTemplate(
            method=t.method, url=f"{config.base_url}{t.path}",
            body=t.body.encode("utf-8") if t.body else None,
            headers=t.headers or None, label=t.endpoint_id,
        )
        try:
            verdict = authorization_diff(engine, template, t.owner, t.others)
        except Exception as exc:
            run.warnings.append(f"test {t.id}: replay error ({type(exc).__name__}: {exc})")
            continue
        run.tests_run += 1

        # Object-specificity gate: a body-match across identities is only a real
        # BOLA if the endpoint returns object-SPECIFIC content. A negative
        # control (a non-owned/non-existent object) proves it: if the owner's
        # real object and the control return the SAME body, the endpoint is
        # constant/public and the match is not a break. Without a control, the
        # finding is recorded as SUSPECTED, never a verified outcome.
        confirmed = False
        if verdict.violation:
            if t.control_path:
                control_tmpl = RequestTemplate(
                    method=t.method, url=f"{config.base_url}{t.control_path}",
                    body=t.body.encode("utf-8") if t.body else None,
                    headers=t.headers or None, label=t.endpoint_id)
                try:
                    control_obs = replay(engine, control_tmpl, t.owner)
                    owner_obs = verdict.observation(t.owner)
                    object_specific = bool(
                        owner_obs and control_obs.body_sha256 != owner_obs.body_sha256)
                except Exception:
                    object_specific = False
                if not object_specific:
                    verdict.violation = False   # constant/public → not a BOLA
                    run.warnings.append(
                        f"test {t.id}: response is not object-specific (matches the "
                        f"control) — suppressed as a non-finding")
                else:
                    confirmed = True
            else:
                run.warnings.append(
                    f"test {t.id}: no control_path — reporting SUSPECTED (add a "
                    f"control_path to a non-owned object to confirm object-specificity)")

        recs = verdict_records(verdict, t.endpoint_id, vuln_id=t.id,
                               source="webauthz", confirmed=confirmed)
        for kind, rows in recs.items():
            accumulated.setdefault(kind, []).extend(rows)
        confirmed_vulns.extend(recs.get(M.VulnRecord.KIND, []))
        run.findings.append({
            "id": t.id, "endpoint": t.endpoint_id, "class": t.vuln_class,
            "owasp": t.owasp, "owner": t.owner, "violation": verdict.violation,
            "confirmed": confirmed, "offending": verdict.offending,
            "observations": [
                {"identity": o.identity, "status": o.status, "allowed": o.allowed}
                for o in verdict.observations
            ],
        })

    graph = build_graph(accumulated, [config.base_url])
    persist_records(out / "normalized", accumulated)
    _finalize(out, graph, run, accumulated)

    # verified outcomes (A5) — stamped with the config's authorization
    if confirmed_vulns:
        record_confirmed(
            confirmed_vulns, project_dir=out, producing_model=producing_model,
        )
    return run


def _client_for(base_url: str) -> Any:
    """Pick an HTTP client appropriate for the target.

    An https target on 443 uses the egress-allowlisted ``EgressClient`` (scoped
    to the target host). An http target, or any non-443 port, cannot be served
    through the HTTPS-CONNECT egress proxy, so it falls back to the unrestricted
    ``UrllibClient`` — acceptable here because webauthz hits a single
    operator-declared, authorized target and replay disables redirect-following,
    so it never wanders off-host.
    """
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _finalize(out: Path, graph, run: AuthzRun, accumulated) -> None:
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    import json
    (out / "webauthz-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["AuthzRun", "build_engine", "run_authz"]
