"""Parse an API description into a normalised endpoint inventory and a
seed authorization test matrix.

Supported inputs (auto-detected):
  * OpenAPI 3.x / Swagger 2.0   — JSON or YAML
  * Postman collection v2.x     — JSON
  * GraphQL introspection result — JSON (the ``__schema`` object, whether
    wrapped in ``{"data": {...}}`` or bare)

Everything here is pure and offline: it reads one local file and emits
plain dicts. No network, no LLM, no mutation of the caller's target.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

try:  # PyYAML is present in the RAPTOR environment; degrade if not.
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover - exercised only on stripped envs
    _HAVE_YAML = False


# --- Object-id heuristics ---------------------------------------------------
# A path/query parameter whose name looks like an object reference is the
# raw material for a BOLA (API1) test. We deliberately favour precision over
# recall: a false positive pollutes the operator's authz matrix with a
# spurious test target, which is worse than missing an oddly-named id.
#
# An id name is: one of a small set of exact names; OR a ``_id``/``_ids``
# snake-case suffix (case-insensitive); OR a camelCase/UPPER ``Id``/``ID``
# suffix (case-SENSITIVE — the capital is what distinguishes ``userId`` from
# the ``id`` inside ``valid``/``grid``/``android``/``void``).
_ID_EXACT = {"id", "ids", "uid", "guid", "uuid", "slug", "key", "ref", "token"}
_ID_SNAKE_RE = re.compile(r"(_id|_ids)$", re.IGNORECASE)
_ID_CAMEL_RE = re.compile(r"[a-z](Id|Ids|ID)$")  # case-sensitive on purpose


def _is_id_param(name: str) -> bool:
    """True when a parameter name denotes an object reference (see above)."""
    if not name:
        return False
    n = name.strip()
    return (n.lower() in _ID_EXACT
            or bool(_ID_SNAKE_RE.search(n))
            or bool(_ID_CAMEL_RE.search(n)))

# Path or operation text hinting at a privileged / function-level surface
# (drives the BFLA / API5 rows).
_PRIVILEGED_RE = re.compile(
    r"admin|internal|manage|superuser|root|privileg|sudo|backend|"
    r"config|setting|users?/|accounts?/|roles?|permission|grant|revoke",
    re.IGNORECASE,
)

# State-changing operations. "MUTATION" is here so GraphQL mutations get
# property-level (API3) and privileged (BFLA/API5) treatment like their REST
# write-verb counterparts — they are exactly the state-changing surface.
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE", "MUTATION"}
_HTTP_METHODS = {"GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}


# --- Loading & detection ----------------------------------------------------

def load_spec(path: Path) -> Any:
    """Load a JSON or YAML description file into a Python object.

    Tries JSON first (fast, always available), then YAML. Raises
    ``ValueError`` with a readable message on failure.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    if _HAVE_YAML:
        try:
            return yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{path}: not valid JSON or YAML ({exc})") from exc
    raise ValueError(
        f"{path}: not valid JSON, and PyYAML is unavailable to try YAML"
    )


def _graphql_schema(doc: Any) -> dict | None:
    """Return the introspection ``__schema`` object — bare or wrapped in the
    standard ``{"data": {...}}`` envelope — or None. Single source of truth
    for how introspection results are unwrapped (used by detect_kind and the
    parser, so a new envelope shape is edited in one place)."""
    if not isinstance(doc, dict):
        return None
    schema = doc.get("__schema")
    if schema is None and isinstance(doc.get("data"), dict):
        schema = doc["data"].get("__schema")
    return schema if isinstance(schema, dict) else None


def detect_kind(doc: Any) -> str:
    """Classify a loaded description. Returns one of
    ``openapi`` | ``postman`` | ``graphql`` | ``unknown``.
    """
    if not isinstance(doc, dict):
        return "unknown"
    if "openapi" in doc or "swagger" in doc:
        return "openapi"
    schema = _graphql_schema(doc)
    if schema is not None and "types" in schema:
        return "graphql"
    # Postman collection v2.x: has info + item[].
    info = doc.get("info")
    if isinstance(info, dict) and "item" in doc:
        return "postman"
    return "unknown"


# --- $ref resolution (local only) ------------------------------------------

def _resolve_ref(doc: dict, ref: str, _seen: set | None = None) -> Any:
    """Resolve a local ``#/a/b/c`` JSON pointer. Non-local refs and
    broken pointers resolve to ``{}`` so callers never crash on them."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    _seen = _seen or set()
    if ref in _seen:  # cyclic schema — stop.
        return {}
    _seen.add(ref)
    node: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    if isinstance(node, dict) and "$ref" in node:
        return _resolve_ref(doc, node["$ref"], _seen)
    return node


def _schema_fields(doc: dict, schema: Any) -> list[str]:
    """Top-level property names of an OpenAPI/JSON-Schema object, one
    ``$ref`` hop deep. Used to surface mass-assignment candidates."""
    if isinstance(schema, dict) and "$ref" in schema:
        schema = _resolve_ref(doc, schema["$ref"])
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if isinstance(props, dict):
        return list(props.keys())
    # allOf / oneOf / anyOf — merge child property names.
    fields: list[str] = []
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(key, []) or []:
            fields.extend(_schema_fields(doc, sub))
    return fields


# --- Classification ---------------------------------------------------------

def _is_object_scoped(path_params: list[str], query_params: list[str], path: str) -> bool:
    for name in (*path_params, *query_params):
        if _is_id_param(name or ""):
            return True
    # A templated segment in the path (``/users/{id}``) is an object ref
    # even if the param metadata was omitted from the spec.
    return bool(re.search(r"\{[^}]+\}", path or ""))


def _owasp_focus(method: str, path: str, object_scoped: bool,
                 body_fields: list[str], privileged: bool) -> list[str]:
    focus: list[str] = []
    if object_scoped:
        focus.append("API1")  # Broken Object Level Authorization
    if body_fields and method in _MUTATING_METHODS:
        focus.append("API3")  # Broken Object Property Level Authorization
    if privileged:
        focus.append("API5")  # Broken Function Level Authorization
    if re.search(r"url|uri|callback|webhook|redirect|fetch|proxy|image_url",
                 path, re.IGNORECASE):
        focus.append("API7")  # Server Side Request Forgery
    return focus or ["API4"]  # default: resource consumption / general


def _endpoint(idx: int, method: str, path: str, *, operation_id: str = "",
              summary: str = "", auth_required: bool = False,
              security: list | None = None, path_params: list | None = None,
              query_params: list | None = None,
              body_fields: list | None = None) -> dict:
    method = method.upper()
    path = path or ""
    path_params = path_params or []
    query_params = query_params or []
    body_fields = body_fields or []
    object_scoped = _is_object_scoped(path_params, query_params, path)
    privileged = bool(
        _PRIVILEGED_RE.search(path)
        or _PRIVILEGED_RE.search(operation_id or "")
        or (method in _MUTATING_METHODS and object_scoped)
    )
    return {
        "id": f"EP-{idx:04d}",
        "method": method,
        "path": path,
        "operation_id": operation_id or "",
        "summary": summary or "",
        "auth_required": bool(auth_required),
        "security": security or [],
        "path_params": path_params,
        "query_params": query_params,
        "body_fields": body_fields,
        "object_scoped": object_scoped,
        "privileged": privileged,
        "owasp_focus": _owasp_focus(method, path, object_scoped, body_fields, privileged),
    }


# --- OpenAPI / Swagger ------------------------------------------------------

def _parse_openapi(doc: dict) -> tuple[list[dict], str]:
    endpoints: list[dict] = []
    global_security = doc.get("security") or []
    base_url = ""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base_url = servers[0].get("url", "") or ""
    elif "host" in doc:  # Swagger 2.0
        scheme = (doc.get("schemes") or ["https"])[0]
        base_url = f"{scheme}://{doc.get('host', '')}{doc.get('basePath', '')}"

    idx = 1
    for path, item in (doc.get("paths") or {}).items():
        # YAML permits non-string keys (a bare ``on:`` decodes to True, a
        # numeric key to int); skip them rather than crash on ``.upper()``.
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", []) or []
        for method, op in item.items():
            if not isinstance(method, str):
                continue
            if method.upper() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = [*shared_params, *(op.get("parameters", []) or [])]
            path_params, query_params = [], []
            for p in params:
                if isinstance(p, dict) and "$ref" in p:
                    p = _resolve_ref(doc, p["$ref"])
                if not isinstance(p, dict):
                    continue
                loc, name = p.get("in"), p.get("name")
                if not name:
                    continue
                if loc == "path":
                    path_params.append(name)
                elif loc == "query":
                    query_params.append(name)

            body_fields: list[str] = []
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                if "$ref" in rb:
                    rb = _resolve_ref(doc, rb["$ref"])
                content = (rb or {}).get("content", {}) or {}
                for media in content.values():
                    if isinstance(media, dict):
                        body_fields.extend(_schema_fields(doc, media.get("schema")))
            else:  # Swagger 2.0 body parameter
                for p in params:
                    if isinstance(p, dict) and p.get("in") == "body":
                        body_fields.extend(_schema_fields(doc, p.get("schema")))

            op_security = op.get("security")
            security = op_security if op_security is not None else global_security
            # A hand-edited spec may carry ``security: [null]`` or non-mapping
            # entries; skip them rather than raise TypeError on ``for k in entry``.
            sec_names = [k for entry in (security or [])
                         if isinstance(entry, dict) for k in entry]

            endpoints.append(_endpoint(
                idx, method, path,
                operation_id=op.get("operationId", ""),
                summary=op.get("summary", "") or op.get("description", ""),
                auth_required=bool(sec_names),
                security=sec_names,
                path_params=path_params,
                query_params=query_params,
                body_fields=sorted(set(body_fields)),
            ))
            idx += 1
    return endpoints, base_url


# --- Postman ----------------------------------------------------------------

def _postman_url_path(url: Any) -> tuple[str, list[str]]:
    """Return (path, query_param_names) from a Postman url node."""
    if isinstance(url, str):
        raw, _, query_str = url.partition("?")
        # Strip scheme://host if present, keeping the path; a template-var or
        # bare-path url (no ``://``) is kept verbatim as the path.
        m = re.match(r"[a-z][a-z0-9+.-]*://[^/]+(/.*)?$", raw, re.IGNORECASE)
        path = m.group(1) if (m and m.group(1)) else raw
        query, seen = [], set()
        for key, _val in parse_qsl(query_str, keep_blank_values=True):
            if key and key not in seen:
                seen.add(key)
                query.append(key)
        return path or raw, query
    if isinstance(url, dict):
        segs = url.get("path", [])
        if isinstance(segs, list):
            path = "/" + "/".join(str(s) for s in segs)
        else:
            path = str(segs or url.get("raw", ""))
        query = [q.get("key") for q in (url.get("query") or [])
                 if isinstance(q, dict) and q.get("key")]
        return path, query
    return "", []


def _postman_body_fields(body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []
    mode = body.get("mode")
    if mode == "urlencoded":
        return [f.get("key") for f in (body.get("urlencoded") or [])
                if isinstance(f, dict) and f.get("key")]
    if mode == "formdata":
        return [f.get("key") for f in (body.get("formdata") or [])
                if isinstance(f, dict) and f.get("key")]
    if mode == "raw":
        raw = body.get("raw", "")
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return list(parsed.keys())
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _parse_postman(doc: dict) -> tuple[list[dict], str]:
    endpoints: list[dict] = []
    collection_auth = doc.get("auth")
    idx = [1]

    def walk(items: list, inherited_auth: Any) -> None:
        for node in items or []:
            if not isinstance(node, dict):
                continue
            if "item" in node:  # folder
                walk(node.get("item", []), node.get("auth", inherited_auth))
                continue
            req = node.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET"))
            path, query = _postman_url_path(req.get("url"))
            path_params = re.findall(r"[:{]([A-Za-z0-9_]+)}?", path)
            auth = req.get("auth", inherited_auth)
            auth_required = bool(auth) and (
                not isinstance(auth, dict) or auth.get("type") not in (None, "noauth")
            )
            sec = [auth.get("type")] if isinstance(auth, dict) and auth.get("type") else []
            endpoints.append(_endpoint(
                idx[0], method, path,
                operation_id=node.get("name", ""),
                summary=node.get("name", ""),
                auth_required=auth_required,
                security=sec,
                path_params=path_params,
                query_params=query,
                body_fields=sorted(set(_postman_body_fields(req.get("body")))),
            ))
            idx[0] += 1

    walk(doc.get("item", []), collection_auth)
    return endpoints, ""


# --- GraphQL introspection --------------------------------------------------

def _parse_graphql(doc: dict) -> tuple[list[dict], str]:
    schema = _graphql_schema(doc)
    if schema is None:
        return [], ""
    type_map = {t.get("name"): t for t in schema.get("types", [])
                if isinstance(t, dict)}
    endpoints: list[dict] = []
    idx = 1
    for op_kind, key in (("QUERY", "queryType"), ("MUTATION", "mutationType")):
        root = schema.get(key)
        if not isinstance(root, dict):
            continue
        type_def = type_map.get(root.get("name"))
        if not isinstance(type_def, dict):
            continue
        for field in type_def.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            name = field.get("name", "")
            args = [a.get("name") for a in (field.get("args") or [])
                    if isinstance(a, dict) and a.get("name")]
            # An id-ish arg makes a query/mutation object-scoped.
            endpoints.append(_endpoint(
                idx, op_kind, f"{op_kind.lower()}.{name}",
                operation_id=name,
                summary=field.get("description", "") or "",
                auth_required=False,  # GraphQL auth lives in resolvers, not schema
                security=[],
                path_params=[a for a in args if _is_id_param(a or "")],
                query_params=args,
                body_fields=[] if op_kind == "QUERY" else args,
            ))
            idx += 1
    return endpoints, ""


# --- Public builders --------------------------------------------------------

_PARSERS = {
    "openapi": _parse_openapi,
    "postman": _parse_postman,
    "graphql": _parse_graphql,
}


def build_inventory(doc: Any, *, source_path: str = "",
                    base_url: str = "") -> dict:
    """Build the normalised endpoint inventory from a loaded description."""
    kind = detect_kind(doc)
    if kind not in _PARSERS:
        raise ValueError(
            "unrecognised API description: expected OpenAPI/Swagger, a "
            "Postman collection, or a GraphQL introspection result"
        )
    endpoints, detected_base = _PARSERS[kind](doc)
    return {
        "source_kind": kind,
        "source_path": source_path,
        "base_url": base_url or detected_base,
        "endpoint_count": len(endpoints),
        "object_scoped_count": sum(1 for e in endpoints if e["object_scoped"]),
        "privileged_count": sum(1 for e in endpoints if e["privileged"]),
        "no_auth_count": sum(1 for e in endpoints if not e["auth_required"]),
        "endpoints": endpoints,
    }


def build_authz_matrix(inventory: dict,
                       roles: list[str] | None = None) -> dict:
    """Seed the cross-account authorization test matrix from an inventory.

    Emits one BOLA row per object-scoped endpoint (API1), one property-
    level row per mutating endpoint that carries body fields (API3), and
    one BFLA row per privileged endpoint (API5). ``result`` is left null
    for the operator/LLM to fill during execution.
    """
    roles = roles or ["anonymous", "user_a", "user_b", "admin"]
    tests: list[dict] = []
    idx = 1

    def add(ep: dict, owasp: str, test_type: str, procedure: str) -> None:
        nonlocal idx
        tests.append({
            "id": f"AZ-{idx:04d}",
            "endpoint_id": ep["id"],
            "method": ep["method"],
            "path": ep["path"],
            "owasp": owasp,
            "test_type": test_type,
            "procedure": procedure,
            "expected": "denied",
            "result": None,  # filled during execution: denied | allowed | error
            "evidence": None,
        })
        idx += 1

    for ep in inventory.get("endpoints", []):
        if ep["object_scoped"]:
            add(ep, "API1", "BOLA",
                f"Authenticate as user_a; issue {ep['method']} {ep['path']} "
                f"referencing an object owned by user_b. Expect 403/404, not 200 "
                f"with user_b's data.")
        if ep["body_fields"] and ep["method"] in _MUTATING_METHODS:
            add(ep, "API3", "property-level / mass-assignment",
                f"As user_a, send {ep['method']} {ep['path']} adding privileged "
                f"fields not in the documented set (e.g. role, is_admin, owner_id). "
                f"Confirm the server ignores them. Known body fields: "
                f"{', '.join(ep['body_fields'][:8])}.")
        if ep["privileged"]:
            add(ep, "API5", "BFLA",
                f"With a low-privilege (user_a) token, call {ep['method']} "
                f"{ep['path']}. Expect 403. Then try method tampering "
                f"(GET->PUT/DELETE) on the same route.")

    return {
        "roles": roles,
        "note": ("Seed matrix — provision >=2 accounts per role before running. "
                 "Object ids come from the app, not the spec: capture real ids "
                 "for user_a and user_b during Phase 1 recon."),
        "test_count": len(tests),
        "tests": tests,
    }
