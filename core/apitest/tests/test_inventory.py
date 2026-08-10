"""Tests for core.apitest.inventory — the offline API description parser.

Fully offline; the root conftest.py puts the repo root on sys.path and sets
RAPTOR_DIR, so a bare ``from core.apitest import ...`` resolves at collection.
"""

import pytest

from core.apitest import (
    build_authz_matrix,
    build_inventory,
    detect_kind,
)

# --- fixtures ---------------------------------------------------------------

OPENAPI = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/v1"}],
    "security": [{"bearerAuth": []}],
    "components": {
        "schemas": {
            "User": {"type": "object", "properties": {
                "name": {"type": "string"},
                "role": {"type": "string"},
            }},
        }
    },
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "parameters": [
                    {"name": "id", "in": "path", "required": True},
                    {"name": "expand", "in": "query"},
                ],
            },
            "put": {
                "operationId": "updateUser",
                "parameters": [{"name": "id", "in": "path"}],
                "requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/User"}}}},
            },
        },
        "/health": {
            "get": {"operationId": "health", "security": []},
        },
        "/admin/settings": {
            "post": {
                "operationId": "setConfig",
                "requestBody": {"content": {"application/json": {
                    "schema": {"type": "object",
                               "properties": {"flag": {"type": "boolean"}}}}}},
            },
        },
    },
}

POSTMAN = {
    "info": {"name": "Demo", "schema": "https://schema.getpostman.com/v2.1.0"},
    "auth": {"type": "bearer"},
    "item": [
        {
            "name": "Get order",
            "request": {
                "method": "GET",
                "url": {"host": ["api", "example", "com"],
                        "path": ["orders", ":order_id"],
                        "query": [{"key": "verbose", "value": "1"}]},
            },
        },
        {
            "name": "Folder",
            "item": [
                {
                    "name": "Create order",
                    "request": {
                        "method": "POST",
                        "url": {"path": ["orders"]},
                        "body": {"mode": "raw",
                                 "raw": '{"item": "x", "qty": 2}'},
                    },
                },
            ],
        },
    ],
}

GRAPHQL = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [
                {"name": "user", "args": [{"name": "id"}], "description": "one user"},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "deleteUser", "args": [{"name": "id"}]},
            ]},
        ],
    }}
}


# --- detection --------------------------------------------------------------

def test_detect_kind():
    assert detect_kind(OPENAPI) == "openapi"
    assert detect_kind(POSTMAN) == "postman"
    assert detect_kind(GRAPHQL) == "graphql"
    assert detect_kind({"swagger": "2.0", "paths": {}}) == "openapi"
    assert detect_kind({"nonsense": 1}) == "unknown"
    assert detect_kind([1, 2, 3]) == "unknown"


# --- OpenAPI ----------------------------------------------------------------

def test_openapi_inventory_basics():
    inv = build_inventory(OPENAPI, source_path="spec.json")
    assert inv["source_kind"] == "openapi"
    assert inv["base_url"] == "https://api.example.com/v1"
    assert inv["endpoint_count"] == 4
    by_op = {e["operation_id"]: e for e in inv["endpoints"]}

    get_user = by_op["getUser"]
    assert get_user["method"] == "GET"
    assert get_user["path_params"] == ["id"]
    assert get_user["query_params"] == ["expand"]
    assert get_user["object_scoped"] is True
    assert get_user["auth_required"] is True          # inherits global security
    assert "bearerAuth" in get_user["security"]
    assert "API1" in get_user["owasp_focus"]          # BOLA

    update_user = by_op["updateUser"]
    assert update_user["body_fields"] == ["name", "role"]   # $ref resolved
    assert "API3" in update_user["owasp_focus"]            # property-level


def test_openapi_auth_and_privilege_flags():
    inv = build_inventory(OPENAPI)
    by_op = {e["operation_id"]: e for e in inv["endpoints"]}
    assert by_op["health"]["auth_required"] is False       # security: [] override
    assert by_op["setConfig"]["privileged"] is True        # /admin/ path
    assert "API5" in by_op["setConfig"]["owasp_focus"]


def test_swagger2_body_and_host():
    swagger = {
        "swagger": "2.0", "host": "api.example.com", "basePath": "/v2",
        "schemes": ["https"],
        "paths": {"/things": {"post": {
            "operationId": "createThing",
            "parameters": [{"name": "body", "in": "body", "schema": {
                "type": "object", "properties": {"a": {}, "b": {}}}}],
        }}},
    }
    inv = build_inventory(swagger)
    assert inv["base_url"] == "https://api.example.com/v2"
    assert inv["endpoints"][0]["body_fields"] == ["a", "b"]


# --- Postman ----------------------------------------------------------------

def test_postman_inventory():
    inv = build_inventory(POSTMAN)
    assert inv["source_kind"] == "postman"
    assert inv["endpoint_count"] == 2                       # nested folder walked
    paths = {e["path"] for e in inv["endpoints"]}
    assert "/orders/:order_id" in paths
    get_order = next(e for e in inv["endpoints"] if e["method"] == "GET")
    assert "order_id" in get_order["path_params"]
    assert get_order["object_scoped"] is True
    assert get_order["auth_required"] is True               # inherits collection auth
    create = next(e for e in inv["endpoints"] if e["method"] == "POST")
    assert set(create["body_fields"]) == {"item", "qty"}


# --- GraphQL ----------------------------------------------------------------

def test_graphql_inventory():
    inv = build_inventory(GRAPHQL)
    assert inv["source_kind"] == "graphql"
    assert inv["endpoint_count"] == 2
    by_op = {e["operation_id"]: e for e in inv["endpoints"]}
    assert by_op["user"]["method"] == "QUERY"
    assert by_op["user"]["object_scoped"] is True          # id arg
    assert by_op["deleteUser"]["method"] == "MUTATION"


# --- authz matrix -----------------------------------------------------------

def test_authz_matrix_seeds_bola_bfla_property():
    inv = build_inventory(OPENAPI)
    matrix = build_authz_matrix(inv)
    kinds = {t["test_type"] for t in matrix["tests"]}
    assert "BOLA" in kinds
    assert "BFLA" in kinds
    assert any("property" in k for k in kinds)
    # Every test row references a real endpoint id and defaults to unrun.
    ep_ids = {e["id"] for e in inv["endpoints"]}
    for t in matrix["tests"]:
        assert t["endpoint_id"] in ep_ids
        assert t["result"] is None
        assert t["expected"] == "denied"
    assert matrix["test_count"] == len(matrix["tests"])


def test_custom_roles():
    inv = build_inventory(OPENAPI)
    matrix = build_authz_matrix(inv, roles=["guest", "member"])
    assert matrix["roles"] == ["guest", "member"]


# --- robustness -------------------------------------------------------------

def test_unknown_description_raises():
    with pytest.raises(ValueError):
        build_inventory({"totally": "unknown"})


def test_empty_paths_ok():
    inv = build_inventory({"openapi": "3.0.0", "paths": {}})
    assert inv["endpoint_count"] == 0
    matrix = build_authz_matrix(inv)
    assert matrix["test_count"] == 0


def test_postman_string_url_query_params():
    """Regression: string-form Postman URLs must yield query params so
    query-based object ids still get BOLA rows."""
    doc = {
        "info": {"name": "S", "schema": "v2.1.0"}, "auth": {"type": "bearer"},
        "item": [{"name": "get order", "request": {
            "method": "GET",
            "url": "https://api.example.com/orders?order_id=5&verbose=1"}}],
    }
    inv = build_inventory(doc)
    ep = inv["endpoints"][0]
    assert ep["path"] == "/orders"
    assert ep["query_params"] == ["order_id", "verbose"]
    assert ep["object_scoped"] is True                     # order_id detected
    matrix = build_authz_matrix(inv)
    assert any(t["test_type"] == "BOLA" for t in matrix["tests"])


def test_graphql_mutation_gets_property_level_row():
    """Regression: MUTATION is a mutating method, so mutations with args
    get an API3 property-level row."""
    doc = {"data": {"__schema": {
        "queryType": {"name": "Q"}, "mutationType": {"name": "M"},
        "types": [
            {"name": "Q", "fields": []},
            {"name": "M", "fields": [
                {"name": "updateProfile", "args": [{"name": "bio"}, {"name": "role"}]}]},
        ]}}}
    inv = build_inventory(doc)
    mut = inv["endpoints"][0]
    assert mut["method"] == "MUTATION"
    assert "API3" in mut["owasp_focus"]
    matrix = build_authz_matrix(inv)
    assert any("property" in t["test_type"] for t in matrix["tests"])


def test_yaml_non_string_path_and_method_keys_dont_crash():
    """Regression: YAML bool/int keys (on:, 123:) must be skipped, not crash."""
    doc = {"openapi": "3.0.0", "paths": {
        "/ok": {"get": {"operationId": "ok"}},
        True: {"get": {"operationId": "boolPath"}},      # ``on:`` -> True
        "/x": {True: {"operationId": "boolMethod"}},      # ``on:`` method
        123: {"post": {"operationId": "intPath"}},
    }}
    inv = build_inventory(doc)                             # must not raise
    ops = {e["operation_id"] for e in inv["endpoints"]}
    assert "ok" in ops
    assert "boolPath" not in ops and "boolMethod" not in ops


@pytest.mark.parametrize("name,expected", [
    ("id", True), ("ids", True), ("uuid", True), ("guid", True),
    ("user_id", True), ("order_ids", True), ("accountId", True),
    ("userID", True), ("orderIds", True), ("slug", True), ("token", True),
    ("valid", False), ("grid", False), ("void", False), ("android", False),
    ("hidden", False), ("invalid", False), ("name", False),
])
def test_id_param_precision(name, expected):
    """Regression: id heuristic must not over-match valid/grid/android/void."""
    inv = build_inventory({"openapi": "3.0.0", "paths": {"/x": {"get": {
        "operationId": "x",
        "parameters": [{"name": name, "in": "query"}]}}}})
    assert inv["endpoints"][0]["object_scoped"] is expected


def test_malformed_security_entry_doesnt_crash():
    """Regression: security: [null] / non-mapping entries must be skipped."""
    doc = {"openapi": "3.0.0", "security": [None, {"bearerAuth": []}],
           "paths": {"/x": {"get": {"operationId": "x"}}}}
    inv = build_inventory(doc)                             # must not raise
    ep = inv["endpoints"][0]
    assert ep["auth_required"] is True
    assert ep["security"] == ["bearerAuth"]


def test_cyclic_ref_terminates():
    doc = {
        "openapi": "3.0.0",
        "components": {"schemas": {"Node": {"$ref": "#/components/schemas/Node"}}},
        "paths": {"/n": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Node"}}}}}}},
    }
    inv = build_inventory(doc)          # must not hang or crash
    assert inv["endpoints"][0]["body_fields"] == []
