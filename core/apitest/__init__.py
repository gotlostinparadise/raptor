"""API security-testing substrate.

Turns an API description (OpenAPI/Swagger, a Postman collection, or a
GraphQL introspection result) into two mechanical artefacts that ground
the LLM-driven ``/api`` workflow:

- ``api-inventory.json`` — a normalised endpoint list (method, path,
  parameters, request-body fields, auth requirement, object-scope
  heuristic, and the OWASP API Top-10 categories each endpoint most
  invites).
- ``authz-matrix.json`` — a seed authorization test matrix: one row per
  object-scoped or privileged endpoint, describing the cross-account
  replay to run for BOLA (API1), BFLA (API5) and property-level
  authorization (API3).

The parsing is deterministic and dependency-light (stdlib + optional
PyYAML for YAML specs). It never contacts the network — it only reads a
local description file. Discovery of *undocumented* endpoints is a
separate, dynamic step owned by the workflow skill.
"""

from core.apitest.inventory import (
    build_authz_matrix,
    build_inventory,
    detect_kind,
    load_spec,
)

__all__ = [
    "build_authz_matrix",
    "build_inventory",
    "detect_kind",
    "load_spec",
]
