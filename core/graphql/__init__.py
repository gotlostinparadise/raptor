"""GraphQL security testing — a distinct, fast-growing surface generic scanners miss.

Covers the GraphQL-specific weaknesses: introspection left open in production
(information disclosure) and alias/batching amplification (a DoS vector), with
argument injection delegated to `/inject` and field-level authorization to
`/webauthz` (a GraphQL query is a ``POST /graphql`` body those tools already
handle), so nothing is duplicated.

Pieces: :mod:`core.graphql.introspection` (query/parse, reusing the `/api`
GraphQL parser), :mod:`core.graphql.checks`, :mod:`core.graphql.config`,
:mod:`core.graphql.runner`, :mod:`core.graphql.cli`.
"""

from core.graphql.config import GraphQLConfig, load_config
from core.graphql.runner import GraphQLRun, run_graphql

__all__ = ["GraphQLConfig", "load_config", "GraphQLRun", "run_graphql"]
