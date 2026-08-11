"""Business-logic & race-condition testing — the flaws automation misses most.

TOCTOU races (double-spend, coupon reuse, stock/limit bypass) and workflow abuse
are hard to scan for because the vulnerability is in *timing* and *state*, not in
a single response. This capability fires N identical requests simultaneously (a
single-packet-attack approximation) and applies a **state oracle**: if a limited
operation succeeds more times than the operator says it should, the limit is not
atomic — a confirmed race (``PROOF_STATE_ORACLE``).

Pieces: :mod:`core.racecond.harness` (concurrency), :mod:`core.racecond.oracle`
(the state verdict), :mod:`core.racecond.config`, :mod:`core.racecond.runner`,
:mod:`core.racecond.cli`.
"""

from core.racecond.config import RaceConfig, RaceTest, load_config
from core.racecond.runner import RaceRun, run_race

__all__ = ["RaceConfig", "RaceTest", "load_config", "RaceRun", "run_race"]
