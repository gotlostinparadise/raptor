"""Per-target sensitivity gate for external-LLM egress (Feature 1).

A run's target (an engagement source tree / project) is classified as
SENSITIVE or EXTERNAL_OK. When the active run is SENSITIVE, RAPTOR
refuses to build *any* LLM provider whose destination is not
first-party-trusted — so target code never leaves for OmniRoute or any
other third-party gateway. First-party-trusted = Anthropic direct
(``api.anthropic.com``), Claude Code, AWS Bedrock (your own account),
and local Ollama (never leaves the box).

Fail-closed
-----------
An UNKNOWN (never-classified) target, once a run engages the gate,
resolves to SENSITIVE. The operator is asked once; the answer persists
in ``~/.config/raptor/sensitivity.json``. Until answered, the target is
treated as sensitive and OmniRoute is refused.

Enforcement point
-----------------
:func:`guard_model` is called from :func:`core.llm.providers.create_provider`
— the single transport-agnostic chokepoint every caller passes through
(in-process SDK path, the credential-isolation dispatcher worker, and
cve-diff's ``ResilientLLMClient``). Raising there prevents the provider
from ever being constructed, so no bytes leave regardless of whether the
egress proxy happens to be up. Defense-in-depth: the egress proxy
allowlist (:mod:`core.llm.egress`) additionally drops guarded hosts for
sensitive runs.

Tri-state, so we don't retroactively break library/test code
-------------------------------------------------------------
``UNSET`` => the gate is dormant (allow). Only a run that calls
:func:`set_current_target` (real analysis: ``/agentic`` etc.) or that
sets ``RAPTOR_SENSITIVE`` engages the deny-by-default behaviour. Unit
tests that construct a provider directly never set a target context, so
they keep working; a genuine analysis run resolves UNKNOWN -> SENSITIVE.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from core.logging import get_logger

logger = get_logger()

# ---------------------------------------------------------------------------
# Trust model
# ---------------------------------------------------------------------------
# A provider/destination is TRUSTED when target source may flow to it even
# on a sensitive run. Everything else is GUARDED (blocked when sensitive).

# Providers that are first-party by construction, independent of host.
_TRUSTED_PROVIDERS = frozenset({
    "anthropic",                    # api.anthropic.com (your Anthropic account)
    "bedrock",                      # Anthropic models on YOUR AWS account
    "ollama",                       # local, never leaves the machine
    "claudecode", "claude_code", "claude-code",
    "claudecode-resumable", "claude_code_resumable", "claude-code-resumable",
})

# Hosts that are trusted even when reached via a generic OpenAI-compatible
# provider (e.g. someone points ``api_base`` straight at Anthropic).
_TRUSTED_HOSTS = frozenset({"api.anthropic.com"})

_LOOPBACK = ("localhost", "127.0.0.1", "::1")

# Static defaults for providers whose native SDK hardcodes the base URL.
_KNOWN_DEFAULT_HOSTS = {"anthropic": "https://api.anthropic.com"}

# ---------------------------------------------------------------------------
# Tri-state
# ---------------------------------------------------------------------------
SENSITIVE = "sensitive"
EXTERNAL_OK = "external_ok"
UNSET = "unset"

# Marker file an operator can drop in a target root to force SENSITIVE
# regardless of the registry.
MARKER_FILENAME = ".raptor-sensitive"


def _registry_path() -> Path:
    override = os.environ.get("RAPTOR_SENSITIVITY_REGISTRY")
    if override:
        return Path(override)
    return Path.home() / ".config" / "raptor" / "sensitivity.json"


# ---------------------------------------------------------------------------
# Registry (persisted classifications)
# ---------------------------------------------------------------------------

def _normalise_key(target: str | os.PathLike) -> str:
    """Registry key for a target. Absolute resolved path, or a
    ``project:<name>`` sentinel passed through verbatim."""
    s = str(target)
    if s.startswith("project:"):
        return s
    try:
        return str(Path(s).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        return s


def _load_registry() -> dict:
    path = _registry_path()
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"version": 1, "entries": {}}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("sensitivity: unreadable registry %s (%s) — "
                       "treating as empty (fail-closed downstream)", path, exc)
        return {"version": 1, "entries": {}}
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        logger.warning("sensitivity: malformed registry %s — treating as empty", path)
        return {"version": 1, "entries": {}}
    return data


def _save_registry(data: dict) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".sensitivity-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def set_classification(target: str | os.PathLike, sensitive: bool,
                       note: Optional[str] = None) -> None:
    """Persist a SENSITIVE / EXTERNAL_OK decision for ``target``."""
    key = _normalise_key(target)
    data = _load_registry()
    data["entries"][key] = {
        "sensitive": bool(sensitive),
        "note": note or "",
        "ts": int(time.time()),
    }
    _save_registry(data)
    logger.info("sensitivity: %s -> %s", key,
                SENSITIVE if sensitive else EXTERNAL_OK)


def get_classification(target: str | os.PathLike) -> Optional[bool]:
    """Return ``True`` (sensitive) / ``False`` (external ok) / ``None``
    (unknown) for ``target``, consulting marker file then registry."""
    s = str(target)
    if not s.startswith("project:"):
        try:
            if (Path(s).expanduser() / MARKER_FILENAME).is_file():
                return True
        except (OSError, RuntimeError, ValueError):
            pass
    entry = _load_registry()["entries"].get(_normalise_key(target))
    if entry is None:
        return None
    return bool(entry.get("sensitive"))


def list_classifications() -> dict:
    return dict(_load_registry()["entries"])


# ---------------------------------------------------------------------------
# Current-run context
# ---------------------------------------------------------------------------
_current_state: str = UNSET
_current_target: Optional[str] = None
_current_out_dir: Optional[str] = None
_current_known: bool = True  # False when the active target was UNKNOWN


def _state_from_env() -> Optional[str]:
    raw = os.environ.get("RAPTOR_SENSITIVE")
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on", "sensitive"):
        return SENSITIVE
    if v in ("0", "false", "no", "off", "external_ok", "external"):
        return EXTERNAL_OK
    logger.warning("sensitivity: unrecognised RAPTOR_SENSITIVE=%r — ignoring", raw)
    return None


def current_state() -> str:
    """Resolve the active run's state. ``RAPTOR_SENSITIVE`` env wins
    (cross-process authority), else the module context set by
    :func:`set_current_target`, else ``UNSET`` (gate dormant)."""
    env = _state_from_env()
    if env is not None:
        return env
    return _current_state


def current_target_is_known() -> bool:
    """True unless the active run's target was UNKNOWN (never
    classified) and therefore defaulted to SENSITIVE."""
    return _current_known


def set_current_target(target: str | os.PathLike | None,
                       out_dir: str | os.PathLike | None = None) -> str:
    """Engage the gate for ``target`` and return the resolved state.

    UNKNOWN targets resolve to SENSITIVE (fail-closed) and flip
    :func:`current_target_is_known` to ``False`` so the caller can
    prompt the operator once. An explicit ``RAPTOR_SENSITIVE`` env var
    still overrides the outcome downstream via :func:`current_state`.
    """
    global _current_state, _current_target, _current_out_dir, _current_known
    _current_out_dir = str(out_dir) if out_dir is not None else None
    if target is None:
        _current_target = None
        _current_known = False
        _current_state = SENSITIVE
        return _current_state
    _current_target = str(target)
    verdict = get_classification(target)
    if verdict is None:
        _current_known = False
        _current_state = SENSITIVE
        logger.info("sensitivity: target %s UNKNOWN — defaulting to SENSITIVE "
                    "(external LLMs blocked until classified)", _current_target)
    else:
        _current_known = True
        _current_state = SENSITIVE if verdict else EXTERNAL_OK
    return _current_state


def propagate_env() -> None:
    """Export the resolved state to ``os.environ`` so any child process
    inherits the gate (relevant when LLM work is fanned out to worker
    processes). No-op when ``RAPTOR_SENSITIVE`` is already set — an
    explicit operator override always wins — or when the state is UNSET.
    """
    if os.environ.get("RAPTOR_SENSITIVE"):
        return
    if _current_state in (SENSITIVE, EXTERNAL_OK):
        os.environ["RAPTOR_SENSITIVE"] = _current_state


def engage_for_run(target, out_dir=None, *, logger_=None) -> str:
    """Engage the gate for an analysis run and propagate to children.

    Convenience wrapper used by command entrypoints (``/agentic``,
    ``/codeql``, ``/analyze``): resolves + sets the target context,
    exports ``RAPTOR_SENSITIVE`` for any worker children, and logs a
    one-line warning when the target is UNCLASSIFIED (fail-closed to
    SENSITIVE). Never raises — a gate that breaks run startup would be
    worse than the leak it guards against; enforcement still happens at
    :func:`guard_model`.
    """
    log = logger_ or logger
    try:
        state = set_current_target(target, out_dir)
        propagate_env()
        if state == SENSITIVE and not current_target_is_known():
            log.warning(
                "Sensitivity: target %s is UNCLASSIFIED — treating as "
                "SENSITIVE; external LLMs (OmniRoute etc.) blocked. Run "
                "`libexec/raptor-sensitivity set %s external` to allow them "
                "for this non-sensitive target.", target, target,
            )
        return state
    except Exception as exc:  # noqa: BLE001 — must not break run startup
        log.debug("sensitivity gate not engaged: %s", exc)
        return UNSET


def reset_current() -> None:
    """Clear the module context (test hygiene)."""
    global _current_state, _current_target, _current_out_dir, _current_known
    _current_state = UNSET
    _current_target = None
    _current_out_dir = None
    _current_known = True


# ---------------------------------------------------------------------------
# Trust decision
# ---------------------------------------------------------------------------

def _hostname_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except (ValueError, TypeError):
        return ""


def resolved_host(config) -> str:
    """Best-effort destination hostname for a ModelConfig."""
    from .model_data import PROVIDER_ENDPOINTS
    provider = (getattr(config, "provider", "") or "").lower()
    url = (
        getattr(config, "api_base", None)
        or PROVIDER_ENDPOINTS.get(provider)
        or _KNOWN_DEFAULT_HOSTS.get(provider)
    )
    return _hostname_of(url) if url else ""


def model_is_trusted(config) -> bool:
    """True when target source may flow to this model even on a
    sensitive run (first-party / local)."""
    provider = (getattr(config, "provider", "") or "").lower()
    if provider in _TRUSTED_PROVIDERS:
        return True
    host = resolved_host(config)
    if not host:
        # No resolvable host and a non-trusted provider — treat as
        # guarded rather than guess.
        return False
    if host.lower() in _LOOPBACK:
        return True
    return host.lower() in _TRUSTED_HOSTS


class OmniEgressBlocked(RuntimeError):
    """Raised when a sensitive run tries to reach a guarded (non
    first-party) LLM destination."""

    def __init__(self, host: str, config) -> None:
        self.host = host
        self.provider = getattr(config, "provider", "?")
        self.model = getattr(config, "model_name", "?")
        super().__init__(
            f"Sensitive-target gate: refusing to send to "
            f"{self.provider}/{self.model} via {host or '<unknown host>'}. "
            f"This run's target is classified SENSITIVE, so only "
            f"first-party destinations (Anthropic / Claude Code / Bedrock / "
            f"local Ollama) are allowed.\n"
            f"  To permit external LLMs for this NON-sensitive target:\n"
            f"    libexec/raptor-sensitivity set <target> external\n"
            f"  Or for a one-off run:  RAPTOR_SENSITIVE=external_ok ...\n"
            f"  Sensitive engagements should instead route to Anthropic "
            f"(default) or RAPTOR_CONFIG=~/.config/raptor/models.anthropic.json."
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _audit(decision: str, config, reason: str,
           out_dir: str | os.PathLike | None = None) -> None:
    record = {
        "ts": int(time.time()),
        "decision": decision,          # "allow" | "deny"
        "provider": getattr(config, "provider", None),
        "model": getattr(config, "model_name", None),
        "host": resolved_host(config),
        "reason": reason,
        "target": _current_target,
        "state": current_state(),
    }
    target_dir = out_dir or _current_out_dir
    try:
        if target_dir:
            path = Path(target_dir) / "omni-egress.jsonl"
        else:
            path = _registry_path().parent / "omni-egress.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.debug("sensitivity: audit write skipped (%s)", exc)


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

def guard_model(config, out_dir: str | os.PathLike | None = None) -> None:
    """Enforce the sensitivity gate for ``config``.

    No-op unless the active run is SENSITIVE. Raises
    :class:`OmniEgressBlocked` when a sensitive run targets a guarded
    (non first-party) destination.
    """
    if current_state() != SENSITIVE:
        return  # UNSET (dormant) or EXTERNAL_OK (opted in) — allow.
    if model_is_trusted(config):
        logger.debug("sensitivity: allow trusted %s/%s",
                     getattr(config, "provider", "?"),
                     getattr(config, "model_name", "?"))
        return
    host = resolved_host(config)
    _audit("deny", config, "sensitive run; guarded destination", out_dir)
    raise OmniEgressBlocked(host, config)
