"""Sandboxed execution + output-parsing helpers for tool-wrapper sources.

The passive sources (crt.sh, Censys) make in-process HTTP calls through an
egress-allowlisted :class:`~core.http.HttpClient`. The *active* sources instead
shell out to external binaries (subfinder, dnsx, naabu, httpx). Those need a
different containment story, and it splits in two because of how the kernel
primitives compose (see ``core/sandbox/context.py``):

  * **HTTP-layer tools** (httpx and the bespoke HTTP probes) can run behind the
    in-process HTTPS egress proxy, which host-allowlists their egress. The proxy
    forces ``seccomp_block_udp`` and pins TCP to its own port — strong
    containment. Use :func:`run_http_tool`.

  * **DNS / port tools** (subfinder, dnsx, naabu) use UDP/53 and, for the port
    scanner, connect to arbitrary TCP ports — neither of which can traverse an
    HTTP CONNECT proxy. They run under a namespace with ``block_network=False``,
    ``restrict_reads=True`` (``$HOME`` and credentials denied), resource rlimits,
    and a sanitised environment. Host-level egress allowlisting is not
    achievable for raw DNS/SYN; the compensating control is that **the argv is
    built by RAPTOR from in-scope roots (never attacker input)** and the tool's
    stdout is parsed in-process — the trust boundary is the parser, which is the
    same model the passive sources already rely on. Use :func:`run_net_tool`.

Both helpers are the **injection seam** for offline tests: a source takes a
``runner=`` callable defaulting to one of these, and a test passes a fake that
returns a canned :class:`ToolResult` without touching the sandbox or the
network. Nothing here is exercised in CI — a source only invokes its runner when
its wrapped binary is on ``PATH`` (:func:`tool_available`), and tests inject.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


@dataclass
class ToolResult:
    """Normalised result of a tool invocation — the seam's return type.

    A thin stand-in for :class:`subprocess.CompletedProcess` carrying only what
    a source needs, so a fake runner in a test can produce one trivially.
    """

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False


# ProjectDiscovery's tool-manager (pdtm) installs the real PD binaries here.
# A RAPTOR venv commonly ships the *Python* ``httpx`` CLI, which shadows PD's
# ``httpx`` on PATH and breaks the httpx source (wrong binary -> bad/empty
# output). Prefer the pdtm install dir so a bare tool name resolves to
# ProjectDiscovery's binary, not the collision. Override with RAPTOR_PDTM_BIN.
def _pdtm_bin_dir() -> Path:
    return Path(os.environ.get("RAPTOR_PDTM_BIN")
                or os.path.expanduser("~/.pdtm/go/bin"))


def resolve_binary(name: str) -> Optional[str]:
    """Resolve a tool name to an executable path, preferring the pdtm install
    dir over ``PATH`` (defeats the venv ``httpx`` shadow). A name that already
    contains a path separator is honoured as-is. ``None`` when found nowhere."""
    if os.sep in name or (os.altsep and os.altsep in name):
        return name if os.access(name, os.X_OK) else None
    cand = _pdtm_bin_dir() / name
    if cand.is_file() and os.access(cand, os.X_OK):
        return str(cand)
    return shutil.which(name)


def _resolve_argv0(cmd: Sequence[str]) -> List[str]:
    """``cmd`` with argv[0] rewritten to the resolved PD binary path (no-op
    when it can't be resolved — the OS/sandbox then does its own lookup)."""
    out = list(cmd)
    if out:
        resolved = resolve_binary(out[0])
        if resolved:
            out[0] = resolved
    return out


def tool_available(binary: str) -> bool:
    """True when ``binary`` resolves to an executable (pdtm dir or ``PATH``)."""
    return resolve_binary(binary) is not None


def parse_jsonl(stdout: str) -> List[Dict[str, Any]]:
    """Parse a tool's JSON-lines stdout into a list of dicts.

    ProjectDiscovery tools emit one JSON object per line under ``-json`` / ``-j``
    / ``-oJ``. Non-JSON and blank lines are skipped rather than raising — a
    banner line or a progress message must not abort a whole run's parse.
    """
    out: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _child_env(env: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """The environment handed to a child tool.

    ``env`` is the orchestrator-supplied sanitised environment (already run
    through :func:`core.config.RaptorConfig.get_safe_env`). Fall back to
    computing it here so a source is usable standalone in a test/CLI that didn't
    thread one through.
    """
    if env:
        return dict(env)
    from core.config import RaptorConfig
    return dict(RaptorConfig.get_safe_env())


def _completed_to_result(cp: subprocess.CompletedProcess) -> ToolResult:
    return ToolResult(
        stdout=cp.stdout or "" if isinstance(cp.stdout, str) else "",
        stderr=cp.stderr or "" if isinstance(cp.stderr, str) else "",
        returncode=cp.returncode,
    )


def run_http_tool(
    cmd: Sequence[str],
    *,
    output: Path,
    proxy_hosts: Sequence[str],
    timeout: int = 180,
    env: Optional[Mapping[str, str]] = None,
) -> ToolResult:
    """Run an HTTP-layer tool behind the hostname-allowlisted egress proxy.

    ``proxy_hosts`` is the set of in-scope hosts the tool is permitted to reach
    (typically the names/IPs being probed). The child can reach nothing else.
    """
    from core.sandbox.context import run_untrusted_networked
    try:
        cp = run_untrusted_networked(
            _resolve_argv0(cmd),
            output=str(output),
            proxy_hosts=list(proxy_hosts),
            timeout=timeout,
            capture_output=True,
            text=True,
            env=_child_env(env),
            caller_label="recon",
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                          timed_out=True)
    return _completed_to_result(cp)


def run_net_tool(
    cmd: Sequence[str],
    *,
    output: Path,
    tcp_ports: Optional[Sequence[int]] = None,
    timeout: int = 300,
    env: Optional[Mapping[str, str]] = None,
    readable_paths: Optional[Sequence[str]] = None,
) -> ToolResult:
    """Run a DNS / port tool under a network-open, read-restricted namespace.

    ``block_network=False`` keeps UDP/53 (and DoH/443) reachable; ``output`` and
    ``tcp_ports`` engage Landlock (filesystem write-restricted, ``$HOME`` reads
    denied via ``restrict_reads``). Pass ``tcp_ports=None`` for a port scanner
    that must connect to arbitrary ports — network egress is then unrestricted by
    design, and containment rests on read-restriction + rlimits + the
    RAPTOR-built argv. ``readable_paths`` extends the read allowlist for tools
    that need an operator-supplied input file (e.g. a bruteforce wordlist)
    outside the default system/output dirs.
    """
    from core.sandbox.context import sandbox
    try:
        with sandbox(
            block_network=False,
            output=str(output),
            restrict_reads=True,
            allowed_tcp_ports=list(tcp_ports) if tcp_ports else None,
            readable_paths=list(readable_paths) if readable_paths else None,
            caller_label="recon",
        ) as run:
            cp = run(
                _resolve_argv0(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_child_env(env),
                # ``env`` is already the orchestrator's get_safe_env(); tell the
                # sandbox to (idempotently) strip DANGEROUS_ENV_VARS from it too,
                # which also silences the "get_safe_env not applied" warning.
                strict_env=True,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                          timed_out=True)
    return _completed_to_result(cp)


def run_local_tool(
    cmd: Sequence[str],
    *,
    timeout: int = 120,
    env: Optional[Mapping[str, str]] = None,
) -> ToolResult:
    """Run a no-network local generator (e.g. a permutation tool) as trusted.

    RAPTOR-chosen argv, no target contact, no attacker-derived input — only
    ``get_safe_env`` + rlimits apply (``run_trusted``).
    """
    from core.sandbox.context import run_trusted
    try:
        cp = run_trusted(
            _resolve_argv0(cmd), timeout=timeout, capture_output=True, text=True,
            env=_child_env(env),
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                          timed_out=True)
    return _completed_to_result(cp)


__all__ = [
    "ToolResult", "tool_available", "parse_jsonl",
    "run_http_tool", "run_net_tool", "run_local_tool",
]
