"""Pluggable OAST collaborator backends.

The client (:mod:`core.oast.client`) never talks to a network directly — it asks
a *backend* for its callback ``domain`` and polls it for
:class:`~core.oast.interaction.Interaction` s. That indirection is the "server
optional" design: the same client works against

  - :class:`InMemoryBackend` — a self-contained collaborator with no network, for
    tests and for a locally-run listener that records interactions in-process;
  - :class:`HttpPollBackend` — a real backend that polls a self-hosted (or
    hosted) JSON collector over the egress-allowlisted :class:`core.http.HttpClient`.

A full interactsh-protocol backend (RSA registration + encrypted polling) is an
additional subclass that slots in here without touching the client — the reason
the boundary is a two-method ABC.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional

from core.oast.interaction import Interaction


class OastBackend(abc.ABC):
    """A collaborator: it owns a callback domain and reports interactions."""

    @property
    @abc.abstractmethod
    def domain(self) -> str:
        """The base callback domain; payload hosts are ``<token>.<domain>``."""
        raise NotImplementedError

    @abc.abstractmethod
    def poll(self, tokens: Optional[List[str]] = None) -> List[Interaction]:
        """Return interactions observed since the last poll.

        ``tokens`` optionally narrows to specific correlation tokens; a backend
        that can't filter server-side returns all and lets the client correlate.
        """
        raise NotImplementedError

    def register(self, token: str) -> None:
        """Optional hook: tell the backend to expect ``token`` (no-op default)."""


class InMemoryBackend(OastBackend):
    """A working, network-free collaborator. Feed it interactions in tests, or
    have a local listener call :meth:`record` for a genuine self-hosted mode."""

    def __init__(self, domain: str = "oast.local") -> None:
        self._domain = domain
        self._pending: List[Interaction] = []

    @property
    def domain(self) -> str:
        return self._domain

    def record(self, interaction: Interaction) -> None:
        """Register an observed interaction (called by a local listener/test)."""
        self._pending.append(interaction)

    def poll(self, tokens: Optional[List[str]] = None) -> List[Interaction]:
        if tokens is None:
            out = list(self._pending)
        else:
            wanted = set(tokens)

            def match(i: Interaction) -> bool:
                # Match the token field, or a wanted token appearing as a host
                # label — the latter is how DNS-exfil hits (token in hostname,
                # token field empty) still correlate.
                if i.token in wanted:
                    return True
                labels = set((i.host or "").lower().rstrip(".").split("."))
                return bool(labels & wanted)

            out = [i for i in self._pending if match(i)]
        # drain only what we return, so unmatched traffic can still arrive later
        returned_ids = {id(i) for i in out}
        self._pending = [i for i in self._pending if id(i) not in returned_ids]
        return out


class HttpPollBackend(OastBackend):
    """Poll a self-hosted JSON collector. Egress-allowlisted by construction.

    The collector is any endpoint returning ``{"interactions": [ {...}, ... ]}``
    for ``GET <poll_url>?token=<t>`` (or all interactions when no token). This is
    the simple, crypto-free shape a self-hosted callback server exposes; the
    hosted interactsh protocol is a separate backend.
    """

    def __init__(self, domain: str, poll_url: str, client: Any) -> None:
        self._domain = domain
        self.poll_url = poll_url
        self.client = client  # a core.http.HttpClient (egress-allowlisted)

    @property
    def domain(self) -> str:
        return self._domain

    def poll(self, tokens: Optional[List[str]] = None) -> List[Interaction]:
        out: List[Interaction] = []
        query_tokens = tokens if tokens is not None else [None]
        for tok in query_tokens:
            url = self.poll_url + (f"?token={tok}" if tok else "")
            try:
                data: Dict[str, Any] = self.client.get_json(url, retries=0)
            except Exception:
                continue
            for row in (data.get("interactions") or []):
                out.append(Interaction.from_dict(row, token=tok or ""))
        return out


__all__ = ["OastBackend", "InMemoryBackend", "HttpPollBackend"]
