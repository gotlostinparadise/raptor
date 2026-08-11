"""The payload store — bundled seed + enrichment loaders + context query."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from core.payloads.entry import CTX_ANY, PayloadEntry
from core.payloads.seed import SEED


class PayloadStore:
    """A queryable set of :class:`PayloadEntry`, seeded and enrichable."""

    def __init__(self, entries: Optional[Iterable[PayloadEntry]] = None) -> None:
        self._by_id: Dict[str, PayloadEntry] = {}
        for e in (entries if entries is not None else SEED):
            self._by_id[e.id] = e

    def add(self, entries: Iterable[PayloadEntry]) -> int:
        """Merge entries (id wins; new ids added). Returns count added."""
        n = 0
        for e in entries:
            if e.id not in self._by_id:
                n += 1
            self._by_id[e.id] = e
        return n

    def all(self) -> List[PayloadEntry]:
        return list(self._by_id.values())

    def get(self, entry_id: str) -> Optional[PayloadEntry]:
        return self._by_id.get(entry_id)

    def select(
        self, vuln_class: str, *, contexts: Optional[List[str]] = None,
        include_destructive: bool = False, tag: Optional[str] = None,
    ) -> List[PayloadEntry]:
        """Entries for ``vuln_class``, context-matching first, destructive dropped.

        Ordering: entries whose context matches one of ``contexts`` come first,
        then context-agnostic (``any``) entries, then the rest — so a context-aware
        caller tries the most-likely-to-fire vectors first.
        """
        ents = [e for e in self._by_id.values()
                if e.vuln_class == vuln_class
                and (include_destructive or not e.destructive)
                and (tag is None or tag in e.tags)]
        if not contexts:
            return ents
        matched = [e for e in ents if e.context in contexts]
        anyc = [e for e in ents if e.context == CTX_ANY and e not in matched]
        rest = [e for e in ents if e not in matched and e not in anyc]
        return matched + anyc + rest

    def load(self, loader, **kwargs) -> int:
        """Enrich from a loader callable returning an iterable of entries."""
        return self.add(loader(**kwargs))


_DEFAULT: Optional[PayloadStore] = None


def default_store() -> PayloadStore:
    """Process-wide default store (seed only until a loader enriches it)."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = PayloadStore()
    return _DEFAULT


__all__ = ["PayloadStore", "default_store"]
