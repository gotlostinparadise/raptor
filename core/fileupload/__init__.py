"""Unrestricted file-upload detection (M4 S5).

Uploads a marker file with a dangerous extension, locates where it was stored,
and reads it back. Two confirmations, both mechanical:

  * **executed** — the uploaded file runs server-side (a ``<?php echo a*b ?>``
    marker returns the *computed product* wrapped in a token, which mere serving
    of the source cannot produce): the strongest proof;
  * **retrievable** — the uploaded content is served back verbatim (stored +
    reachable), an unrestricted upload even if not executed.

Both are CWE-434 (:data:`core.webgraph.model.PROOF_REFLECTED_MARKER`).
"""

from __future__ import annotations

from core.fileupload.oracle import classify_upload

__all__ = ["classify_upload"]
