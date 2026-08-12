"""Tests for core.fileupload — multipart upload, path discovery, execute/retrieve oracle."""

import json
from pathlib import Path

from core.fileupload.config import from_dict
from core.fileupload.multipart import build_multipart
from core.fileupload.oracle import UploadMarker, classify_upload
from core.fileupload.runner import run_fileupload
from core.session.tests.fakes import FakeClient, resp

_M = UploadMarker(token="tok1", a=7, b=191)   # product 1337


def test_oracle_executed_vs_retrievable_vs_none():
    assert classify_upload(resp(200, body=b"tok11337tok1"), _M) == "executed"
    assert classify_upload(resp(200, body=_M.php().encode()), _M) == "retrievable"
    assert classify_upload(resp(200, body=b"nothing here"), _M) == ""
    assert classify_upload(resp(404, body=b"tok11337tok1"), _M) == ""   # not served


def test_multipart_shape():
    body, headers = build_multipart("file", "x.php", b"<?php ?>", "application/x-php",
                                    {"Upload": "Upload"}, "BOUND")
    assert headers["Content-Type"] == "multipart/form-data; boundary=BOUND"
    assert b'filename="x.php"' in body and b'name="Upload"' in body
    assert body.endswith(b"--BOUND--\r\n")


def _cfg(**kw):
    base = {"base_url": "http://dvwa.test", "authorization": "lab",
            "upload_url": "/upload", "retrieve_template": "/uploads/{filename}"}
    base.update(kw)
    return from_dict(base)


import re as _re


def _upload_app(store, *, execute):
    """A vulnerable upload app: stores the file, serves it back — and, if
    ``execute``, actually EVALUATES the stored PHP marker (echo TOKEN.(a*b).TOKEN)
    so the retrieved body carries the computed product, exactly like a real server."""
    def h(method, url, headers, body):
        if method == "POST":
            m = body.split(b'filename="', 1)
            if len(m) == 2:
                fn = m[1].split(b'"', 1)[0].decode()
                content = body.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
                store[fn] = content
            return resp(200, body=b"uploaded")
        for fn, content in store.items():
            if fn in url:
                mm = _re.search(rb"echo '([^']+)'\.\((\d+)\*(\d+)\)\.'([^']+)'", content)
                if execute and mm:
                    tok, a, b = mm.group(1).decode(), int(mm.group(2)), int(mm.group(3))
                    return resp(200, body=f"{tok}{a * b}{tok}".encode())
                return resp(200, body=content)
        return resp(404, body=b"not found")
    return lambda hosts: FakeClient(h)


def test_runner_confirms_executed(tmp_path):
    store = {}
    run = run_fileupload(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=_upload_app(store, execute=True))
    assert run.verdict == "executed"
    rows = [json.loads(l) for l in (Path(tmp_path) / "normalized" / "vulns.jsonl").read_text().splitlines() if l.strip()]
    assert any(r["vuln_class"] == "unrestricted_file_upload" for r in rows)


def test_runner_confirms_retrievable(tmp_path):
    store = {}
    run = run_fileupload(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=_upload_app(store, execute=False))
    assert run.verdict == "retrievable"


def test_runner_no_finding_when_not_served(tmp_path):
    def h(method, url, headers, body):
        return resp(200, body=b"uploaded") if method == "POST" else resp(404)
    run = run_fileupload(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=lambda hosts: FakeClient(h))
    assert run.verdict == "" and [f for f in run.findings if f.get("proof")] == []


def test_dry_run_uploads_nothing(tmp_path):
    run = run_fileupload(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0
