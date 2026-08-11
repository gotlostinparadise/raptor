"""Tests for core.repeater — spec tampering, PoC generation, send/diff."""

import json

from core.repeater import poc
from core.repeater.cli import main
from core.repeater.repeater import Repeater
from core.repeater.request import RequestSpec
from core.session.tests.fakes import FakeClient, resp


def _spec():
    return RequestSpec(method="POST", url="https://api.test/orders?id=1",
                       headers={"Authorization": "Bearer T"}, body='{"qty":1}')


def test_request_tamper_is_immutable():
    s = _spec()
    s2 = s.with_query("id", "2")
    assert "id=2" in s2.url and "id=1" in s.url          # original unchanged
    s3 = s.with_header("X-Test", "1")
    assert s3.headers.get("X-Test") == "1" and "X-Test" not in s.headers


def test_to_curl_includes_method_headers_body():
    c = poc.to_curl(_spec())
    assert "-X POST" in c and "Authorization: Bearer T" in c and "--data-raw" in c


def test_to_python_is_runnable_and_escapes():
    script = poc.to_python(_spec())
    # compiles as valid Python
    compile(script, "<poc>", "exec")
    assert "urllib.request" in script and "Bearer T" in script


def test_to_http_raw_has_request_line_and_host():
    raw = poc.to_http_raw(_spec())
    assert raw.startswith("POST /orders?id=1 HTTP/1.1")
    assert "Host: api.test" in raw


def test_repeater_send_and_diff():
    calls = {"n": 0}

    def h(method, url, headers, body):
        calls["n"] += 1
        # tampered id=2 returns a bigger body
        return resp(200, body=b"X" * (50 if "id=2" in url else 10))

    rep = Repeater(FakeClient(h))
    a = rep.send(_spec())
    b = rep.send(_spec().with_query("id", "2"))
    d = Repeater.diff(a, b)
    assert d["body_changed"] and d["length_delta"] == 40
    assert calls["n"] == 2


def test_cli_poc_offline(tmp_path):
    spec = tmp_path / "req.json"
    spec.write_text(json.dumps({"method": "GET", "url": "https://x.test/a"}))
    assert main(["--spec", str(spec), "--poc", "curl"]) == 0


def test_cli_send_requires_active_and_auth(tmp_path, capsys):
    spec = tmp_path / "req.json"
    spec.write_text(json.dumps({"method": "GET", "url": "https://x.test/a"}))
    assert main(["--spec", str(spec), "--send"]) == 2
    assert "active" in capsys.readouterr().err
    assert main(["--spec", str(spec), "--send", "--active"]) == 2
    assert "authorization" in capsys.readouterr().err


def test_cli_poc_to_file(tmp_path):
    spec = tmp_path / "req.json"
    spec.write_text(json.dumps({"method": "POST", "url": "https://x.test/a", "body": "z"}))
    out = tmp_path / "poc.py"
    assert main(["--spec", str(spec), "--poc", "python", "--out", str(out)]) == 0
    compile(out.read_text(), "<poc>", "exec")
