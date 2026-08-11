"""Pure tests for core.clientside.analyzers."""

from core.clientside import analyzers as A


def test_cors_reflection_with_credentials_is_high():
    out = A.cors_analysis("https://evil.test", {
        "Access-Control-Allow-Origin": "https://evil.test",
        "Access-Control-Allow-Credentials": "true"})
    assert out and out[0]["type"] == "cors_origin_reflection"
    assert out[0]["severity"] == "high" and out[0]["credentials"] is True


def test_cors_clean_when_not_reflected():
    assert A.cors_analysis("https://evil.test", {
        "Access-Control-Allow-Origin": "https://self.test"}) == []


def test_cors_null_origin_flagged():
    out = A.cors_analysis("https://x", {"Access-Control-Allow-Origin": "null"})
    assert any(f["type"] == "cors_null_origin" for f in out)


def test_csp_missing_and_unsafe_inline():
    assert A.csp_analysis(None)[0]["type"] == "csp_missing"
    out = A.csp_analysis("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert any(f["type"] == "csp_unsafe_inline" for f in out)


def test_csp_wildcard_source():
    out = A.csp_analysis("script-src *")
    assert any(f["type"] == "csp_wildcard_script_source" for f in out)


def test_clickjacking_when_no_protection():
    assert A.clickjacking({}, {}) is not None
    assert A.clickjacking({"X-Frame-Options": "DENY"}, {}) is None
    assert A.clickjacking({}, {"frame-ancestors": ["'none'"]}) is None


def test_cookie_flags_missing():
    out = A.cookie_flags(["session=abc; Path=/"])
    assert out[0]["cookie"] == "session"
    assert set(out[0]["missing"]) == {"secure", "httponly", "samesite"}
    # a fully-flagged cookie is clean
    assert A.cookie_flags(["s=1; Secure; HttpOnly; SameSite=Strict"]) == []


def test_cookie_flags_matches_attributes_not_substrings():
    # regression: a cookie whose NAME/VALUE contains "secure"/"httponly" must
    # still be flagged when the actual attributes are absent
    out = A.cookie_flags(["pref=theme_secure_httponly_samesite; Path=/"])
    assert set(out[0]["missing"]) == {"secure", "httponly", "samesite"}


def test_open_redirect_subdomain_prefix_not_flagged():
    # marker as a subdomain PREFIX of the real host is not a redirect to marker
    assert A.open_redirect("//evil-rap-marker.example.attacker.com/", "",
                           "evil-rap-marker.example") is None


def test_open_redirect_detects_marker_host():
    assert A.open_redirect("//evil-rap-marker.example/", "", "evil-rap-marker.example")
    assert A.open_redirect("https://evil-rap-marker.example/x", "", "evil-rap-marker.example")
    # backslash trick
    assert A.open_redirect("/\\evil-rap-marker.example", "", "evil-rap-marker.example")
    # same-site redirect is clean
    assert A.open_redirect("/dashboard", "https://self.test/dashboard",
                           "evil-rap-marker.example") is None
