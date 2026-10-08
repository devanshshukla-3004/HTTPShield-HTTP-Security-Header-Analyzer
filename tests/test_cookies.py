from httpshield.analyzer import analyze_cookies
from httpshield.models import Status


def test_secure_cookie_passes():
    results = analyze_cookies(["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"], True)
    assert results[0].status == Status.PASS


def test_missing_cookie_attributes_warn():
    results = analyze_cookies(["session=abc; Path=/"], True)
    assert results[0].status == Status.WARN


def test_samesite_none_requires_secure():
    results = analyze_cookies(["session=abc; SameSite=None"], True)
    assert results[0].status == Status.FAIL
