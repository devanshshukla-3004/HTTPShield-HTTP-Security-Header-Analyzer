from httpshield.analyzer import analyze_headers, analyze_transport
from httpshield.models import HttpResponseData, Status


def response(headers=None, url="https://example.com"):
    return HttpResponseData(
        requested_url=url,
        final_url=url,
        status_code=200,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        set_cookies=[],
        redirects=[],
        elapsed_ms=10,
    )


def test_secure_headers_pass():
    result = analyze_headers(response({
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
    }))
    by_id = {item.check_id: item for item in result}
    assert by_id["hsts"].status == Status.PASS
    assert by_id["csp"].status == Status.PASS
    assert by_id["content-type-options"].status == Status.PASS
    assert by_id["clickjacking"].status == Status.PASS


def test_missing_headers_are_flagged():
    assert any(item.status == Status.FAIL for item in analyze_headers(response()))


def test_http_transport_fails():
    result = analyze_transport(response(url="http://example.com"))
    assert result[0].status == Status.FAIL
