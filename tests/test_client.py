from httpshield.client import FetchError, HttpClient


def test_invalid_url_rejected():
    try:
        HttpClient().fetch("ftp://example.com")
    except FetchError:
        pass
    else:
        raise AssertionError("Expected FetchError")
