from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from urllib.parse import urlparse

from .models import HttpResponseData


class FetchError(RuntimeError):
    """Raised when a target cannot be fetched safely."""


class TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class HttpClient:
    timeout: float = 10.0
    user_agent: str = "HTTPShield/0.1 (+defensive-security-audit)"

    def fetch(self, url: str) -> HttpResponseData:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise FetchError("Target must be an absolute http:// or https:// URL.")

        redirects = TrackingRedirectHandler()
        context = ssl.create_default_context()
        opener = build_opener(redirects, HTTPSHandler(context=context))
        request = Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )

        started = time.perf_counter()
        try:
            response = opener.open(request, timeout=self.timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise FetchError(str(exc)) from exc

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        with response:
            response.read(1)
            headers = {k.lower(): v.strip() for k, v in response.headers.items()}
            cookies = response.headers.get_all("Set-Cookie") or []
            return HttpResponseData(
                requested_url=url,
                final_url=response.geturl(),
                status_code=getattr(response, "status", 200),
                headers=headers,
                set_cookies=list(cookies),
                redirects=redirects.chain,
                elapsed_ms=elapsed_ms,
            )
