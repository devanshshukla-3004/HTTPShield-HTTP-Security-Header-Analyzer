from __future__ import annotations

from .client import FetchError, HttpClient
from .models import CheckResult, HttpResponseData, Severity, Status


def result(check_id, title, status, severity, score, evidence, remediation, category="Headers"):
    return CheckResult(check_id, title, status, severity, max(0, min(100, score)),
                       evidence, remediation, category)


def header(response: HttpResponseData, name: str) -> str | None:
    return response.headers.get(name.lower())


def analyze_transport(response: HttpResponseData) -> list[CheckResult]:
    checks = []
    if response.is_https:
        checks.append(result("https", "Transport security", Status.PASS, Severity.INFO, 100,
            f"Final URL uses HTTPS: {response.final_url}",
            "Keep HTTPS enforced across the application.", "Transport"))
    else:
        checks.append(result("https", "Transport security", Status.FAIL, Severity.CRITICAL, 0,
            f"Final URL uses HTTP: {response.final_url}",
            "Serve the target over HTTPS and redirect HTTP requests to HTTPS.", "Transport"))

    checks.append(result(
        "redirect-chain", "Redirect chain",
        Status.WARN if len(response.redirects) > 5 else Status.PASS,
        Severity.MEDIUM if len(response.redirects) > 5 else Severity.INFO,
        60 if len(response.redirects) > 5 else 100,
        f"{len(response.redirects)} redirects were observed.",
        "Keep redirect chains short and deterministic.", "Transport"))
    return checks


def analyze_headers(response: HttpResponseData) -> list[CheckResult]:
    checks = []

    if response.is_https:
        hsts = header(response, "strict-transport-security")
        if not hsts:
            checks.append(result("hsts", "HTTP Strict Transport Security", Status.FAIL, Severity.HIGH, 25,
                "Strict-Transport-Security is missing on the final HTTPS response.",
                "Configure HSTS with an appropriate max-age after validating HTTPS coverage."))
        else:
            max_age = 0
            for token in hsts.split(";"):
                if token.strip().lower().startswith("max-age="):
                    try:
                        max_age = int(token.split("=", 1)[1])
                    except ValueError:
                        pass
            checks.append(result(
                "hsts", "HTTP Strict Transport Security",
                Status.PASS if max_age >= 15552000 else Status.WARN,
                Severity.INFO if max_age >= 15552000 else Severity.MEDIUM,
                100 if max_age >= 15552000 else 65,
                f"HSTS is present with max-age={max_age}.",
                "Use a sufficiently long HSTS max-age after validating HTTPS coverage."))
    else:
        checks.append(result("hsts", "HTTP Strict Transport Security", Status.NA, Severity.INFO, 100,
            "HSTS is not evaluated because the final response is HTTP.",
            "Serve the target over HTTPS."))

    csp = header(response, "content-security-policy")
    weak = [x for x in ("'unsafe-inline'", "'unsafe-eval'") if csp and x in csp.lower()]
    checks.append(result(
        "csp", "Content Security Policy",
        Status.FAIL if not csp else Status.WARN if weak else Status.PASS,
        Severity.HIGH if not csp else Severity.MEDIUM if weak else Severity.INFO,
        25 if not csp else 70 if weak else 100,
        "Content-Security-Policy is missing." if not csp else
        "CSP is present." + (f" Weak directives: {', '.join(weak)}." if weak else ""),
        "Define a restrictive CSP; prefer nonces/hashes over unsafe-inline or unsafe-eval."))

    xcto = header(response, "x-content-type-options")
    good_xcto = xcto and xcto.lower() == "nosniff"
    checks.append(result("content-type-options", "MIME sniffing protection",
        Status.PASS if good_xcto else Status.FAIL,
        Severity.INFO if good_xcto else Severity.MEDIUM,
        100 if good_xcto else 35,
        "X-Content-Type-Options is set to nosniff." if good_xcto
        else "X-Content-Type-Options is missing or not set to nosniff.",
        "Set X-Content-Type-Options: nosniff."))

    xfo = header(response, "x-frame-options")
    frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    protected = frame_ancestors or bool(xfo and xfo.upper() in {"DENY", "SAMEORIGIN"})
    checks.append(result("clickjacking", "Clickjacking protection",
        Status.PASS if protected else Status.FAIL,
        Severity.INFO if protected else Severity.MEDIUM,
        100 if protected else 35,
        "Framing is restricted by CSP frame-ancestors or X-Frame-Options." if protected
        else "No effective frame-ancestors or supported X-Frame-Options restriction was observed.",
        "Prefer CSP frame-ancestors; use X-Frame-Options as defense in depth."))

    referrer = header(response, "referrer-policy")
    strong = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if not referrer:
        checks.append(result("referrer-policy", "Referrer policy", Status.WARN, Severity.LOW, 65,
            "Referrer-Policy is missing.",
            "Set an explicit policy such as strict-origin-when-cross-origin."))
    else:
        value = referrer.strip().lower()
        checks.append(result("referrer-policy", "Referrer policy",
            Status.PASS if value in strong else Status.WARN,
            Severity.INFO if value in strong else Severity.LOW,
            100 if value in strong else 70,
            f"Referrer-Policy is {referrer}.",
            "Keep an explicit privacy-conscious referrer policy."))

    permissions = header(response, "permissions-policy")
    checks.append(result("permissions-policy", "Browser feature policy",
        Status.PASS if permissions else Status.WARN,
        Severity.INFO if permissions else Severity.LOW,
        100 if permissions else 70,
        "Permissions-Policy is present." if permissions else "Permissions-Policy is missing.",
        "Restrict browser features the application does not need."))

    server = header(response, "server")
    powered = header(response, "x-powered-by")
    disclosure = powered or server
    checks.append(result("technology-disclosure", "Technology disclosure",
        Status.WARN if disclosure else Status.PASS,
        Severity.LOW if disclosure else Severity.INFO,
        70 if powered else 80 if server else 100,
        f"Response discloses technology metadata: {disclosure}." if disclosure
        else "No common technology disclosure header was observed.",
        "Remove unnecessary Server/X-Powered-By disclosure where practical."))

    return checks


def _cookie_attrs(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {"name": name}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.strip().lower()] = None
    return name, attrs


def analyze_cookies(cookies: list[str], https: bool) -> list[CheckResult]:
    if not cookies:
        return [result("cookies", "Cookie security attributes", Status.NA, Severity.INFO, 100,
            "No Set-Cookie response headers were observed.",
            "If sensitive cookies are used, configure Secure, HttpOnly and an explicit SameSite policy.", "Cookies")]

    checks = []
    for index, raw in enumerate(cookies, 1):
        name, attrs = _cookie_attrs(raw)
        missing, problems = [], []

        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")

        same_site = (attrs.get("samesite") or "").lower()
        if not same_site:
            missing.append("SameSite")
        elif same_site not in {"strict", "lax", "none"}:
            problems.append(f"invalid SameSite={same_site}")
        elif same_site == "none" and "secure" not in attrs:
            problems.append("SameSite=None requires Secure")

        lower_name = name.lower()
        if lower_name.startswith("__host-") and (
            "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs):
            problems.append("__Host- prefix requirements are not satisfied")
        if lower_name.startswith("__secure-") and "secure" not in attrs:
            problems.append("__Secure- cookie is missing Secure")

        if problems:
            status, severity, score = Status.FAIL, Severity.HIGH, 20
        elif missing:
            status, severity, score = Status.WARN, Severity.MEDIUM, 60
        else:
            status, severity, score = Status.PASS, Severity.INFO, 100

        evidence = f"{name}: "
        evidence += "Problems: " + "; ".join(problems) if problems else (
            "Missing: " + ", ".join(missing) if missing else
            "Secure, HttpOnly and SameSite attributes present."
        )
        checks.append(result(f"cookie-{index}", f"Cookie security: {name}", status, severity, score,
            evidence,
            "For session or sensitive cookies, use Secure and HttpOnly; set SameSite explicitly, preferably Strict or Lax where compatible.",
            "Cookies"))
    return checks


def audit(url: str, timeout: float = 10.0) -> dict:
    try:
        response = HttpClient(timeout=timeout).fetch(url)
    except FetchError as exc:
        return {"target": url, "error": str(exc), "score": 0, "grade": "F", "checks": []}

    checks = analyze_transport(response) + analyze_headers(response) + analyze_cookies(response.set_cookies, response.is_https)
    applicable = [c.score for c in checks if c.status != Status.NA]
    score = round(sum(applicable) / len(applicable)) if applicable else 0
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    return {
        "target": url,
        "final_url": response.final_url,
        "status_code": response.status_code,
        "elapsed_ms": response.elapsed_ms,
        "redirects": response.redirects,
        "score": score,
        "grade": grade,
        "summary": {
            "total": len(checks),
            "pass": sum(c.status == Status.PASS for c in checks),
            "warn": sum(c.status == Status.WARN for c in checks),
            "fail": sum(c.status == Status.FAIL for c in checks),
            "error": sum(c.status == Status.ERROR for c in checks),
            "not_applicable": sum(c.status == Status.NA for c in checks),
        },
        "checks": [c.to_dict() for c in checks],
    }
