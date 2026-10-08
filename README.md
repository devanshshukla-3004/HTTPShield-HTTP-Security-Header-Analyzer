# 🛡️ HTTPShield

### Day 08 — 100 Days, 100 Cybersecurity Projects

HTTPShield is a defensive HTTP security analyzer that inspects web responses, redirect behavior, security headers, and cookies, then produces evidence-backed findings, remediation guidance, and a normalized security score.

> Status: **Functional, user-ready MVP**  
> Scope: **Defensive HTTP security analysis — not exploitation or penetration testing.**

## Why HTTPShield?

Security response headers provide practical browser-side defenses. OWASP documents their role in reducing risks such as XSS, clickjacking, MIME confusion, and information disclosure.

HTTPShield turns those recommendations into a repeatable command-line audit.

## 🔎 What it checks

| Area | Checks |
|---|---|
| Transport | HTTPS, redirect chain |
| Browser defenses | CSP, HSTS, X-Content-Type-Options |
| Framing | CSP frame-ancestors / X-Frame-Options |
| Privacy | Referrer-Policy |
| Browser capabilities | Permissions-Policy |
| Disclosure | Server / X-Powered-By |
| Cookies | Secure, HttpOnly, SameSite, cookie prefixes |

Cookie analysis follows defensive guidance around Secure, HttpOnly, SameSite, and cookie prefixes.

## 🧠 Analysis philosophy

HTTPShield does more than check whether a header exists.

- CSP is inspected for unsafe-inline and unsafe-eval.
- Clickjacking protection accepts CSP frame-ancestors or effective X-Frame-Options.
- HSTS is evaluated for max-age.
- SameSite=None without Secure is treated as a cookie configuration failure.
- Technology disclosure is reported separately from missing defenses.
- Every finding contains evidence and remediation guidance.

## 🏗️ Architecture

```
Target URL
   |
   v
HTTP Client
   |
   +-- status
   +-- headers
   +-- cookies
   +-- redirects
   |
   v
Security Analyzer
   |
   +-- Transport checks
   +-- Header checks
   +-- Cookie checks
   +-- Disclosure checks
   |
   v
Score + Severity + Evidence
   |
   +-- Terminal
   +-- JSON
   +-- CSV
```

## 🚀 Quick start

### 1. Clone

```bash
git clone https://github.com/devanshshukla-3004/HTTPShield-HTTP-Security-Header-Analyzer.git
cd HTTPShield-HTTP-Security-Header-Analyzer
```

### 2. Create an environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Scan a target you are authorized to assess

```bash
httpshield https://example.com
```

Export reports:

```bash
httpshield https://example.com --json reports/example.json
httpshield https://example.com --csv reports/example.csv
```

Quiet automation mode:

```bash
httpshield https://example.com --quiet --json reports/example.json
```

## 📊 Scoring

HTTPShield produces a 0–100 **triage posture score**.

| Score | Grade |
|---:|:---:|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

The score is not a compliance percentage and should not be interpreted as proof of overall application security.

## 🧪 Testing

Run:

```bash
python -m pytest
```

GitHub Actions validates Python 3.10, 3.11, 3.12, and 3.13.

## 🔒 Safety design

HTTPShield is intentionally non-destructive.

It:
- performs ordinary HTTP GET requests;
- follows normal redirects;
- reads response metadata;
- does not brute-force credentials;
- does not exploit vulnerabilities;
- does not fuzz endpoints;
- does not modify target systems;
- does not require credentials or external reputation APIs.

Only scan systems you own or have explicit authorization to assess.

## ⚠️ Limitations

HTTPShield is not a replacement for a full web application security assessment.

It does not:
- prove that a CSP is logically perfect;
- crawl an entire application;
- test authenticated behavior;
- exploit vulnerabilities;
- validate the complete TLS configuration;
- claim OWASP compliance or certification.

Some security headers are context-dependent. APIs and non-HTML responses may not need every browser-oriented control.

## 🗺️ Roadmap

- richer CSP directive analysis;
- cookie expiration/domain/path risk analysis;
- TLS certificate metadata;
- baseline comparison;
- HTML report;
- SARIF output;
- optional local dashboard;
- versioned security rules.

## 📁 Project structure

```
HTTPShield-HTTP-Security-Header-Analyzer/
├── .github/workflows/ci.yml
├── samples/
├── src/httpshield/
│   ├── analyzer.py
│   ├── client.py
│   ├── cli.py
│   ├── models.py
│   └── reporter.py
├── tests/
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

## 🎓 Learning outcomes

- HTTP response analysis
- secure-header reasoning
- cookie security
- redirect handling
- defensive security automation
- CLI design
- structured reporting
- security scoring
- automated testing
- CI/CD practices

## 📜 License

MIT License.

## 👤 Author

**Devansh Shukla**  
BTech CSE | Cybersecurity & AI

Part of the **100 Days, 100 Cybersecurity Projects** challenge.

## ⚠️ Disclaimer

HTTPShield is an educational and defensive security tool. Use it only against systems you own or have explicit authorization to assess.

## References

- OWASP HTTP Headers Cheat Sheet
- OWASP Content Security Policy Cheat Sheet
- OWASP HTTP Strict Transport Security Cheat Sheet
- MDN Set-Cookie documentation
