# Web VAPT Suite

A broader, non-destructive web security posture scanner that consolidates the
useful safe checks from the user's 20 Python security scripts into one workflow.

## Run

```bash
python -m pip install -r requirements.txt
python web_vapt.py https://example.com
```

## Included checks

### Recon / discovery
- URL normalization
- DNS/IP resolution
- common subdomain resolution
- HTTP status and redirects
- server/banner disclosure

### Web security posture
- CSP
- HSTS
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- CORS indicators
- HTTP method/TRACE indicators
- cookie Secure/HttpOnly/SameSite
- mixed content
- directory listing indicators
- exposed .env/.git and common debug/API documentation endpoints
- robots.txt/sitemap/security.txt
- HTML comments with secret/debug keywords
- source-map references
- password fields over HTTP
- forms for manual application-security review

### JWT
- Detects JWT-like tokens in the initial response
- Decodes header/payload locally
- Flags visible `alg=none`
- Notes missing visible `exp` claim

### TLS
- TLS version
- cipher
- certificate subject/issuer/expiry
- SANs

### Reporting
- Finding category
- Evidence
- Severity
- Recommended validation/remediation
- Overall triage risk score
- JSON report

## About "all vulnerabilities"

No black-box scanner can honestly guarantee that it will find **every** weak
vulnerability. SQL injection, XSS, SSRF, IDOR, auth bypass, business-logic
flaws, race conditions and many API issues require context-aware testing.

This suite therefore aims for broad **safe detection/triage**, while keeping
destructive or exploit behavior out of the automated scanner.

Use only on systems you own or are explicitly authorized to assess.
