# Web VAPT Testing Methodology

This project is designed for authorized, non-destructive web security assessment.

## Workflow

```
Scope → Recon → Passive/Low-impact Checks → Evidence → Risk Rating → Manual Validation → Report
```

## Assessment Areas

### Recon
- URL normalization
- DNS resolution
- common hostname discovery
- redirect behavior
- server/banner metadata
- TLS certificate metadata

### Configuration
- Security headers
- Cookie attributes
- CORS behavior
- HTTP methods
- mixed content
- TLS configuration

### Exposure
- Common sensitive files
- Debug/admin/API documentation endpoints
- Directory listing indicators
- Source-map references
- HTML comments

### Application Review Leads
The scanner identifies pages/forms/tokens that deserve manual review. It deliberately avoids automatically exploiting:

- SQL injection
- XSS
- SSRF
- IDOR
- Authentication bypass
- RCE
- File upload
- Brute force

## Evidence Standard

Every finding should contain:

1. Target URL
2. HTTP status
3. Relevant request/response evidence
4. Severity
5. Confidence
6. Recommended validation
7. Remediation

A scanner observation is not automatically a confirmed vulnerability.
