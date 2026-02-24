# Web Security Scanner

Checks a list of URLs for **Security Header Misconfigurations** and **JavaScript Library Vulnerabilities**, outputting results as CSV.

## Installation

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. (Optional but recommended) Install retire.js for enhanced JS vulnerability scanning
npm install -g retire
```

## Usage

```bash
# Basic scan
python3 web_security_scanner.py -i urls.txt -o results.csv

# With retire.js enabled
python3 web_security_scanner.py -i urls.txt -o results.csv --retire

# Custom timeout and thread count
python3 web_security_scanner.py -i urls.txt -o results.csv --timeout 20 --threads 5
```

### Input File Format (`urls.txt`)
```
# Comments start with #
https://example.com
https://target.site.com
http://internal-app.local:8080
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Input file with URLs (one per line) | Required |
| `-o, --output` | Output CSV file path | Required |
| `--timeout` | HTTP request timeout (seconds) | 15 |
| `--threads` | Concurrent scanning threads | 3 |
| `--retire` | Enable retire.js for JS scanning | Off |

## What It Checks

### Security Headers
| Header | Severity if Missing | Description |
|--------|-------------------|-------------|
| `Strict-Transport-Security` | HIGH | HSTS - forces HTTPS |
| `Content-Security-Policy` | HIGH | Mitigates XSS/injection (checks for `unsafe-inline`, `unsafe-eval`, wildcard `*`) |
| `X-Content-Type-Options` | HIGH | Prevents MIME-type sniffing |
| `X-Frame-Options` | HIGH | Prevents clickjacking |
| `Referrer-Policy` | HIGH | Controls referrer leakage |
| `Permissions-Policy` | HIGH | Restricts browser features |
| `Cross-Origin-Opener-Policy` | MEDIUM | Isolates browsing context |
| `Cross-Origin-Resource-Policy` | MEDIUM | Controls cross-origin loading |
| `Cross-Origin-Embedder-Policy` | MEDIUM | Controls cross-origin embedding |

### Information Leakage (unwanted headers)
- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`

### Cookie Security
- Missing `Secure`, `HttpOnly`, or `SameSite` flags

### JavaScript Library Vulnerabilities
**Built-in scanner** detects known vulnerable versions of:
- jQuery, Bootstrap, AngularJS, Lodash, Moment.js, Vue.js, React, Handlebars, DOMPurify

**retire.js** (optional, `--retire` flag) provides comprehensive scanning against the full retire.js vulnerability database.

## CSV Output Format

| Column | Content |
|--------|---------|
| `URL` | The scanned URL |
| `Results` | Full findings with severity tags: `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[OK]`, `[INFO]` |

## Severity Levels

- **CRITICAL** - SSL/TLS failures, fundamental security issues
- **HIGH** - Missing critical security headers, known CVEs in JS libraries
- **MEDIUM** - Misconfigured headers, missing recommended headers
- **LOW** - Information leakage, cosmetic issues
- **OK** - Header present and correctly configured
