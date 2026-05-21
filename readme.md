# Web Security Scanner

Checks a list of URLs for **Security Header Misconfigurations** and **JavaScript Library Vulnerabilities**, outputting results as CSV.

## Installation

```bash
# 1. Core scanner only — minimum to run the CLI
pip install -r requirements.txt

# 2. (Optional) Jupyter notebook support — pandas + jupyter + ipykernel
pip install -r requirements-notebook.txt

# 3. (Optional) --deep mode — headless Chromium via Playwright
pip install -r requirements-deep.txt
playwright install chromium

# 4. (Optional) retire.js — full JS vulnerability database
npm install -g retire
```

Each optional file `-r requirements.txt` so you only ever need to run one
install line for the feature set you want. For everything at once:

```bash
pip install -r requirements-notebook.txt -r requirements-deep.txt
playwright install chromium
```

## Usage

There are two ways to run the scanner:

- **CLI** — `python3 web_security_scanner.py …` (see commands below)
- **Jupyter notebook** — `web_security_scanner.ipynb` for interactive use, inline tables, and quick re-runs (see [Jupyter workflow](#jupyter-workflow))

### CLI

```bash
# Basic scan
python3 web_security_scanner.py -i urls.txt -o results.csv

# With retire.js enabled
python3 web_security_scanner.py -i urls.txt -o results.csv --retire

# Custom timeout and thread count
python3 web_security_scanner.py -i urls.txt -o results.csv --timeout 20 --threads 5

# Auto-generate a strict CSP per URL (populates 'Generated CSP' + 'CSP Warnings' columns)
python3 web_security_scanner.py -i urls.txt -o results.csv --gen-csp

# Deep CSP generation — also captures resources injected by JavaScript at runtime
# (requires: pip install playwright && playwright install chromium)
python3 web_security_scanner.py -i urls.txt -o results.csv --gen-csp --deep
```

### Jupyter workflow

`web_security_scanner.ipynb` imports the same `web_security_scanner` module — there's no duplicated logic, so any change to the script is picked up after a kernel restart.

```bash
# One-time install
pip install -r requirements.txt pandas jupyter
# (optional) for --deep mode:
pip install playwright && playwright install chromium

# Launch
jupyter notebook web_security_scanner.ipynb
```

The notebook walks through nine cells:

1. Install hints (commented `%pip` lines you can uncomment)
2. Imports
3. **Configure** — edit a Python list of URLs and an `OPTIONS` dict (`timeout`, `threads`, `use_retire`, `skip_csp`, `gen_csp`, `deep`)
4. Run the scan with progress output
5. **Summary table** — pandas DataFrame with severity counts and CSP-suggestion flag per URL
6. Findings detail per URL
7. **Generated CSP per URL** — strict policy printed directive-by-directive plus warnings
8. Optional CSV export (same format as the CLI)
9. Optional Nginx / Apache config snippets per URL

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
| `--gen-csp` | Always auto-generate a strict CSP from observed page sources | Off |
| `--deep` | Use headless Chromium (Playwright) to also capture JS-injected resources | Off |

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

## CSP Auto-Generation

The scanner can build a tailored **Content-Security-Policy** by observing every script, stylesheet, image, font, frame, and network request the page uses, then grouping them by CSP directive.

### Modes

- **Static (default with `--gen-csp`)** — parses the initial HTML response. Fast, no extra dependencies. Catches everything referenced in the HTML.
- **Deep (`--gen-csp --deep`)** — also loads the page in headless Chromium via Playwright and captures every network request, including those injected by JavaScript (analytics, ads, dynamic chunks). More accurate.

Install Playwright once before using `--deep`:
```bash
pip install playwright
playwright install chromium
```

### Strict by default

The generator emits a strict policy:

- `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`, `upgrade-insecure-requests`
- **Never auto-injects `'unsafe-inline'` or `'unsafe-eval'`**. When the page uses inline `<script>`/`<style>`, inline event handlers (`onclick=`), or `eval()`, the generator records a warning in the **CSP Warnings** column explaining how to refactor (move to external files, use a nonce, or replace `eval()`).
- Surfaces the result in two dedicated CSV columns:
  - `Generated CSP` — the full policy header value, ready to paste into your server config
  - `CSP Warnings` — insecure patterns detected on the page that the strict policy will block

### Example output

```
Generated CSP:
  default-src 'self'; script-src 'self' https://cdn.jsdelivr.net;
  style-src 'self' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data: https://www.google-analytics.com;
  object-src 'none'; base-uri 'self'; frame-ancestors 'none';
  upgrade-insecure-requests

CSP Warnings:
  - Inline <script> blocks detected — policy will block them. Fix by moving JS
    into external files, or by adding a per-request nonce.
```

## CSV Output Format

| Column | Content |
|--------|---------|
| `URL` | The scanned URL |
| `Results` | Full findings with severity tags: `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[OK]`, `[INFO]` |
| `Generated CSP` | Tailored strict Content-Security-Policy header value (when CSP is missing/misconfigured, or whenever `--gen-csp` is passed) |
| `CSP Warnings` | Inline scripts/styles/eval/event-handlers detected on the page that the strict policy will block, with refactoring hints |

## Severity Levels

- **CRITICAL** - SSL/TLS failures, fundamental security issues
- **HIGH** - Missing critical security headers, known CVEs in JS libraries
- **MEDIUM** - Misconfigured headers, missing recommended headers
- **LOW** - Information leakage, cosmetic issues
- **OK** - Header present and correctly configured

## TLS/HTTPS Security Configuration

The `example_configuration/` directory includes server-specific security configurations and a dedicated **TLS/HTTPS Security Guide** (`tls_security_guide.md`) covering:

- **Testing TLS**: How to check your TLS configuration using OpenSSL, testssl.sh, Nmap, SSL Labs, and other tools
- **Server Configuration**: Secure TLS setup for Nginx, Apache, Tomcat, and Node.js
- **Certificate Management**: Obtaining, renewing, and monitoring certificates with Let's Encrypt
- **Vulnerability Prevention**: Protection against POODLE, BEAST, CRIME, Heartbleed, DROWN, and other TLS attacks
- **Best Practices Checklist**: Complete checklist for secure HTTPS deployment
