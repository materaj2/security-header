#!/usr/bin/env python3
"""
Web Security Scanner - Security Header & JavaScript Library Vulnerability Checker
==================================================================================
Checks a list of URLs for:
  1. Security Header Misconfigurations
  2. JavaScript Library Vulnerabilities (via retire.js)

Usage:
  python3 web_security_scanner.py -i urls.txt -o results.csv
  python3 web_security_scanner.py -i urls.txt -o results.txt --format txt
  python3 web_security_scanner.py -i urls.txt -o results.csv --timeout 15 --threads 5

Author: Security Lab Tool
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] 'beautifulsoup4' not installed. Run: pip install beautifulsoup4")
    sys.exit(1)

# ─────────────────────────────────────────────
# CSP directive vocabulary (used both for validation and source classification)
# ─────────────────────────────────────────────
VALID_CSP_DIRECTIVES = {
    # Fetch directives
    "child-src", "connect-src", "default-src", "font-src", "frame-src",
    "img-src", "manifest-src", "media-src", "object-src", "prefetch-src",
    "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "worker-src",
    # Document directives
    "base-uri", "sandbox",
    # Navigation directives
    "form-action", "frame-ancestors", "navigate-to",
    # Reporting directives
    "report-uri", "report-to",
    # Other / boolean directives
    "block-all-mixed-content", "upgrade-insecure-requests",
    "require-trusted-types-for", "trusted-types",
    "require-sri-for", "plugin-types", "referrer",
}

# Values that legitimately belong to Referrer-Policy, NOT CSP.
# When one of these appears as a CSP directive name, it's almost always a
# header confusion bug — flag it explicitly so the user gets a clear hint.
REFERRER_POLICY_VALUES = {
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url",
}


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "HSTS - Forces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "checks": {
            "max-age": lambda v: _extract_max_age(v) >= 31536000,
            "includeSubDomains": lambda v: "includesubdomains" in v.lower(),
        },
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "CSP - Mitigates XSS and injection attacks",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
        "checks": {
            "no_unsafe_inline": lambda v: "unsafe-inline" not in v.lower()
            or "nonce-" in v.lower()
            or "'strict-dynamic'" in v.lower(),
            "no_unsafe_eval": lambda v: "unsafe-eval" not in v.lower(),
            "no_wildcard_src": lambda v: not re.search(
                r"(default-src|script-src)\s+[^;]*\*", v
            ),
        },
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME-type sniffing",
        "recommended": "nosniff",
        "checks": {
            "nosniff": lambda v: v.strip().lower() == "nosniff",
        },
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents clickjacking via framing",
        "recommended": "DENY or SAMEORIGIN",
        "checks": {
            "valid_value": lambda v: v.strip().upper() in ["DENY", "SAMEORIGIN"]
            or v.strip().upper().startswith("ALLOW-FROM"),
        },
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Controls referrer information sent with requests",
        "recommended": "strict-origin-when-cross-origin or no-referrer",
        "checks": {
            "valid_value": lambda v: v.strip().lower()
            in [
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ],
        },
    },
    "Permissions-Policy": {
        "required": True,
        "description": "Controls browser feature access (camera, mic, geolocation, etc.)",
        "recommended": "geolocation=(), camera=(), microphone=()",
        "checks": {},
    },
    "X-XSS-Protection": {
        "required": False,
        "description": "Legacy XSS filter (deprecated, but absence noted)",
        "recommended": "0 (disable) or absent with strong CSP",
        "checks": {
            "not_enabled_without_block": lambda v: v.strip() != "1"
            or "mode=block" in v.lower(),
        },
    },
    "Cross-Origin-Opener-Policy": {
        "required": False,
        "description": "COOP - Isolates browsing context",
        "recommended": "same-origin",
        "checks": {
            "valid_value": lambda v: v.strip().lower()
            in ["same-origin", "same-origin-allow-popups", "unsafe-none"],
        },
    },
    "Cross-Origin-Resource-Policy": {
        "required": False,
        "description": "CORP - Controls cross-origin resource loading",
        "recommended": "same-origin or same-site",
        "checks": {
            "valid_value": lambda v: v.strip().lower()
            in ["same-origin", "same-site", "cross-origin"],
        },
    },
    "Cross-Origin-Embedder-Policy": {
        "required": False,
        "description": "COEP - Controls cross-origin embedding",
        "recommended": "require-corp",
        "checks": {
            "valid_value": lambda v: v.strip().lower()
            in ["require-corp", "credentialless", "unsafe-none"],
        },
    },
    "Cache-Control": {
        "required": False,
        "description": "Controls caching behavior",
        "recommended": "no-store, no-cache for sensitive pages",
        "checks": {},
    },
}

# Headers that should NOT be present (information leakage)
UNWANTED_HEADERS = {
    "Server": "Reveals web server software/version",
    "X-Powered-By": "Reveals backend technology (e.g., PHP, ASP.NET)",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
    "X-Generator": "Reveals site generator (e.g., WordPress)",
}


def _validate_csp_directive_names(csp_value):
    """
    Walk a CSP header value and return a list of (severity, message) findings
    for directive names that aren't part of the CSP spec. Catches the very
    common mistake of putting Referrer-Policy values (e.g.
    'strict-origin-when-cross-origin') into the CSP header — when that happens,
    the browser silently ignores the directive and the policy is effectively
    just whatever else is present.
    """
    findings = []
    for raw in csp_value.split(";"):
        token = raw.strip()
        if not token:
            continue
        directive = token.split()[0].lower()
        if directive in VALID_CSP_DIRECTIVES:
            continue
        if directive in REFERRER_POLICY_VALUES:
            findings.append((
                "HIGH",
                f"Invalid CSP directive '{directive}' — this is a Referrer-Policy value, "
                f"not a CSP directive. The browser silently ignores it, so any sources you "
                f"intended to allow here are NOT actually whitelisted. Move "
                f"'{directive}' to a separate 'Referrer-Policy' header and use the correct "
                f"CSP directive (e.g. 'script-src') for the origins it was meant to allow.",
            ))
        else:
            findings.append((
                "MEDIUM",
                f"Unknown CSP directive '{directive}' — browsers ignore it. "
                f"Check spelling against the CSP spec.",
            ))
    return findings


def _extract_max_age(value):
    """Extract max-age value from HSTS header."""
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def get_session():
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ─────────────────────────────────────────────
# Security Header Checks
# ─────────────────────────────────────────────
def check_security_headers(url, response, skip_csp=False):
    """Analyze security headers and return findings."""
    findings = []
    headers = response.headers
    is_https = url.startswith("https://")

    # Check required/recommended security headers
    for header_name, config in SECURITY_HEADERS.items():
        if skip_csp and header_name == "Content-Security-Policy":
            continue
        value = headers.get(header_name)

        if value is None:
            severity = "HIGH" if config["required"] else "MEDIUM"
            # HSTS only relevant for HTTPS
            if header_name == "Strict-Transport-Security" and not is_https:
                findings.append(
                    f"[INFO] {header_name}: N/A (site not using HTTPS)"
                )
                continue
            findings.append(
                f"[{severity}] {header_name}: MISSING - {config['description']}. "
                f"Recommended: {config['recommended']}"
            )
        else:
            # Run specific checks
            issues = []
            for check_name, check_fn in config["checks"].items():
                try:
                    if not check_fn(value):
                        issues.append(check_name)
                except Exception:
                    issues.append(f"{check_name} (parse error)")

            if issues:
                findings.append(
                    f"[MEDIUM] {header_name}: MISCONFIGURED ({', '.join(issues)}) - "
                    f"Current value: '{value}'"
                )
            else:
                findings.append(f"[OK] {header_name}: {value}")

            # Extra validation for CSP — catch unknown / mistyped directive names
            # (e.g. Referrer-Policy values accidentally placed in the CSP header).
            if header_name == "Content-Security-Policy":
                for severity, msg in _validate_csp_directive_names(value):
                    findings.append(f"[{severity}] {header_name}: {msg}")

    # Check for information leakage headers
    for header_name, description in UNWANTED_HEADERS.items():
        value = headers.get(header_name)
        if value:
            findings.append(
                f"[LOW] {header_name}: PRESENT ('{value}') - {description}. "
                f"Consider removing or obfuscating."
            )

    # Additional: check if HTTP redirects to HTTPS
    if not is_https:
        findings.append(
            "[HIGH] HTTPS: Site accessed over HTTP - no transport encryption"
        )

    # Additional: check for cookie security flags on Set-Cookie
    set_cookies = headers.get("Set-Cookie", "")
    if set_cookies:
        cookie_issues = []
        if is_https and "secure" not in set_cookies.lower():
            cookie_issues.append("Missing 'Secure' flag")
        if "httponly" not in set_cookies.lower():
            cookie_issues.append("Missing 'HttpOnly' flag")
        if "samesite" not in set_cookies.lower():
            cookie_issues.append("Missing 'SameSite' attribute")
        if cookie_issues:
            findings.append(
                f"[MEDIUM] Set-Cookie: {'; '.join(cookie_issues)}"
            )

    return findings


# ─────────────────────────────────────────────
# JavaScript Library Vulnerability Checks
# ─────────────────────────────────────────────
def check_retire_js_available():
    """Check if retire.js CLI is available."""
    try:
        result = subprocess.run(
            ["retire", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def scan_js_with_retire(url, html_content, timeout=60):
    """
    Use retire.js to scan for vulnerable JavaScript libraries.
    Saves HTML to temp file and scans with retire CLI.
    """
    findings = []

    # Write HTML content to a temp directory for retire.js to scan
    with tempfile.TemporaryDirectory(prefix="retirejs_") as tmpdir:
        html_file = os.path.join(tmpdir, "index.html")
        with open(html_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(html_content)

        try:
            result = subprocess.run(
                [
                    "retire",
                    "--path", tmpdir,
                    "--outputformat", "json",
                    "--exitwith", "0",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.stdout.strip():
                try:
                    retire_output = json.loads(result.stdout)

                    # retire.js v5+ format: {"version":"...", "data":[...], ...}
                    if isinstance(retire_output, dict):
                        retire_data = retire_output.get("data", [])
                        errors = retire_output.get("errors", [])
                        if errors:
                            for err in errors:
                                findings.append(f"[WARN] retire.js: {err}")
                    # retire.js v3/v4 format: [...]
                    elif isinstance(retire_output, list):
                        retire_data = retire_output
                    else:
                        retire_data = []

                    for item in retire_data:
                        for res in item.get("results", []):
                            component = res.get("component", "unknown")
                            version = res.get("version", "unknown")
                            for vuln in res.get("vulnerabilities", []):
                                severity = vuln.get("severity", "unknown").upper()
                                identifiers = vuln.get("identifiers", {})
                                cve_list = identifiers.get("CVE", [])
                                summary = identifiers.get(
                                    "summary", "No description"
                                )
                                cve_str = (
                                    ", ".join(cve_list) if cve_list else "No CVE"
                                )
                                findings.append(
                                    f"[{severity}] {component} v{version}: "
                                    f"{cve_str} - {summary}"
                                )
                except json.JSONDecodeError:
                    # retire.js may output non-JSON warnings
                    pass

            # Also check stderr for any useful info
            if result.stderr.strip() and "found" in result.stderr.lower():
                pass  # retire.js prints summary to stderr

        except subprocess.TimeoutExpired:
            findings.append("[ERROR] retire.js scan timed out")
        except Exception as e:
            findings.append(f"[ERROR] retire.js scan failed: {str(e)}")

    return findings


def scan_js_builtin(html_content):
    """
    Built-in fallback scanner: detect common JS libraries and known vulnerable versions
    using regex pattern matching on the HTML source.
    """
    findings = []

    # Known vulnerable library patterns: (regex, lib_name, extract_version_group, vuln_info)
    VULN_PATTERNS = [
        # jQuery
        {
            "name": "jQuery",
            "patterns": [
                r"jquery[.-](\d+\.\d+\.\d+)",
                r"jquery\.min\.js\?v=(\d+\.\d+\.\d+)",
                r"jQuery\s+v?(\d+\.\d+\.\d+)",
                r"jquery/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "3.5.0",
                    "severity": "MEDIUM",
                    "info": "CVE-2020-11022/CVE-2020-11023 - XSS in jQuery.htmlPrefilter",
                },
                {
                    "below": "3.0.0",
                    "severity": "MEDIUM",
                    "info": "CVE-2015-9251 - XSS via cross-domain ajax request",
                },
                {
                    "below": "1.12.0",
                    "severity": "MEDIUM",
                    "info": "CVE-2019-11358 - Prototype pollution in jQuery.extend",
                },
            ],
        },
        # Bootstrap
        {
            "name": "Bootstrap",
            "patterns": [
                r"bootstrap[.-](\d+\.\d+\.\d+)",
                r"bootstrap\.min\.(js|css)\?v=(\d+\.\d+\.\d+)",
                r"Bootstrap\s+v?(\d+\.\d+\.\d+)",
                r"bootstrap/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "3.4.1",
                    "severity": "MEDIUM",
                    "info": "CVE-2019-8331 - XSS in tooltip/popover data-template",
                },
                {
                    "below": "4.3.1",
                    "severity": "LOW",
                    "info": "CVE-2019-8331 - XSS in tooltip data-template (v4 branch)",
                },
            ],
        },
        # Angular.js (1.x)
        {
            "name": "AngularJS",
            "patterns": [
                r"angular[.-](\d+\.\d+\.\d+)",
                r"angular\.min\.js\?v=(\d+\.\d+\.\d+)",
                r"AngularJS\s+v?(\d+\.\d+\.\d+)",
                r"angular(?:\.min)?\.js/(\d+\.\d+\.\d+)",
            ],
            "vulns": [
                {
                    "below": "1.8.0",
                    "severity": "HIGH",
                    "info": "Multiple XSS and sandbox escape vulnerabilities",
                },
                {
                    "below": "1.6.9",
                    "severity": "HIGH",
                    "info": "CVE-2022-25869 - XSS via $sanitize service",
                },
            ],
        },
        # Lodash
        {
            "name": "lodash",
            "patterns": [
                r"lodash[.-](\d+\.\d+\.\d+)",
                r"lodash\.min\.js\?v=(\d+\.\d+\.\d+)",
                r"lodash/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "4.17.21",
                    "severity": "HIGH",
                    "info": "CVE-2021-23337 - Command injection via template",
                },
                {
                    "below": "4.17.12",
                    "severity": "HIGH",
                    "info": "CVE-2019-10744 - Prototype pollution",
                },
            ],
        },
        # Moment.js
        {
            "name": "moment.js",
            "patterns": [
                r"moment[.-](\d+\.\d+\.\d+)",
                r"moment\.min\.js",
                r"moment/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "2.29.4",
                    "severity": "HIGH",
                    "info": "CVE-2022-31129 - ReDoS vulnerability in string parsing",
                },
            ],
        },
        # Vue.js
        {
            "name": "Vue.js",
            "patterns": [
                r"vue[.-](\d+\.\d+\.\d+)",
                r"vue\.min\.js",
                r"Vue\.js\s+v(\d+\.\d+\.\d+)",
                r"vuejs/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "2.5.0",
                    "severity": "MEDIUM",
                    "info": "Potential XSS through template injection",
                },
            ],
        },
        # React (detecting from source)
        {
            "name": "React",
            "patterns": [
                r"react[.-](\d+\.\d+\.\d+)",
                r"react\.production\.min\.js",
                r"react/(\d+\.\d+\.\d+)/",
            ],
            "vulns": [
                {
                    "below": "16.4.2",
                    "severity": "MEDIUM",
                    "info": "CVE-2018-6341 - XSS via dangerouslySetInnerHTML",
                },
            ],
        },
        # Handlebars
        {
            "name": "Handlebars",
            "patterns": [
                r"handlebars[.-](\d+\.\d+\.\d+)",
                r"handlebars\.min\.js",
                r"Handlebars\s+v(\d+\.\d+\.\d+)",
            ],
            "vulns": [
                {
                    "below": "4.7.7",
                    "severity": "HIGH",
                    "info": "CVE-2021-23369 - Prototype pollution / RCE",
                },
            ],
        },
        # DOMPurify (sanitizer)
        {
            "name": "DOMPurify",
            "patterns": [
                r"dompurify[.-](\d+\.\d+\.\d+)",
                r"purify\.min\.js",
                r"DOMPurify\s+(\d+\.\d+\.\d+)",
            ],
            "vulns": [
                {
                    "below": "2.3.6",
                    "severity": "HIGH",
                    "info": "Multiple mXSS bypass vulnerabilities",
                },
            ],
        },
    ]

    content_lower = html_content.lower()

    for lib in VULN_PATTERNS:
        detected_version = None
        for pattern in lib["patterns"]:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                # Get last group (some patterns have multiple groups)
                detected_version = match.group(match.lastindex or 1)
                break

        if detected_version:
            version_tuple = _parse_version(detected_version)
            if version_tuple is None:
                findings.append(
                    f"[INFO] {lib['name']}: Detected version '{detected_version}' (could not parse for vuln check)"
                )
                continue

            is_vulnerable = False
            for vuln in lib["vulns"]:
                vuln_version = _parse_version(vuln["below"])
                if vuln_version and version_tuple < vuln_version:
                    findings.append(
                        f"[{vuln['severity']}] {lib['name']} v{detected_version}: "
                        f"Vulnerable (< {vuln['below']}) - {vuln['info']}"
                    )
                    is_vulnerable = True
                    break

            if not is_vulnerable:
                findings.append(
                    f"[OK] {lib['name']} v{detected_version}: No known vulnerabilities"
                )

    return findings


def _parse_version(version_str):
    """Parse a version string into a tuple for comparison."""
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return None


# ─────────────────────────────────────────────
# CSP Auto-Generation
# ─────────────────────────────────────────────
CSP_DIRECTIVE_ORDER = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "connect-src",
    "frame-src",
    "media-src",
    "object-src",
    "form-action",
    "base-uri",
    "frame-ancestors",
]

FONT_EXT_RE = re.compile(r"\.(woff2?|ttf|otf|eot)(\?|$)", re.IGNORECASE)


def _csp_resolve_source(raw_src, base_origin, base_scheme):
    """Convert a raw URL/path from page content into a CSP source token."""
    if not raw_src:
        return None
    s = raw_src.strip()
    if not s or s.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    if s.startswith("data:"):
        return "data:"
    if s.startswith("blob:"):
        return "blob:"
    if s.startswith("//"):
        s = base_scheme + ":" + s
    if s.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            p = urlparse(s)
            if not p.netloc:
                return "'self'"
            origin = f"{p.scheme}://{p.netloc}"
            return "'self'" if origin == base_origin else origin
        except Exception:
            return None
    # Relative / root-relative paths
    return "'self'"


def _csp_sort_key(token):
    """Sort CSP source tokens: keywords first, then origins alphabetically."""
    keyword_order = [
        "'none'",
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'strict-dynamic'",
        "data:",
        "blob:",
    ]
    try:
        return (0, keyword_order.index(token))
    except ValueError:
        return (1, token.lower())


def _csp_sha256(content):
    """
    Return the CSP source-list hash token for an inline script/style block.
    Format: 'sha256-BASE64='. Browsers compute the hash over the exact bytes of
    the element's text content (no whitespace normalisation), so we pass the
    string as-is.
    """
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def _empty_directives():
    """Return a fresh directive→set-of-tokens dict with strict baseline tokens."""
    directives = {d: set() for d in CSP_DIRECTIVE_ORDER}
    directives["default-src"].add("'self'")
    directives["object-src"].add("'none'")
    directives["base-uri"].add("'self'")
    directives["frame-ancestors"].add("'none'")
    for d in ("script-src", "style-src", "img-src", "font-src", "connect-src", "form-action"):
        directives[d].add("'self'")
    # data: in img-src / font-src is widely safe and almost universally needed
    # (favicons, inline SVGs in CSS, icon-font libraries like FontAwesome /
    # Phosphor / Lucide that ship base64 WOFF). Omitting it routinely breaks
    # otherwise-strict policies on real-world pages.
    directives["img-src"].add("data:")
    directives["font-src"].add("data:")
    return directives


def _collect_csp_sources_static(url, html_content, strict=True):
    """
    Walk the HTML with BeautifulSoup and collect external origins grouped by CSP
    directive. In strict mode, inline blocks / event handlers / eval() are recorded
    as warnings only — 'unsafe-inline' and 'unsafe-eval' are NOT added to the policy.

    Returns: (directives_dict, notes_set, inline_flags) or (None, set(), {})
    on parse failure. inline_flags is a dict with boolean keys:
      'inline_script', 'inline_style', 'eval', 'inline_event_handler'.
    """
    inline_flags = {
        "inline_script": False,
        "inline_style": False,
        "eval": False,
        "inline_event_handler": False,
        "has_script_bundles": False,
    }
    inline_hashes = {"script-src": set(), "style-src": set()}
    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        return None, set(), inline_flags, inline_hashes

    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
    base_scheme = parsed.scheme or "https"

    directives = _empty_directives()
    notes = set()

    def add(directive, raw_src):
        token = _csp_resolve_source(raw_src, base_origin, base_scheme)
        if token:
            directives[directive].add(token)

    # Scripts (external + inline)
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            inline_flags["has_script_bundles"] = True
            add("script-src", src)
        else:
            body = tag.string or ""
            if body.strip():
                inline_flags["inline_script"] = True
                inline_hashes["script-src"].add(_csp_sha256(body))
                if strict:
                    notes.add(
                        "Inline <script> blocks detected — policy will block them. "
                        "Fix by moving JS into external files, or by adding a per-request nonce "
                        "(script-src 'self' 'nonce-RANDOM') and setting nonce=\"RANDOM\" on each <script>."
                    )
                else:
                    directives["script-src"].add("'unsafe-inline'")
                    notes.add(
                        "Inline <script> blocks detected — prefer nonces or hashes over 'unsafe-inline'."
                    )
                if re.search(r"\beval\s*\(|new\s+Function\s*\(", body):
                    inline_flags["eval"] = True
                    if strict:
                        notes.add(
                            "eval() or new Function() detected — policy will block them. "
                            "Refactor to avoid dynamic code evaluation."
                        )
                    else:
                        directives["script-src"].add("'unsafe-eval'")
                        notes.add(
                            "eval() or new Function() usage detected — required 'unsafe-eval'; refactor to avoid it."
                        )
                # Detect fetch/XHR/WebSocket targets for connect-src
                for u in re.findall(
                    r"""(?:fetch|\.open|new\s+WebSocket|new\s+EventSource)\s*\(\s*['"]([^'"]+)['"]""",
                    body,
                ):
                    add("connect-src", u)
                for u in re.findall(r"""['"](wss?://[^'"\s]+)['"]""", body):
                    add("connect-src", u)

    # Stylesheets (external <link>)
    for tag in soup.find_all("link"):
        rel = tag.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        rel_lower = [r.lower() for r in rel]
        href = tag.get("href")
        if not href:
            continue
        if "stylesheet" in rel_lower:
            add("style-src", href)
            if FONT_EXT_RE.search(href):
                add("font-src", href)
        if "preload" in rel_lower:
            as_attr = (tag.get("as") or "").lower()
            mapping = {
                "script": "script-src",
                "style": "style-src",
                "image": "img-src",
                "font": "font-src",
                "fetch": "connect-src",
                "audio": "media-src",
                "video": "media-src",
                "track": "media-src",
            }
            if as_attr in mapping:
                add(mapping[as_attr], href)
        if "preconnect" in rel_lower or "dns-prefetch" in rel_lower:
            host_lower = href.lower()
            if "font" in host_lower or "gstatic" in host_lower:
                add("font-src", href)
                add("style-src", href)

    # Inline <style> blocks + style="" attributes
    inline_style_seen = False
    for tag in soup.find_all("style"):
        body = tag.string or ""
        if body.strip():
            inline_style_seen = True
            inline_hashes["style-src"].add(_csp_sha256(body))
        for font_url in re.findall(
            r"url\(\s*['\"]?([^)'\"]+)['\"]?\s*\)", body, re.IGNORECASE
        ):
            if FONT_EXT_RE.search(font_url):
                add("font-src", font_url)
            elif font_url.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
                add("img-src", font_url)
    if soup.find(attrs={"style": True}):
        inline_style_seen = True
    if inline_style_seen:
        inline_flags["inline_style"] = True
        if strict:
            notes.add(
                "Inline <style> blocks or style=\"\" attributes detected — policy will block them. "
                "Fix by moving CSS into external files, or add a nonce to style-src and the <style> tags."
            )
        else:
            directives["style-src"].add("'unsafe-inline'")
            notes.add(
                "Inline <style>/style=\"\" detected — prefer nonces or hashes over 'unsafe-inline'."
            )

    # Images / media / frames / forms
    for tag in soup.find_all("img"):
        add("img-src", tag.get("src"))
        srcset = tag.get("srcset") or ""
        for part in srcset.split(","):
            candidate = part.strip().split(" ")[0]
            add("img-src", candidate)
    for tag in soup.find_all(["picture", "source"]):
        srcset = tag.get("srcset") or ""
        for part in srcset.split(","):
            candidate = part.strip().split(" ")[0]
            if candidate:
                add("img-src", candidate)
    for tag in soup.find_all(["iframe", "frame"]):
        src = tag.get("src")
        if src:
            add("frame-src", src)
    for tag in soup.find_all(["video", "audio"]):
        add("media-src", tag.get("src"))
        for source in tag.find_all("source"):
            add("media-src", source.get("src"))
    for tag in soup.find_all("form"):
        add("form-action", tag.get("action"))
    for tag in soup.find_all(["object", "embed"]):
        src = tag.get("data") or tag.get("src")
        if src:
            directives["object-src"].discard("'none'")
            add("object-src", src)

    # Inline event handlers
    for tag in soup.find_all(True):
        for attr in list(tag.attrs.keys()):
            if attr.lower().startswith("on") and attr.lower() not in ("once",):
                inline_flags["inline_event_handler"] = True
                if strict:
                    notes.add(
                        "Inline event handlers (onclick, onload, etc.) detected — policy will block them. "
                        "Migrate to addEventListener() to keep a strict script-src."
                    )
                else:
                    directives["script-src"].add("'unsafe-inline'")
                    notes.add(
                        "Inline event handlers detected — require 'unsafe-inline'; migrate to addEventListener."
                    )
                break

    return directives, notes, inline_flags, inline_hashes


def _collect_csp_sources_dynamic(url, timeout=15):
    """
    Load the URL in a headless Chromium via Playwright and capture:
      (a) every network request grouped by Playwright's resource_type
      (b) every inline <script>/<style> in the LIVE DOM after navigation —
          this catches content injected at runtime by frameworks like React,
          which static HTML scanning misses entirely.

    Returns: (directives_dict, notes_set, inline_hashes_dict)
             or (None, {error_note}, {}) on failure.

    Requires: pip install playwright && playwright install chromium
    """
    inline_hashes = {"script-src": set(), "style-src": set()}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, {
            "--deep requested but Playwright is not installed. "
            "Run: pip install playwright && playwright install chromium"
        }, inline_hashes

    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
    base_scheme = parsed.scheme or "https"

    directives = _empty_directives()
    notes = set()

    # Playwright resource_type → CSP directive
    resource_map = {
        "script": "script-src",
        "stylesheet": "style-src",
        "image": "img-src",
        "font": "font-src",
        "fetch": "connect-src",
        "xhr": "connect-src",
        "websocket": "connect-src",
        "eventsource": "connect-src",
        "media": "media-src",
        "manifest": "connect-src",
    }

    def on_request(req):
        directive = resource_map.get(req.resource_type)
        if not directive:
            if req.frame and req.frame != req.frame.page.main_frame:
                directive = "frame-src"
            else:
                return
        token = _csp_resolve_source(req.url, base_origin, base_scheme)
        if token:
            directives[directive].add(token)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/125.0.0.0 Safari/537.36"
                    )
                )
                page = context.new_page()
                page.on("request", on_request)
                page.goto(url, wait_until="networkidle", timeout=timeout * 1000)

                # SPA frameworks (React, Vue) frequently inject styles AFTER
                # networkidle fires. Give the page another moment to settle so
                # we capture late-arriving inline content before hashing.
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

                # Pull every inline <script> and <style> from the LIVE DOM
                # (catches runtime-injected content like React style-loader output).
                inline_blocks = page.evaluate(
                    """() => {
                        const scripts = Array.from(document.querySelectorAll('script:not([src])'))
                            .map(el => el.textContent)
                            .filter(t => t && t.trim());
                        const styles = Array.from(document.querySelectorAll('style'))
                            .map(el => el.textContent)
                            .filter(t => t && t.trim());
                        return { scripts, styles };
                    }"""
                )
                for body in inline_blocks.get("scripts", []) or []:
                    inline_hashes["script-src"].add(_csp_sha256(body))
                for body in inline_blocks.get("styles", []) or []:
                    inline_hashes["style-src"].add(_csp_sha256(body))
            finally:
                browser.close()
    except Exception as e:
        notes.add(f"Deep scan via Playwright failed: {str(e)[:200]}")
        return None, notes, inline_hashes

    return directives, notes, inline_hashes


def _merge_directives(*directive_dicts):
    """Union directive→origin sets across multiple collectors."""
    merged = _empty_directives()
    for d in directive_dicts:
        if not d:
            continue
        for key, sources in d.items():
            merged.setdefault(key, set()).update(sources)
    return merged


def _render_csp(directives):
    """Render directive dict as a canonical CSP header string."""
    # Backfill empty resource directives with 'self'
    for d in ("script-src", "style-src", "img-src", "font-src", "connect-src"):
        if not directives.get(d):
            directives.setdefault(d, set()).add("'self'")

    parts = []
    for d in CSP_DIRECTIVE_ORDER:
        sources = directives.get(d)
        if not sources:
            continue
        token_list = sorted(sources, key=_csp_sort_key)
        parts.append(f"{d} {' '.join(token_list)}")
    parts.append("upgrade-insecure-requests")
    return "; ".join(parts)


def generate_csp_from_page(url, html_content, deep=False, timeout=15, strict=True):
    """
    Analyze a page and return three CSP variants plus notes:

      - strict   — no 'unsafe-inline' / 'unsafe-eval'. Goal state.
      - practical — includes 'unsafe-inline' (and 'unsafe-eval' if needed).
                    Works immediately but penalised by Bitsight/SecurityScorecard.
      - hashed    — 'sha256-XYZ=' tokens for each detected inline block instead
                    of 'unsafe-inline'. Bitsight-friendly and works for pages
                    you cannot refactor.

    Args:
        url, html_content, deep, timeout, strict — as before. The 'hashed'
        variant is most accurate with deep=True because it captures content
        that JS injects at runtime (e.g. MinIO's React style-loader output).

    Returns: (strict_csp, practical_csp_or_None, hashed_csp_or_None, notes_list).
             Returns (None, None, None, []) if static parsing fails.
             practical_csp / hashed_csp are None when no inline content was
             detected — the strict policy is sufficient.
             The 5th element is the inline-content flags dict (used by the
             nginx nonce template to decide whether to add 'unsafe-eval').
    """
    static_directives, static_notes, inline_flags, inline_hashes = (
        _collect_csp_sources_static(url, html_content, strict=strict)
    )
    if static_directives is None:
        return None, None, None, [], {}

    if deep:
        dyn_directives, dyn_notes, dyn_hashes = _collect_csp_sources_dynamic(
            url, timeout=timeout
        )
        directives = _merge_directives(static_directives, dyn_directives)
        notes = static_notes | dyn_notes
        # Merge hashes from the live DOM (captures JS-injected styles/scripts).
        for key in ("script-src", "style-src"):
            inline_hashes[key].update(dyn_hashes.get(key, set()))
            if dyn_hashes.get(key):
                if key == "style-src":
                    inline_flags["inline_style"] = True
                else:
                    inline_flags["inline_script"] = True
    else:
        directives = static_directives
        notes = static_notes

    strict_csp = _render_csp({k: set(v) for k, v in directives.items()})

    needs_unsafe_inline_script = inline_flags["inline_script"] or inline_flags["inline_event_handler"]
    needs_unsafe_inline_style = inline_flags["inline_style"]
    needs_unsafe_eval = inline_flags["eval"]

    # Practical: 'unsafe-inline' / 'unsafe-eval' as needed.
    practical_csp = None
    if needs_unsafe_inline_script or needs_unsafe_inline_style or needs_unsafe_eval:
        practical = {k: set(v) for k, v in directives.items()}
        if needs_unsafe_inline_script:
            practical["script-src"].add("'unsafe-inline'")
        if needs_unsafe_eval:
            practical["script-src"].add("'unsafe-eval'")
        if needs_unsafe_inline_style:
            practical["style-src"].add("'unsafe-inline'")
        practical_csp = _render_csp(practical)
        notes.add(
            "A practical CSP companion was emitted with 'unsafe-inline' (and "
            "'unsafe-eval' if needed). Works immediately but penalised by "
            "security-ratings services (Bitsight, SecurityScorecard). Prefer "
            "the hash-based variant or the strict variant after refactoring."
        )

    # Hashed: SHA-256 tokens — Bitsight-friendly alternative to 'unsafe-inline'.
    # Requires deep=True for accuracy on framework-driven pages, but still useful
    # in static mode for fully server-rendered inline content.
    hashed_csp = None
    if inline_hashes["script-src"] or inline_hashes["style-src"]:
        hashed = {k: set(v) for k, v in directives.items()}
        for token in inline_hashes["script-src"]:
            hashed["script-src"].add(token)
        for token in inline_hashes["style-src"]:
            hashed["style-src"].add(token)
        # Inline event handlers cannot be allowed by hash — they require either
        # 'unsafe-inline', 'unsafe-hashes' + per-handler hashes, or refactoring
        # to addEventListener. Surface this so the user isn't surprised.
        if inline_flags["inline_event_handler"]:
            notes.add(
                "Inline event handlers (onclick=, onload=) cannot be permitted "
                "by SHA-256 hash on their own — the hashed CSP variant will "
                "still block them. Options: (a) refactor to addEventListener "
                "(recommended), (b) add 'unsafe-hashes' with per-handler hashes."
            )
        if needs_unsafe_eval:
            notes.add(
                "eval() / new Function() cannot be permitted by hash — the "
                "hashed CSP still blocks them. Refactor to remove dynamic "
                "code evaluation, or fall back to the practical variant."
            )
        hashed_csp = _render_csp(hashed)
        notes.add(
            f"Hash-based CSP variant emitted with "
            f"{len(inline_hashes['script-src'])} script hash(es) and "
            f"{len(inline_hashes['style-src'])} style hash(es). "
            "Bitsight-friendly. Hashes are stable per page version — update "
            "the CSP when the page is redeployed."
        )
        if not deep:
            notes.add(
                "Hash-based CSP was generated from the static HTML response "
                "only. If the page injects styles/scripts at runtime (e.g. "
                "React style-loader), re-run with --deep to capture them."
            )
        else:
            notes.add(
                "Deep capture: if blocks persist after applying this Hash-based "
                "CSP, the inline content likely changes per request (dynamic "
                "theming, user-specific values, timestamps). In that case "
                "hashes can never be stable — use the Nginx Nonce Template "
                "(also generated below) instead. Nonces work regardless of "
                "content changes because nginx injects them at response time."
            )
    elif deep and inline_flags["has_script_bundles"]:
        # --deep ran, no inline content captured, but the page loads JS bundles.
        # Either the bundles don't inject inline content, OR they inject it
        # later than our wait window. Surface both possibilities.
        notes.add(
            "Deep capture ran but found no inline scripts/styles in the live "
            "DOM. If the page is a SPA and you still see CSP blocks, the bundle "
            "may inject content after our wait window — extend the wait or use "
            "the Nginx Nonce Template for a content-independent fix."
        )

    # Late top-level guidance for SPAs without --deep (the static collector saw
    # script bundles but no static inline content, which is the common case
    # for React/Vue/Angular apps).
    if not deep and inline_flags["has_script_bundles"] and hashed_csp is None:
        notes.add(
            "The page loads JavaScript bundle(s) but no inline content was "
            "found in the static HTML. SPAs (React/Vue/Angular) commonly "
            "inject styles at runtime — those are invisible to a static scan. "
            "Re-run with --deep so the scanner can capture them and emit a "
            "hash-based CSP, or use the Nginx Nonce Template for the most "
            "robust answer."
        )

    return strict_csp, practical_csp, hashed_csp, sorted(notes), dict(inline_flags)


# ─────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────
def scan_url(url, session, use_retire=False, timeout=15, skip_csp=False,
             gen_csp=False, deep=False):
    """Scan a single URL for security issues."""
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "status": None,
        "header_findings": [],
        "js_findings": [],
        "csp_suggestion": None,
        "csp_suggestion_practical": None,
        "csp_suggestion_hashed": None,
        "csp_inline_flags": {},
        "csp_notes": [],
    }

    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            },
        )
        result["status"] = response.status_code

        # 1) Security Header Analysis
        result["header_findings"] = check_security_headers(url, response, skip_csp=skip_csp)

        # 2) JavaScript Library Vulnerability Analysis
        html_content = response.text
        if use_retire:
            result["js_findings"] = scan_js_with_retire(url, html_content)
        # Always run built-in scan (catches different things)
        builtin_findings = scan_js_builtin(html_content)
        # Merge (avoid duplicates)
        existing = set(result["js_findings"])
        for f in builtin_findings:
            if f not in existing:
                result["js_findings"].append(f)

        # 3) Auto-generate a tailored CSP recommendation
        if not skip_csp:
            csp_present = response.headers.get("Content-Security-Policy")
            csp_needs_help = (
                csp_present is None
                or any(
                    "Content-Security-Policy: MISSING" in f
                    or "Content-Security-Policy: MISCONFIGURED" in f
                    for f in result["header_findings"]
                )
            )
            should_generate = gen_csp or csp_needs_help
            if should_generate and html_content:
                csp_strict, csp_practical, csp_hashed, csp_notes, csp_flags = generate_csp_from_page(
                    url, html_content, deep=deep, timeout=timeout, strict=True
                )
                if csp_strict:
                    result["csp_suggestion"] = csp_strict
                    result["csp_suggestion_practical"] = csp_practical
                    result["csp_suggestion_hashed"] = csp_hashed
                    result["csp_inline_flags"] = csp_flags
                    result["csp_notes"] = csp_notes
                    result["header_findings"].append(
                        f"[INFO] Content-Security-Policy (Strict, recommended): {csp_strict}"
                    )
                    if csp_hashed:
                        result["header_findings"].append(
                            f"[INFO] Content-Security-Policy (Hash-based, Bitsight-friendly): {csp_hashed}"
                        )
                    if csp_practical:
                        result["header_findings"].append(
                            f"[INFO] Content-Security-Policy (Practical, works without refactoring): {csp_practical}"
                        )
                    for note in csp_notes:
                        result["header_findings"].append(f"[INFO] CSP note: {note}")

    except requests.exceptions.SSLError as e:
        result["status"] = "SSL_ERROR"
        result["header_findings"] = [f"[CRITICAL] SSL/TLS Error: {str(e)[:200]}"]
    except requests.exceptions.ConnectionError as e:
        result["status"] = "CONN_ERROR"
        result["header_findings"] = [f"[ERROR] Connection failed: {str(e)[:200]}"]
    except requests.exceptions.Timeout:
        result["status"] = "TIMEOUT"
        result["header_findings"] = [f"[ERROR] Request timed out after {timeout}s"]
    except requests.exceptions.RequestException as e:
        result["status"] = "ERROR"
        result["header_findings"] = [f"[ERROR] Request failed: {str(e)[:200]}"]

    return result


def generate_recommendations(result):
    """Build remediation recommendations from a result's findings."""
    recs = []

    csp_suggestion = result.get("csp_suggestion")

    for f in result["header_findings"]:
        # Missing security header
        m = re.match(r"\[(?:HIGH|MEDIUM)\] ([^:]+): MISSING", f)
        if m:
            header = m.group(1).strip()
            cfg = SECURITY_HEADERS.get(header)
            if cfg:
                if header == "Content-Security-Policy" and csp_suggestion:
                    recs.append(
                        f"Add 'Content-Security-Policy' header. Auto-generated for this page: {csp_suggestion}"
                    )
                else:
                    recs.append(
                        f"Add '{header}' header. Recommended: {cfg['recommended']}"
                    )
            continue

        # Misconfigured security header
        m = re.match(r"\[MEDIUM\] ([^:]+): MISCONFIGURED", f)
        if m:
            header = m.group(1).strip()
            cfg = SECURITY_HEADERS.get(header)
            if cfg:
                if header == "Content-Security-Policy" and csp_suggestion:
                    recs.append(
                        f"Fix 'Content-Security-Policy' configuration. Auto-generated for this page: {csp_suggestion}"
                    )
                else:
                    recs.append(
                        f"Fix '{header}' configuration. Recommended: {cfg['recommended']}"
                    )
            continue

        # Information leakage headers
        m = re.match(r"\[LOW\] ([^:]+): PRESENT", f)
        if m:
            header = m.group(1).strip()
            recs.append(
                f"Remove or obfuscate '{header}' header to avoid leaking server info."
            )
            continue

        # No HTTPS
        if "[HIGH] HTTPS:" in f:
            recs.append(
                "Enable HTTPS and redirect all HTTP traffic to HTTPS; deploy a valid TLS certificate."
            )
            continue

        # Cookie issues
        if "[MEDIUM] Set-Cookie:" in f:
            recs.append(
                "Set 'Secure', 'HttpOnly', and 'SameSite' attributes on all cookies."
            )
            continue

        # SSL/TLS errors
        if "[CRITICAL] SSL/TLS Error" in f:
            recs.append(
                "Resolve SSL/TLS configuration issues (valid certificate chain, supported protocols)."
            )
            continue

    # JS library vulnerabilities
    for f in result["js_findings"]:
        m = re.match(r"\[(?:CRITICAL|HIGH|MEDIUM|LOW)\] ([^ ]+) v([^:]+):", f)
        if m:
            lib, ver = m.group(1), m.group(2).strip()
            recs.append(
                f"Upgrade {lib} (current v{ver}) to the latest patched version."
            )

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


# Concrete example values used when rendering server config snippets.
# These are stricter/cleaner picks than the loose "Recommended:" strings shown
# in finding lines (e.g. "DENY or SAMEORIGIN" → "DENY").
HEADER_EXAMPLE_VALUES = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "X-XSS-Protection": "0",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
}


def _collect_header_actions(result):
    """
    Walk findings and produce structured lists of changes for config-snippet rendering.

    Returns:
        headers_to_set:    list of (header_name, value) pairs in finding order
        headers_to_remove: list of header names to strip (information leakage)
        flags: dict of bool flags — 'cookies', 'https_redirect', 'tls_error'
    """
    headers_to_set = []
    headers_to_remove = []
    seen_set = set()
    seen_remove = set()
    flags = {"cookies": False, "https_redirect": False, "tls_error": False}

    csp_suggestion = result.get("csp_suggestion")

    for f in result["header_findings"]:
        m = re.match(r"\[(?:HIGH|MEDIUM)\] ([^:]+): (MISSING|MISCONFIGURED)", f)
        if m:
            header = m.group(1).strip()
            if header in seen_set or header not in SECURITY_HEADERS:
                continue
            if header == "Content-Security-Policy" and csp_suggestion:
                value = csp_suggestion
            else:
                value = HEADER_EXAMPLE_VALUES.get(
                    header, SECURITY_HEADERS[header]["recommended"]
                )
            seen_set.add(header)
            headers_to_set.append((header, value))
            continue

        m = re.match(r"\[LOW\] ([^:]+): PRESENT", f)
        if m:
            header = m.group(1).strip()
            if header in seen_remove:
                continue
            seen_remove.add(header)
            headers_to_remove.append(header)
            continue

        if "[HIGH] HTTPS:" in f:
            flags["https_redirect"] = True
            continue
        if "[MEDIUM] Set-Cookie:" in f:
            flags["cookies"] = True
            continue
        if "[CRITICAL] SSL/TLS Error" in f:
            flags["tls_error"] = True
            continue

    return headers_to_set, headers_to_remove, flags


def build_apache_config(result):
    """Render an Apache mod_headers snippet for this result, or '' if nothing to do."""
    headers_to_set, headers_to_remove, flags = _collect_header_actions(result)
    if not (headers_to_set or headers_to_remove or any(flags.values())):
        return ""

    lines = []
    lines.append("# Apache — requires mod_headers (a2enmod headers).")
    lines.append("# Place in httpd.conf, the virtual host, or a .htaccess file.")
    lines.append("<IfModule mod_headers.c>")
    for h, v in headers_to_set:
        # Escape any embedded double quotes in the value
        safe_v = v.replace('"', '\\"')
        lines.append(f'    Header always set {h} "{safe_v}"')
    for h in headers_to_remove:
        lines.append(f"    Header always unset {h}")
    lines.append("</IfModule>")

    if flags["cookies"]:
        lines.append("")
        lines.append("# Cookie hardening — prefer setting these in your app. Apache fallback:")
        lines.append(
            '# Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Strict"'
        )
    if flags["https_redirect"]:
        lines.append("")
        lines.append("# Force HTTP → HTTPS (requires mod_rewrite):")
        lines.append("# <IfModule mod_rewrite.c>")
        lines.append("#     RewriteEngine On")
        lines.append("#     RewriteCond %{HTTPS} off")
        lines.append("#     RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]")
        lines.append("# </IfModule>")
    if flags["tls_error"]:
        lines.append("")
        lines.append("# TLS errors detected — review SSLCertificateFile / SSLProtocol / SSLCipherSuite.")

    return "\n".join(lines)


def build_nginx_config(result):
    """Render an nginx snippet for this result, or '' if nothing to do."""
    headers_to_set, headers_to_remove, flags = _collect_header_actions(result)
    if not (headers_to_set or headers_to_remove or any(flags.values())):
        return ""

    lines = []
    lines.append("# Nginx — place inside the relevant server {} block,")
    lines.append("# or include via /etc/nginx/conf.d/security-headers.conf.")
    for h, v in headers_to_set:
        safe_v = v.replace('"', '\\"')
        lines.append(f'add_header {h} "{safe_v}" always;')

    if "Server" in headers_to_remove:
        lines.append("server_tokens off;  # hides nginx version from the Server header")
    other_removes = [h for h in headers_to_remove if h != "Server"]
    if other_removes:
        lines.append("# Stripping the headers below requires the ngx_headers_more module:")
        for h in other_removes:
            lines.append(f'# more_clear_headers "{h}";')

    if flags["cookies"]:
        lines.append("")
        lines.append("# Cookie hardening — prefer setting these in your app. Nginx fallback (1.19.3+):")
        lines.append("# proxy_cookie_flags ~ secure httponly samesite=strict;")
    if flags["https_redirect"]:
        lines.append("")
        lines.append("# Force HTTP → HTTPS (separate server block):")
        lines.append("# server {")
        lines.append("#     listen 80;")
        lines.append("#     listen [::]:80;")
        lines.append("#     server_name _;")
        lines.append("#     return 301 https://$host$request_uri;")
        lines.append("# }")
    if flags["tls_error"]:
        lines.append("")
        lines.append("# TLS errors detected — review ssl_certificate / ssl_protocols / ssl_ciphers.")

    return "\n".join(lines)


def build_nginx_nonce_template(result):
    """
    Render a ready-to-paste nginx config that uses per-request nonces +
    'strict-dynamic' instead of 'unsafe-inline'. This is the Bitsight-friendly
    way to handle pages that contain inline scripts/styles you cannot refactor
    (e.g. a vendored MinIO console).

    Returns '' when the page has no inline content (the strict CSP is enough).
    """
    csp = result.get("csp_suggestion")
    if not csp:
        return ""
    # If neither practical nor hashed variants exist, the page has no inline
    # content — a nonce template would add complexity without benefit.
    if not (result.get("csp_suggestion_practical") or result.get("csp_suggestion_hashed")):
        return ""

    # Pull external origins out of the strict CSP so we can keep them in the
    # nonce variant. (Quick-and-dirty — re-parses our own output.)
    extra_script_origins = []
    extra_style_origins = []
    extra_img_sources = []
    extra_font_sources = []
    extra_connect_origins = []
    for directive in csp.split("; "):
        parts = directive.split()
        if not parts:
            continue
        name, tokens = parts[0], parts[1:]
        externals = [t for t in tokens if t.startswith(("http://", "https://", "data:", "blob:"))]
        if name == "script-src":
            extra_script_origins.extend(externals)
        elif name == "style-src":
            extra_style_origins.extend(externals)
        elif name == "img-src":
            extra_img_sources.extend(externals)
        elif name == "font-src":
            extra_font_sources.extend(externals)
        elif name == "connect-src":
            extra_connect_origins.extend(externals)

    # Don't re-emit tokens that the template already hard-codes in its baseline
    # (otherwise we get e.g. "img-src 'self' data: blob: data:").
    _baseline_tokens = {"'self'", "'none'", "data:", "blob:"}

    def _join(extras):
        filtered = sorted({t for t in extras if t not in _baseline_tokens})
        return (" " + " ".join(filtered)) if filtered else ""

    # eval() / new Function() can ONLY be allowed by 'unsafe-eval' — neither
    # nonces, hashes, nor 'strict-dynamic' permit them. If the page uses eval,
    # the nonce template must include 'unsafe-eval' or the page breaks.
    inline_flags = result.get("csp_inline_flags") or {}
    unsafe_eval_token = " 'unsafe-eval'" if inline_flags.get("eval") else ""
    eval_comment = ""
    if inline_flags.get("eval"):
        eval_comment = (
            "\n# NOTE: 'unsafe-eval' is included because the page was observed using "
            "eval()/new Function().\n"
            "# This is unavoidable without modifying the application source. "
            "Bitsight penalises\n"
            "# 'unsafe-eval' less than 'unsafe-inline' (no HTML-injection surface).\n"
        )

    template = f"""# Nginx + per-request CSP nonce — Bitsight/SecurityScorecard-friendly
# alternative to 'unsafe-inline'. Generated for: {result['url']}
#
# Requirements (one of):
#   - nginx-extras package (apt install nginx-extras) for set_secure_random_alphanum
#   - OR OpenResty / nginx + lua-nginx-module
#
# Place inside the relevant 'location' or 'server' block.
{eval_comment}
# 1. Fresh 32-char nonce for every request.
set_secure_random_alphanum $cspNonce 32;

# 2. Disable upstream compression so sub_filter can rewrite the response body.
proxy_set_header Accept-Encoding "";

# 3. Inject nonce into every <script> and <style> tag.
sub_filter_once off;
sub_filter_types text/html;
sub_filter '<script'  '<script nonce="$cspNonce"';
sub_filter '<style'   '<style nonce="$cspNonce"';

# 4. CSP using 'nonce-...' + 'strict-dynamic'. The nonce-allowed root script
#    can then load other scripts transitively without origin allowlisting.
add_header Content-Security-Policy "\\
default-src 'self'; \\
script-src 'nonce-$cspNonce' 'strict-dynamic'{unsafe_eval_token}{_join(extra_script_origins)}; \\
style-src 'nonce-$cspNonce'{_join(extra_style_origins)}; \\
img-src 'self' data: blob:{_join(extra_img_sources)}; \\
font-src 'self' data:{_join(extra_font_sources)}; \\
connect-src 'self'{_join(extra_connect_origins)}; \\
object-src 'none'; base-uri 'self'; frame-ancestors 'self'; \\
upgrade-insecure-requests; block-all-mixed-content; \\
require-trusted-types-for 'script'\\
" always;

# Keep Referrer-Policy on its OWN header — it is NOT a CSP directive.
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""
    return template


def format_config_examples(result):
    """Combined Apache + Nginx snippet block for plain-text output."""
    apache = build_apache_config(result)
    nginx = build_nginx_config(result)
    if not apache and not nginx:
        return ""
    sections = []
    if apache:
        sections.append("[Apache]\n" + apache)
    if nginx:
        sections.append("[Nginx]\n" + nginx)
    return "\n\n".join(sections)


def count_severities(result):
    """Return (critical, high, medium, low) counts for a result."""
    all_findings = result["header_findings"] + result["js_findings"]
    critical = sum(1 for f in all_findings if "[CRITICAL]" in f)
    high = sum(1 for f in all_findings if "[HIGH]" in f)
    medium = sum(1 for f in all_findings if "[MEDIUM]" in f)
    low = sum(1 for f in all_findings if "[LOW]" in f)
    return critical, high, medium, low


def has_issues(result):
    all_findings = result["header_findings"] + result["js_findings"]
    return any(
        tag in f
        for f in all_findings
        for tag in ["[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]"]
    )


def format_findings(result):
    """Format all findings into a single string for CSV output."""
    lines = []
    lines.append(f"=== HTTP Status: {result['status']} ===")

    lines.append("")
    lines.append("--- Security Headers ---")
    if result["header_findings"]:
        for f in result["header_findings"]:
            lines.append(f"  {f}")
    else:
        lines.append("  No findings.")

    lines.append("")
    lines.append("--- JavaScript Libraries ---")
    if result["js_findings"]:
        for f in result["js_findings"]:
            lines.append(f"  {f}")
    else:
        lines.append("  No JS libraries detected / No findings.")

    critical, high, medium, low = count_severities(result)

    lines.append("")
    lines.append(
        f"--- Summary: {critical} CRITICAL | {high} HIGH | {medium} MEDIUM | {low} LOW ---"
    )

    return "\n".join(lines)


def format_recommendations(result):
    """Format recommendations as a readable bulleted string."""
    recs = generate_recommendations(result)
    if not recs:
        return "No recommendations - no issues detected."
    return "\n".join(f"  - {r}" for r in recs)


def write_csv(output_path, results):
    """Write results to a CSV file with a recommendations column."""
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "URL",
            "Has Issues",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Results",
            "Recommendations",
            "Generated CSP (Strict)",
            "Generated CSP (Hash-based)",
            "Generated CSP (Practical)",
            "CSP Warnings",
            "Apache Config",
            "Nginx Config",
            "Nginx Nonce Template",
        ])

        for result in sorted(results, key=lambda x: x["url"]):
            formatted = format_findings(result)
            recs = generate_recommendations(result)
            recs_text = "\n".join(f"- {r}" for r in recs) if recs else ""
            critical, high, medium, low = count_severities(result)
            csp_warnings = "\n".join(f"- {n}" for n in result.get("csp_notes", []))
            writer.writerow([
                result["url"],
                "YES" if has_issues(result) else "NO",
                critical,
                high,
                medium,
                low,
                formatted,
                recs_text,
                result.get("csp_suggestion") or "",
                result.get("csp_suggestion_hashed") or "",
                result.get("csp_suggestion_practical") or "",
                csp_warnings,
                build_apache_config(result),
                build_nginx_config(result),
                build_nginx_nonce_template(result),
            ])


REPORT_WIDTH = 78


def _format_csp_pretty(csp_value, indent="      "):
    """
    Pretty-print a CSP header value. Splits directives onto separate lines and
    wraps long source lists (hashes, multiple origins) so each token is on its
    own line under its directive. Returns '' if input is empty.
    """
    if not csp_value:
        return ""
    directives = [d.strip() for d in csp_value.split(";") if d.strip()]
    if not directives:
        return ""
    name_width = max(len(d.split(maxsplit=1)[0]) for d in directives)

    lines = []
    for i, directive in enumerate(directives):
        parts = directive.split()
        name = parts[0]
        tokens = parts[1:]
        terminator = ";" if i < len(directives) - 1 else ""

        if not tokens:
            lines.append(f"{indent}{name}{terminator}")
            continue

        one_line = f"{indent}{name.ljust(name_width)} {' '.join(tokens)}{terminator}"
        if len(one_line) <= REPORT_WIDTH + 20:
            lines.append(one_line)
            continue

        # Wrap: directive name + first token on line 1, remaining tokens stacked under
        lines.append(f"{indent}{name.ljust(name_width)} {tokens[0]}")
        inner_indent = " " * (len(indent) + name_width + 1)
        for t in tokens[1:-1]:
            lines.append(f"{inner_indent}{t}")
        lines.append(f"{inner_indent}{tokens[-1]}{terminator}")
    return "\n".join(lines)


def _split_header_findings(header_findings):
    """
    Bucket findings by severity. [INFO] entries are dropped because they
    duplicate the structured csp_suggestion / csp_notes fields, which we render
    in dedicated sections.
    """
    buckets = {"critical": [], "high": [], "medium": [], "low": [], "ok": []}
    for f in header_findings:
        for sev in ("critical", "high", "medium", "low", "ok"):
            tag = f"[{sev.upper()}]"
            if f.startswith(tag):
                buckets[sev].append(f[len(tag):].lstrip())
                break
    return buckets


def _wrap_indented(text, first_prefix, width=REPORT_WIDTH):
    """Wrap `text` so the first line starts with `first_prefix` and continuation
    lines are indented under it."""
    return textwrap.fill(
        text,
        width=width,
        initial_indent=first_prefix,
        subsequent_indent=" " * len(first_prefix),
        break_long_words=False,
        break_on_hyphens=False,
    )


def _section_header(title):
    return f"{title}\n{'-' * REPORT_WIDTH}\n"


def _write_url_section(f, result):
    crit, high, med, low = count_severities(result)
    f.write("=" * REPORT_WIDTH + "\n")
    f.write(f"  {result['url']}\n")
    f.write(
        f"  HTTP {result['status']}  |  "
        f"{crit} CRITICAL  |  {high} HIGH  |  {med} MEDIUM  |  {low} LOW\n"
    )
    f.write("=" * REPORT_WIDTH + "\n\n")

    buckets = _split_header_findings(result["header_findings"])

    # ── ISSUES TO FIX ──
    issues_exist = any(buckets[s] for s in ("critical", "high", "medium", "low"))
    if issues_exist:
        f.write(_section_header("ISSUES TO FIX"))
        for sev in ("critical", "high", "medium", "low"):
            for msg in buckets[sev]:
                tag = f"[{sev.upper()}]"
                f.write(_wrap_indented(msg, f"  {tag.ljust(9)} ") + "\n\n")

    # ── HEADERS PASSING (compact list) ──
    if buckets["ok"]:
        ok_names = []
        for line in buckets["ok"]:
            header_name = line.split(":", 1)[0].strip()
            ok_names.append(header_name)
        f.write(_section_header(f"HEADERS PASSING ({len(ok_names)})"))
        # Two columns when the list is long
        if len(ok_names) >= 6:
            mid = (len(ok_names) + 1) // 2
            col1 = ok_names[:mid]
            col2 = ok_names[mid:]
            colw = max((len(n) for n in col1), default=0) + 4
            for i in range(mid):
                left = f"[OK] {col1[i]}"
                right = f"[OK] {col2[i]}" if i < len(col2) else ""
                f.write(f"  {left.ljust(colw + 5)}{right}\n")
        else:
            for n in ok_names:
                f.write(f"  [OK] {n}\n")
        f.write("\n")

    # ── JAVASCRIPT LIBRARIES ──
    if result["js_findings"]:
        f.write(_section_header("JAVASCRIPT LIBRARIES"))
        for js in result["js_findings"]:
            f.write(f"  {js}\n")
        f.write("\n")

    # ── RECOMMENDED CSP ──
    strict = result.get("csp_suggestion")
    hashed = result.get("csp_suggestion_hashed")
    practical = result.get("csp_suggestion_practical")
    if strict:
        f.write(_section_header("RECOMMENDED CSP — pick one option to apply"))
        f.write(
            "  [Option A] Strict — no 'unsafe-inline'. Best Bitsight score.\n"
            "             WARNING: blocks any inline scripts/styles the page uses.\n"
        )
        f.write("  Content-Security-Policy:\n")
        f.write(_format_csp_pretty(strict, indent="      ") + "\n\n")

        if hashed:
            f.write(
                "  [Option B] Hash-based — Bitsight-friendly without breaking inline\n"
                "             content. Hashes drift if MinIO/page injects dynamic\n"
                "             content per request; re-scan after each upgrade.\n"
            )
            f.write("  Content-Security-Policy:\n")
            f.write(_format_csp_pretty(hashed, indent="      ") + "\n\n")

        if practical:
            f.write(
                "  [Option C] Practical — works immediately. Includes\n"
                "             'unsafe-inline'/'unsafe-eval'. Bitsight will downgrade\n"
                "             the score for these tokens.\n"
            )
            f.write("  Content-Security-Policy:\n")
            f.write(_format_csp_pretty(practical, indent="      ") + "\n\n")

    # ── CSP WARNINGS ──
    notes = result.get("csp_notes") or []
    if notes:
        f.write(_section_header("CSP WARNINGS"))
        for note in notes:
            f.write(_wrap_indented(note, "  - ") + "\n\n")

    # ── READY-TO-PASTE SERVER CONFIG ──
    apache = build_apache_config(result)
    nginx = build_nginx_config(result)
    nonce = build_nginx_nonce_template(result)
    if apache or nginx or nonce:
        f.write(_section_header("READY-TO-PASTE SERVER CONFIG"))
        if nginx:
            f.write("  --- Nginx ---\n")
            for line in nginx.split("\n"):
                f.write(f"  {line}\n" if line else "\n")
            f.write("\n")
        if apache:
            f.write("  --- Apache ---\n")
            for line in apache.split("\n"):
                f.write(f"  {line}\n" if line else "\n")
            f.write("\n")
        if nonce:
            f.write("  --- Nginx Nonce Template (BEST for Bitsight) ---\n")
            for line in nonce.split("\n"):
                f.write(f"  {line}\n" if line else "\n")
            f.write("\n")

    f.write("\n")


def write_txt(output_path, results):
    """Write results in a structured, human-readable layout."""
    sorted_results = sorted(results, key=lambda x: x["url"])
    with open(output_path, "w", encoding="utf-8") as f:
        # ── Report header ──
        f.write("=" * REPORT_WIDTH + "\n")
        f.write("  Web Security Scanner — Report\n")
        f.write(f"  Generated: {date.today().isoformat()}  |  URLs scanned: {len(sorted_results)}\n")
        f.write("=" * REPORT_WIDTH + "\n\n")

        # ── Executive summary ──
        f.write(_section_header("SUMMARY"))
        for result in sorted_results:
            crit, high, med, low = count_severities(result)
            parts = []
            if crit:
                parts.append(f"{crit}C")
            if high:
                parts.append(f"{high}H")
            if med:
                parts.append(f"{med}M")
            if low:
                parts.append(f"{low}L")
            issues_compact = "/".join(parts) if parts else "clean"
            url_short = result["url"]
            if len(url_short) > 55:
                url_short = url_short[:52] + "..."
            status_str = f"HTTP {result['status']}"
            f.write(f"  {url_short:<55}  {status_str:<10}  {issues_compact}\n")
        f.write("\n")
        f.write("  Legend: C=Critical  H=High  M=Medium  L=Low\n\n")

        # ── Per-URL details ──
        for result in sorted_results:
            _write_url_section(f, result)


def main():
    parser = argparse.ArgumentParser(
        description="Web Security Scanner - Security Headers & JS Library Vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i urls.txt -o results.csv
  %(prog)s -i urls.txt -o results.txt --format txt        (human-readable plain text)
  %(prog)s -i urls.txt -o results.csv --timeout 20 --threads 5
  %(prog)s -i urls.txt -o results.csv --retire            (use retire.js if installed)
  %(prog)s -i urls.txt -o results.csv --gen-csp           (auto-generate strict CSP per URL)
  %(prog)s -i urls.txt -o results.csv --gen-csp --deep    (also capture JS-injected sources)

Input file format (urls.txt):
  https://example.com
  https://test.site.com
  http://vulnerable-app.local
        """,
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Input text file with URLs (one per line)"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Output file path"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "txt"],
        default=None,
        help="Output format: 'csv' or 'txt' (default: inferred from output file extension, falls back to csv)",
    )
    parser.add_argument(
        "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)"
    )
    parser.add_argument(
        "--threads", type=int, default=3, help="Number of concurrent threads (default: 3)"
    )
    parser.add_argument(
        "--retire",
        action="store_true",
        help="Use retire.js for JS library scanning (must be installed: npm install -g retire)",
    )
    parser.add_argument(
        "--no-csp",
        action="store_true",
        help="Skip Content-Security-Policy header checks (CSP is often hard for developers to fix)",
    )
    parser.add_argument(
        "--gen-csp",
        action="store_true",
        help="Always auto-generate a strict CSP from observed page sources "
             "(populates the 'Generated CSP' CSV column for every URL)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Use headless Chromium (Playwright) to also capture JS-injected "
             "resources for CSP generation. Requires: pip install playwright && "
             "playwright install chromium",
    )

    args = parser.parse_args()

    # Read URLs
    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    with open(args.input, "r") as f:
        urls = [
            line.strip()
            for line in f.readlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    if not urls:
        print("[!] No URLs found in input file.")
        sys.exit(1)

    print(f"[*] Loaded {len(urls)} URL(s) from {args.input}")

    # Check retire.js availability
    use_retire = False
    if args.retire:
        if check_retire_js_available():
            print("[+] retire.js detected - will use for JS vulnerability scanning")
            use_retire = True
        else:
            print(
                "[!] retire.js not found. Install with: npm install -g retire\n"
                "    Falling back to built-in JS scanner."
            )

    # Scan
    session = get_session()
    results = []

    print(f"[*] Scanning with {args.threads} thread(s), timeout={args.timeout}s...")
    print("-" * 60)

    # Deep mode is single-threaded per URL via Playwright; warn if user combined them
    if args.deep and args.threads > 1:
        print(
            "[!] --deep launches a headless browser per URL; consider --threads 1 "
            "if you hit resource limits."
        )

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(
                scan_url, url, session, use_retire, args.timeout, args.no_csp,
                args.gen_csp, args.deep,
            ): url
            for url in urls
        }

        for i, future in enumerate(as_completed(future_to_url), 1):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)

                # Count issues for progress display
                all_findings = result["header_findings"] + result["js_findings"]
                issues = sum(
                    1
                    for f in all_findings
                    if any(
                        tag in f
                        for tag in ["[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]"]
                    )
                )
                print(
                    f"  [{i}/{len(urls)}] {result['url']} "
                    f"(HTTP {result['status']}) - {issues} issue(s) found"
                )
            except Exception as e:
                print(f"  [{i}/{len(urls)}] {url} - SCAN ERROR: {e}")
                results.append(
                    {
                        "url": url,
                        "status": "SCAN_ERROR",
                        "header_findings": [f"[ERROR] {str(e)}"],
                        "js_findings": [],
                        "csp_suggestion": None,
                        "csp_suggestion_practical": None,
                        "csp_suggestion_hashed": None,
                        "csp_inline_flags": {},
                        "csp_notes": [],
                    }
                )

    # Determine output format
    output_format = args.format
    if output_format is None:
        ext = os.path.splitext(args.output)[1].lower().lstrip(".")
        output_format = ext if ext in ("csv", "txt") else "csv"

    print("-" * 60)
    print(f"[*] Writing results to {args.output} (format: {output_format})...")

    if output_format == "txt":
        write_txt(args.output, results)
    else:
        write_csv(args.output, results)

    print(f"[+] Done! Results saved to: {args.output}")
    print(f"[+] Total URLs scanned: {len(results)}")

    # Print overall summary
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    for r in results:
        all_f = r["header_findings"] + r["js_findings"]
        total_critical += sum(1 for f in all_f if "[CRITICAL]" in f)
        total_high += sum(1 for f in all_f if "[HIGH]" in f)
        total_medium += sum(1 for f in all_f if "[MEDIUM]" in f)
        total_low += sum(1 for f in all_f if "[LOW]" in f)

    print(
        f"[+] Overall: {total_critical} CRITICAL | {total_high} HIGH | "
        f"{total_medium} MEDIUM | {total_low} LOW"
    )


if __name__ == "__main__":
    main()
