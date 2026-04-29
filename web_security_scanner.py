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
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
def check_security_headers(url, response):
    """Analyze security headers and return findings."""
    findings = []
    headers = response.headers
    is_https = url.startswith("https://")

    # Check required/recommended security headers
    for header_name, config in SECURITY_HEADERS.items():
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
# Main Scanner
# ─────────────────────────────────────────────
def scan_url(url, session, use_retire=False, timeout=15):
    """Scan a single URL for security issues."""
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"url": url, "status": None, "header_findings": [], "js_findings": []}

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
        result["header_findings"] = check_security_headers(url, response)

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

    for f in result["header_findings"]:
        # Missing security header
        m = re.match(r"\[(?:HIGH|MEDIUM)\] ([^:]+): MISSING", f)
        if m:
            header = m.group(1).strip()
            cfg = SECURITY_HEADERS.get(header)
            if cfg:
                recs.append(f"Add '{header}' header. Recommended: {cfg['recommended']}")
            continue

        # Misconfigured security header
        m = re.match(r"\[MEDIUM\] ([^:]+): MISCONFIGURED", f)
        if m:
            header = m.group(1).strip()
            cfg = SECURITY_HEADERS.get(header)
            if cfg:
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
        ])

        for result in sorted(results, key=lambda x: x["url"]):
            formatted = format_findings(result)
            recs = generate_recommendations(result)
            recs_text = "\n".join(f"- {r}" for r in recs) if recs else ""
            critical, high, medium, low = count_severities(result)
            writer.writerow([
                result["url"],
                "YES" if has_issues(result) else "NO",
                critical,
                high,
                medium,
                low,
                formatted,
                recs_text,
            ])


def write_txt(output_path, results):
    """Write results to a human-readable plain text file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("Web Security Scanner - Results\n")
        f.write("=" * 70 + "\n\n")

        for result in sorted(results, key=lambda x: x["url"]):
            critical, high, medium, low = count_severities(result)
            issues_flag = "YES" if has_issues(result) else "NO"

            f.write("-" * 70 + "\n")
            f.write(f"URL: {result['url']}\n")
            f.write(f"Has Issues: {issues_flag}\n")
            f.write(
                f"Severity Counts: {critical} CRITICAL | {high} HIGH | "
                f"{medium} MEDIUM | {low} LOW\n"
            )
            f.write("-" * 70 + "\n")
            f.write(format_findings(result) + "\n\n")

            f.write("--- Recommendations ---\n")
            f.write(format_recommendations(result) + "\n\n")


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

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(scan_url, url, session, use_retire, args.timeout): url
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
