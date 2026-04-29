# Security Headers & Secure Cookie Configuration Manual

This manual explains how to apply security header and secure cookie configurations for each supported technology. Use these configurations alongside the `web_security_scanner.py` tool to verify that your server is properly secured.

---

## Table of Contents

1. [Overview of Security Headers](#1-overview-of-security-headers)
2. [Overview of Secure Cookie Flags](#2-overview-of-secure-cookie-flags)
3. [TLS/HTTPS Security](#3-tlshttps-security)
4. [Node.js (Express)](#4-nodejs-express)
5. [AngularJS](#5-angularjs)
6. [Next.js](#6-nextjs)
7. [Apache HTTP Server](#7-apache-http-server)
8. [Nginx](#8-nginx)
9. [Apache Tomcat](#9-apache-tomcat)
10. [Microsoft IIS](#10-microsoft-iis)
11. [Verification](#11-verification)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Overview of Security Headers

Each configuration file sets the following security headers:

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Forces browsers to use HTTPS for all future requests |
| `Content-Security-Policy` | Controls which resources the browser is allowed to load |
| `X-Content-Type-Options` | Prevents MIME type sniffing attacks |
| `X-Frame-Options` | Prevents clickjacking by blocking framing |
| `Referrer-Policy` | Controls referrer information sent with requests |
| `Permissions-Policy` | Restricts access to browser features (camera, mic, etc.) |
| `X-XSS-Protection` | Legacy XSS filter for older browsers |
| `Cross-Origin-Opener-Policy` | Isolates browsing context from cross-origin documents |
| `Cross-Origin-Resource-Policy` | Controls cross-origin resource sharing |
| `Cross-Origin-Embedder-Policy` | Requires CORP/CORS for all cross-origin resources |
| `Cache-Control` | Prevents caching of sensitive responses |

---

## 2. Overview of Secure Cookie Flags

All configurations enforce these cookie security attributes:

| Flag | Purpose |
|---|---|
| `Secure` | Cookie is only sent over HTTPS connections |
| `HttpOnly` | Cookie is not accessible via JavaScript (`document.cookie`) |
| `SameSite=Strict` | Cookie is not sent with cross-site requests (prevents CSRF) |
| `Path=/` | Limits cookie scope to the root path |
| `Max-Age` | Sets an explicit expiration time instead of relying on session cookies |
| `__Host-` prefix | (Where supported) Enforces `Secure`, `Path=/`, and no `Domain` attribute |

---

## 3. TLS/HTTPS Security

Properly configuring TLS is the foundation of HTTPS security. Without secure TLS settings, security headers and cookie flags are meaningless because the transport layer itself is compromised.

### Why TLS Configuration Matters

| Risk | Impact |
|------|--------|
| Outdated TLS versions (1.0, 1.1) | Vulnerable to POODLE, BEAST, and other attacks |
| Weak cipher suites (RC4, DES, 3DES) | Traffic can be decrypted by attackers |
| No forward secrecy | Past traffic can be decrypted if private key is compromised |
| Expired or misconfigured certificates | Browsers show warnings, users lose trust |
| Missing OCSP stapling | Slower connections, privacy concerns |

### Minimum TLS Requirements

- **Protocols:** Only TLS 1.2 and TLS 1.3 (disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
- **Ciphers:** AEAD ciphers with ECDHE key exchange (GCM, CHACHA20-POLY1305)
- **Certificates:** RSA 2048-bit minimum (4096 recommended) or ECDSA P-256+
- **OCSP Stapling:** Enabled for performance and privacy
- **HSTS:** Enabled with `max-age=31536000; includeSubDomains; preload`

### Quick TLS Testing Commands

```bash
# Check TLS version and cipher in use
curl -vI https://your-domain.com 2>&1 | grep -E "SSL connection|TLS|cipher"

# Verify TLS 1.0/1.1 are disabled (should fail)
openssl s_client -connect your-domain.com:443 -tls1
openssl s_client -connect your-domain.com:443 -tls1_1

# Check certificate expiration
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | \
  openssl x509 -noout -dates

# Full scan with testssl.sh
./testssl.sh your-domain.com

# Online: SSL Labs (aim for A+ grade)
# https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com
```

### Detailed TLS Guide

For comprehensive TLS configuration including:
- Server-specific configurations (Nginx, Apache, Tomcat, Node.js)
- Certificate management with Let's Encrypt
- Common TLS vulnerabilities and how to fix them
- Complete best practices checklist
- Troubleshooting guide

See the dedicated guide: **[`tls_security_guide.md`](tls_security_guide.md)**

---

## 4. Node.js (Express)

**File:** `nodejs_security_config.js`

### Prerequisites

```bash
npm install express helmet cookie-parser express-session
```

### How to Use

**Option A: Use as your main application file**

```bash
# Copy the configuration
cp nodejs_security_config.js /path/to/your/project/app.js

# Edit as needed, then run
node app.js
```

**Option B: Import security configuration into an existing app**

Extract the middleware setup into a module and import it:

```javascript
// security.js
const helmet = require('helmet');

module.exports = function applySecurityHeaders(app) {
  app.use(helmet({ /* ... copy helmet config from the example ... */ }));

  // Add Permissions-Policy
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', '...');
    next();
  });
};
```

```javascript
// app.js (your existing application)
const express = require('express');
const applySecurityHeaders = require('./security');

const app = express();
applySecurityHeaders(app);

// ... your existing routes ...
```

### Key Settings to Customize

- **CSP directives**: Adjust `scriptSrc`, `styleSrc`, `imgSrc`, `connectSrc` to match your application's resource origins
- **Session secret**: Set `SESSION_SECRET` environment variable in production
- **Cookie maxAge**: Adjust session and cookie lifetimes for your use case
- **SameSite policy**: Use `'lax'` instead of `'strict'` if your app needs cross-site navigation with cookies (e.g., OAuth redirects)

---

## 5. AngularJS

**File:** `angularjs_security_config.js`

### Prerequisites

```bash
npm install express helmet cookie-parser
```

For AngularJS client-side:
```html
<script src="angular.js"></script>
<script src="angular-sanitize.js"></script>
```

### How to Use

This file contains **two parts**:

**Part 1: Server Configuration (Express)**

The server section serves your AngularJS static files with security headers. It also provides CSRF protection compatible with AngularJS's built-in `$http` XSRF handling.

```bash
# Copy and customize the server portion
cp angularjs_security_config.js /path/to/your/project/server.js

# Place your AngularJS app in a 'public' directory
mkdir -p public
cp -r your-angular-app/* public/

# Run the server
node server.js
```

**Part 2: Client-Side Configuration (AngularJS)**

Extract the AngularJS module from Part 2 of the file and save it as `app-security.js` in your AngularJS application:

```html
<!-- index.html -->
<html ng-app="myApp" ng-csp>
<head>
  <script src="angular.js"></script>
  <script src="angular-sanitize.js"></script>
  <script src="app-security.js"></script>
  <script src="app.js"></script>
</head>
```

```javascript
// app.js
angular.module('myApp', ['ngSanitize', 'appSecurity']);
```

### Key Settings to Customize

- **CSP `script-src`**: If you use `ng-csp`, you should not need `'unsafe-eval'`. If templates are not pre-compiled, you may need it.
- **`$sceDelegateProvider`**: Add trusted CDN domains if your app loads templates or resources from external sources.
- **XSRF cookie/header names**: Default is `XSRF-TOKEN` / `X-XSRF-TOKEN`; change if your server uses different names.

---

## 6. Next.js

**File:** `nextjs_security_config.js`

### How to Use

This file contains **three parts**:

**Part 1: next.config.js**

Copy the `nextConfig` object into your project's `next.config.js`:

```bash
# Back up your existing config
cp next.config.js next.config.js.bak

# Merge the security headers into your next.config.js
```

If you already have a `headers()` function, merge the header entries:

```javascript
// next.config.js
const nextConfig = {
  poweredByHeader: false,
  // ... your existing config ...
  async headers() {
    return [
      // ... copy the header entries from the example ...
    ];
  },
};
module.exports = nextConfig;
```

**Part 2: middleware.ts (CSP with Nonce)**

Copy the middleware code into `middleware.ts` at your project root:

```bash
# Create middleware.ts at project root
touch middleware.ts
# Paste the middleware code from Part 2
```

To use the nonce in your layout:

```tsx
// app/layout.tsx
import { headers } from 'next/headers';

export default async function RootLayout({ children }) {
  const headersList = await headers();
  const nonce = headersList.get('X-Nonce') || '';

  return (
    <html>
      <head>
        <script nonce={nonce} src="/your-script.js" />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

**Part 3: Secure Cookie in API Routes**

Use the cookie-setting pattern from Part 3 in your API route handlers.

### Key Settings to Customize

- **CSP with nonces**: The middleware approach (Part 2) is more secure than the static CSP in Part 1. Choose one approach.
- **`script-src 'unsafe-inline' 'unsafe-eval'`**: Next.js may require these in development. Remove them in production if using nonce-based CSP.
- **Matcher**: Adjust the middleware matcher regex to include/exclude specific paths.
- **Cookie SameSite**: Use `'lax'` for session cookies if your app uses OAuth callbacks.

---

## 7. Apache HTTP Server

**File:** `apache_security.conf`

### Prerequisites

Enable required Apache modules:

```bash
# Debian/Ubuntu
sudo a2enmod headers rewrite ssl
sudo systemctl restart apache2

# CentOS/RHEL
# Ensure these lines are uncommented in httpd.conf:
# LoadModule headers_module modules/mod_headers.so
# LoadModule rewrite_module modules/mod_rewrite.so
# LoadModule ssl_module modules/mod_ssl.so
sudo systemctl restart httpd
```

### How to Use

**Option A: Include in your virtual host**

```apache
# /etc/apache2/sites-available/your-site.conf
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    # Include the security configuration
    Include /etc/apache2/conf-available/security-headers.conf

    # ... your other configuration ...
</VirtualHost>
```

```bash
# Copy the configuration file
sudo cp apache_security.conf /etc/apache2/conf-available/security-headers.conf
sudo a2enconf security-headers
sudo systemctl reload apache2
```

**Option B: Use as .htaccess**

```bash
# Copy to your web root (requires AllowOverride All)
cp apache_security.conf /var/www/html/.htaccess
```

**Option C: Add to global configuration**

```bash
# Append to the end of httpd.conf or apache2.conf
sudo cat apache_security.conf >> /etc/apache2/apache2.conf
sudo systemctl reload apache2
```

### Key Settings to Customize

- **CSP directives**: Modify the `Content-Security-Policy` header value to match your application's resource loading needs
- **Cookie rewrite rule**: The `Header edit Set-Cookie` rule applies `Secure; HttpOnly; SameSite=Strict` to all cookies. Adjust if some cookies need different settings.
- **SSL cipher suite**: Update based on your organization's TLS requirements
- **Upload directory path**: Change `/var/www/html/uploads` to match your actual upload directory
- **FilesMatch patterns**: Add or remove file extensions based on what you serve

---

## 8. Nginx

**File:** `nginx_security.conf`

### How to Use

**Option A: Include as a snippet**

```bash
# Copy the security headers section to a snippet file
sudo cp nginx_security.conf /etc/nginx/snippets/security-headers.conf
```

Then include it in your existing server block:

```nginx
# /etc/nginx/sites-available/your-site.conf
server {
    listen 443 ssl http2;
    server_name example.com;

    # Include security headers
    include /etc/nginx/snippets/security-headers.conf;

    # ... your other configuration ...
}
```

**Option B: Use as a complete server block**

```bash
# Copy as a site configuration
sudo cp nginx_security.conf /etc/nginx/sites-available/your-site.conf
sudo ln -s /etc/nginx/sites-available/your-site.conf /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

**Option C: Rate limiting (add to http block)**

The rate limiting zone must be defined in the `http {}` block of `nginx.conf`:

```nginx
# /etc/nginx/nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

    # ... your other http-level configuration ...
}
```

### Important: Nginx `add_header` Behavior

Nginx has a critical behavior: `add_header` directives in a child block (e.g., `location`) **completely override** all `add_header` directives from the parent block. This means if you add headers in a `location` block, you must re-add all security headers there too.

Solutions:
1. Use the `always` parameter (included in the example) to ensure headers are sent on all response codes
2. Use `include` to import a shared snippet in every `location` block that sets custom headers
3. Use the third-party `more_set_headers` module which does not have this inheritance behavior

### Key Settings to Customize

- **`server_name`**: Replace `example.com` with your actual domain
- **SSL certificate paths**: Update `ssl_certificate` and `ssl_certificate_key`
- **CSP directives**: Adjust the Content-Security-Policy value
- **`client_max_body_size`**: Increase if your application accepts large file uploads
- **Rate limiting**: Adjust `rate=10r/s` and `burst=20` for your traffic patterns
- **`proxy_cookie_flags`**: Uncomment if Nginx is acting as a reverse proxy

---

## 9. Apache Tomcat

**File:** `tomcat_security_config.xml`

### How to Use

The file contains three configuration sections. Apply each to the appropriate Tomcat configuration file.

**Part 1: web.xml (Security filters and cookie config)**

```bash
# For global application (applies to all apps)
sudo cp /path/to/tomcat/conf/web.xml /path/to/tomcat/conf/web.xml.bak

# For a specific application
cp WEB-INF/web.xml WEB-INF/web.xml.bak
```

Add the following sections from the example to your `web.xml`:
- `<filter>` and `<filter-mapping>` for `httpHeaderSecurity`
- `<session-config>` block for secure cookies
- `<error-page>` entries for custom error pages
- `<security-constraint>` for HTTPS enforcement

**Part 2: server.xml**

Edit `$CATALINA_HOME/conf/server.xml`:

```bash
sudo cp /path/to/tomcat/conf/server.xml /path/to/tomcat/conf/server.xml.bak
```

- Set `server=" "` and `xpoweredBy="false"` on all `<Connector>` elements
- Configure the HTTPS connector with proper TLS settings
- Set shutdown port to `-1` in production

**Part 3: context.xml (SameSite cookies)**

Edit `$CATALINA_HOME/conf/context.xml`:

```xml
<Context>
    <CookieProcessor
        className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"
        sameSiteCookies="Strict" />
</Context>
```

**Custom SecurityHeadersFilter (Optional)**

For headers not covered by the built-in `HttpHeaderSecurityFilter`:

```bash
# Create the filter class
mkdir -p src/main/java/com/example/security/
# Copy the SecurityHeadersFilter class from the example
# Compile and place the .class file in WEB-INF/classes/ or package as a .jar in WEB-INF/lib/
```

Then uncomment the corresponding `<filter>` and `<filter-mapping>` entries in `web.xml`.

### Restart Tomcat

```bash
# After making changes
$CATALINA_HOME/bin/shutdown.sh
$CATALINA_HOME/bin/startup.sh

# Or via systemd
sudo systemctl restart tomcat
```

### Key Settings to Customize

- **CSP directives**: Modify the Content-Security-Policy string in `SecurityHeadersFilter`
- **Session timeout**: Adjust `<session-timeout>30</session-timeout>` (in minutes)
- **SameSite policy**: Change from `Strict` to `Lax` if needed for cross-site navigation
- **Keystore path**: Update `certificateKeystoreFile` and password in server.xml
- **Error pages**: Create custom HTML error pages in your webapp

---

## 10. Microsoft IIS

**File:** `iis_security.config`

### Prerequisites

Install the IIS features and the URL Rewrite Module on the server:

```powershell
# Run in an elevated PowerShell prompt
Install-WindowsFeature -Name Web-Server, Web-Http-Redirect, Web-Filtering, Web-Static-Content

# Install URL Rewrite Module (required for the HTTPS redirect and outbound
# Set-Cookie rewrite rule). Download from:
# https://www.iis.net/downloads/microsoft/url-rewrite
```

### How to Use

The file is a complete `web.config` template. Apply it at one of three scopes:

**Option A: Per-site `web.config`**

```powershell
# Back up the existing web.config first
Copy-Item C:\inetpub\wwwroot\web.config C:\inetpub\wwwroot\web.config.bak

# Copy the example, then merge with any existing settings
Copy-Item iis_security.config C:\inetpub\wwwroot\web.config
```

**Option B: Per-application `web.config`**

Place the file at the application root (e.g., `C:\inetpub\wwwroot\myapp\web.config`). Settings here override the parent site's configuration.

**Option C: Server-wide via `applicationHost.config`**

For settings that apply to every site on the server (HSTS, request filtering, removed modules), edit `%windir%\System32\inetsrv\config\applicationHost.config` directly, or use the PowerShell snippets in **PART 2** of the example file.

### Apply SCHANNEL TLS Hardening

The file ships with PowerShell snippets in **PART 3** that disable SSL 2.0/3.0 and TLS 1.0/1.1, enable TLS 1.2/1.3, remove weak ciphers (RC4, DES, 3DES, NULL), and set a strong cipher suite order via Group Policy registry keys.

```powershell
# Run as Administrator. Reboot required after.
# Copy the Set-SchannelProtocol function and the disable/enable calls
# from PART 3 of iis_security.config and execute them.

Restart-Computer -Force
```

Verify with:

```powershell
# Confirm protocols
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'

# Confirm cipher suite order
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions
```

### Restart IIS

```powershell
# Reload configuration without dropping connections
iisreset /noforce

# Or restart a single site
Restart-WebSite -Name "Default Web Site"
```

### Key Settings to Customize

- **CSP directives**: Modify the `Content-Security-Policy` value in `<customHeaders>` to match your application's allowed origins
- **HSTS**: Use either the `Strict-Transport-Security` header **or** the native `<hsts>` element (IIS 10 1709+) - not both
- **Outbound Set-Cookie rule**: The default rule appends `Secure; HttpOnly; SameSite=Strict` unconditionally. If your application already sets these flags, you'll see duplicates - remove the rule or refine the match pattern
- **`requireSSL="true"` on `<httpCookies>`**: This breaks authentication if the site is reachable over HTTP. Remove it for HTTP-only development environments
- **`maxAllowedContentLength`**: Default is 10 MB - increase for sites that accept larger uploads
- **Custom error page paths**: Update `/error/400.html`, etc., to match your actual error page locations
- **Forms authentication**: Update `loginUrl`, `name`, and timeout to match your app
- **`machineKey`**: Generate explicit keys for any web farm or any site using forms auth / out-of-process session state

### Common IIS Pitfalls

- **`removeServerHeader="true"` is IIS 10+ only.** On older IIS, use a URL Rewrite outbound rule against `RESPONSE_Server`, or install the `URLScan` ISAPI filter.
- **WebDAV is enabled by default** on many IIS installs and exposes verbs like `PROPFIND`, `MKCOL`. The example removes the `WebDAVModule` - leave it removed unless you specifically need WebDAV.
- **`<customErrors>` (system.web) and `<httpErrors>` (system.webServer) are different.** ASP.NET errors go through `customErrors`; static-file and IIS-pipeline errors go through `httpErrors`. The example configures both.
- **Outbound rewrite rules run on every response.** A misconfigured `Set-Cookie` rule can break login flows that depend on the cookie format - test with a non-production user first.

---

## 11. Verification

After applying configurations, verify your security headers using the scanner:

```bash
# Scan a single URL
python3 web_security_scanner.py -u https://your-domain.com

# Scan multiple URLs from a file
python3 web_security_scanner.py -f urls.txt

# Check specific headers in the CSV output
python3 web_security_scanner.py -u https://your-domain.com -o results.csv
```

You can also verify manually:

```bash
# Check response headers with curl
curl -I https://your-domain.com

# Check specific header
curl -sI https://your-domain.com | grep -i "strict-transport-security"

# Check cookie flags
curl -sI https://your-domain.com | grep -i "set-cookie"
```

### TLS Verification

```bash
# Quick TLS check - verify TLS version and cipher
curl -vI https://your-domain.com 2>&1 | grep -E "SSL connection|TLS"

# Verify only TLS 1.2+ is enabled
openssl s_client -connect your-domain.com:443 -tls1_2 </dev/null 2>&1 | grep "Protocol"
openssl s_client -connect your-domain.com:443 -tls1_3 </dev/null 2>&1 | grep "Protocol"

# Verify TLS 1.0/1.1 are disabled (should fail)
openssl s_client -connect your-domain.com:443 -tls1 </dev/null 2>&1 | grep -i "error\|alert"
openssl s_client -connect your-domain.com:443 -tls1_1 </dev/null 2>&1 | grep -i "error\|alert"

# Check certificate expiration
echo | openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | \
  openssl x509 -noout -dates

# Verify OCSP Stapling
openssl s_client -connect your-domain.com:443 -servername your-domain.com -status </dev/null 2>/dev/null | \
  grep -A3 "OCSP Response"

# Check HTTP to HTTPS redirect
curl -sI http://your-domain.com | grep -i "location"

# Full scan (online)
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com
```

For a comprehensive TLS testing guide with additional tools (testssl.sh, nmap, sslyze), see **[`tls_security_guide.md`](tls_security_guide.md)**.

### Expected Results

A properly configured server should show:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: accelerometer=(), camera=(), ...
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cache-Control: no-store, no-cache, must-revalidate
```

Cookies should include:

```
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict; Path=/
```

---

## 12. Troubleshooting

### Common Issues

**Headers not appearing**
- Apache: Verify `mod_headers` is enabled (`apachectl -M | grep headers`)
- Nginx: Check that `add_header` is not overridden in a child `location` block
- Tomcat: Ensure the filter is mapped to `/*` and the filter class is on the classpath
- IIS: Verify the `web.config` parses (`%windir%\System32\inetsrv\appcmd list config`); a syntax error makes IIS serve a 500.19 with no headers at all

**CSP blocking resources**
- Use browser DevTools Console to identify blocked resources
- Temporarily use `Content-Security-Policy-Report-Only` header to test without blocking
- Add the necessary origins to the appropriate CSP directive

**Cookies missing security flags**
- Verify the application is served over HTTPS (required for `Secure` flag)
- Check that `__Host-` prefix cookies have `Secure`, `Path=/`, and no `Domain` attribute
- For Apache/Nginx, ensure cookie-rewriting rules run after the application sets cookies

**CORS errors after enabling COOP/COEP/CORP**
- If your app loads cross-origin resources (CDNs, APIs), you may need to:
  - Set `Cross-Origin-Embedder-Policy: credentialless` instead of `require-corp`
  - Add CORS headers to cross-origin resources
  - Temporarily disable COEP while testing

**SameSite cookie issues**
- Use `SameSite=Lax` instead of `Strict` if:
  - Your app uses OAuth/OpenID Connect redirects
  - Users navigate to your site from external links and need session persistence
  - Payment gateways redirect back to your site

**Next.js specific**
- `unsafe-eval` is required in development mode; use nonce-based CSP in production
- Static assets under `/_next/static/` should have different cache headers than HTML pages

**IIS specific**
- "HTTP Error 500.19 - Internal Server Error" usually means a web.config schema mismatch (e.g., `<rewrite>` without URL Rewrite Module installed, or `<hsts>` on IIS &lt; 10 1709). Install the missing module or remove the offending element.
- "Server" header still appearing after `removeServerHeader="true"`: requires IIS 10+. On older versions, add an outbound URL Rewrite rule that clears `RESPONSE_Server`.
- Cookies missing `Secure` despite `requireSSL="true"`: the site must be reached over HTTPS - over plain HTTP, ASP.NET will not emit the cookie at all.
- WebDAV verbs (`PROPFIND`, `MKCOL`) returning 405 unexpectedly: confirm `<modules><remove name="WebDAVModule" /></modules>` is in effect; otherwise the WebDAV module hijacks these verbs even when you don't use it.
- SCHANNEL changes appear to do nothing: SCHANNEL caches protocol/cipher state until reboot. After registry changes, run `Restart-Computer -Force`.

**TLS/HTTPS issues**
- Certificate chain errors: Use `fullchain.pem` (not just `cert.pem`) in your server config
- "SSL certificate has expired": Run `sudo certbot renew --force-renewal` and reload your server
- Mixed content warnings: Search your code for `http://` references and change them to `https://` or use `upgrade-insecure-requests` in CSP
- TLS 1.0/1.1 still enabled: Double-check `ssl_protocols` (Nginx) or `SSLProtocol` (Apache) directive
- OCSP stapling not working: Verify `ssl_trusted_certificate` points to the chain file and DNS resolver is reachable
- For detailed TLS troubleshooting, see **[`tls_security_guide.md`](tls_security_guide.md)**
