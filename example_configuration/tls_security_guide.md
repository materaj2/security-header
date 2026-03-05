# TLS/HTTPS Security Configuration Guide

A comprehensive guide for administrators to check, test, and configure TLS/HTTPS security across web servers. This guide covers testing tools, server-specific configurations, certificate management, and common vulnerabilities.

---

## Table of Contents

1. [TLS Fundamentals](#1-tls-fundamentals)
2. [Testing & Checking TLS Configuration](#2-testing--checking-tls-configuration)
3. [Nginx TLS Configuration](#3-nginx-tls-configuration)
4. [Apache HTTP Server TLS Configuration](#4-apache-http-server-tls-configuration)
5. [Apache Tomcat TLS Configuration](#5-apache-tomcat-tls-configuration)
6. [Node.js (Express) TLS Configuration](#6-nodejs-express-tls-configuration)
7. [Certificate Management with Let's Encrypt](#7-certificate-management-with-lets-encrypt)
8. [Common TLS Vulnerabilities](#8-common-tls-vulnerabilities)
9. [Best Practices Checklist](#9-best-practices-checklist)
10. [Troubleshooting TLS Issues](#10-troubleshooting-tls-issues)

---

## 1. TLS Fundamentals

### TLS Versions

| Version | Status | Notes |
|---------|--------|-------|
| SSL 2.0 | **DEPRECATED** | Broken, must be disabled |
| SSL 3.0 | **DEPRECATED** | Vulnerable to POODLE attack |
| TLS 1.0 | **DEPRECATED** | End-of-life since March 2021 (RFC 8996) |
| TLS 1.1 | **DEPRECATED** | End-of-life since March 2021 (RFC 8996) |
| TLS 1.2 | **RECOMMENDED** | Secure when configured with strong cipher suites |
| TLS 1.3 | **RECOMMENDED** | Latest version, improved security and performance |

**Minimum requirement:** Only enable **TLS 1.2** and **TLS 1.3**. Disable everything else.

### Cipher Suites

**TLS 1.3 cipher suites** (automatically secure, no configuration needed):
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`
- `TLS_CHACHA20_POLY1305_SHA256`

**Recommended TLS 1.2 cipher suites** (AEAD ciphers with forward secrecy):
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-AES128-GCM-SHA256`
- `ECDHE-RSA-AES128-GCM-SHA256`
- `ECDHE-ECDSA-CHACHA20-POLY1305`
- `ECDHE-RSA-CHACHA20-POLY1305`

**Avoid these ciphers:**
- Anything with `RC4`, `DES`, `3DES`, `MD5`
- Ciphers without `ECDHE` or `DHE` (no forward secrecy)
- `NULL` ciphers
- `EXPORT` ciphers
- Ciphers with `CBC` mode (vulnerable to padding oracle attacks in TLS 1.0/1.1)

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Forward Secrecy (PFS)** | Ensures past sessions cannot be decrypted even if the server's private key is compromised. Use ECDHE key exchange. |
| **OCSP Stapling** | Server fetches and caches the certificate revocation status, improving performance and privacy for clients. |
| **HSTS** | Tells browsers to always use HTTPS. Configured via HTTP header (see security header configs). |
| **HSTS Preload** | Submitting domain to browser preload lists so HTTPS is enforced before the first visit. |
| **Certificate Transparency (CT)** | Public logs of all issued certificates, helping detect mis-issued certificates. |
| **CAA Records** | DNS records specifying which Certificate Authorities may issue certificates for your domain. |

---

## 2. Testing & Checking TLS Configuration

### 2.1 Online Tools

#### SSL Labs (Qualys)

The most comprehensive online TLS scanner. Aim for an **A+** rating.

```
https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com
```

- Tests TLS versions, cipher suites, certificate chain, known vulnerabilities
- Provides a letter grade (A+ through F)
- Identifies specific issues and how to fix them

#### Mozilla Observatory

```
https://observatory.mozilla.org/analyze/your-domain.com
```

- Tests both TLS and HTTP security headers
- Provides security scoring and recommendations

### 2.2 Command-Line Tools

#### OpenSSL (built-in on most systems)

```bash
# Check which TLS versions are supported
openssl s_client -connect your-domain.com:443 -tls1_2
openssl s_client -connect your-domain.com:443 -tls1_3

# Verify TLS 1.0/1.1 are disabled (should fail with handshake error)
openssl s_client -connect your-domain.com:443 -tls1
openssl s_client -connect your-domain.com:443 -tls1_1

# View full certificate details
openssl s_client -connect your-domain.com:443 -servername your-domain.com </dev/null 2>/dev/null | openssl x509 -text -noout

# Check certificate expiration date
openssl s_client -connect your-domain.com:443 -servername your-domain.com </dev/null 2>/dev/null | openssl x509 -noout -dates

# Check certificate chain
openssl s_client -connect your-domain.com:443 -servername your-domain.com -showcerts </dev/null

# List supported cipher suites
openssl s_client -connect your-domain.com:443 -cipher 'ALL' </dev/null 2>&1 | grep "Cipher is"

# Test a specific cipher suite
openssl s_client -connect your-domain.com:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384' </dev/null

# Check if weak ciphers are accepted (should fail)
openssl s_client -connect your-domain.com:443 -cipher 'RC4' </dev/null
openssl s_client -connect your-domain.com:443 -cipher 'DES' </dev/null
openssl s_client -connect your-domain.com:443 -cipher 'NULL' </dev/null
```

#### testssl.sh (comprehensive TLS scanner)

```bash
# Install testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Full scan
./testssl.sh your-domain.com

# Quick scan (protocols and ciphers only)
./testssl.sh --protocols --ciphers your-domain.com

# Check specific vulnerabilities
./testssl.sh --vulnerable your-domain.com

# Check certificate
./testssl.sh --server-defaults your-domain.com

# Output as JSON for automated processing
./testssl.sh --jsonfile results.json your-domain.com

# Output as CSV
./testssl.sh --csvfile results.csv your-domain.com

# Scan without color (for logging)
./testssl.sh --color 0 your-domain.com
```

#### Nmap SSL scripts

```bash
# Enumerate all supported TLS versions and cipher suites
nmap --script ssl-enum-ciphers -p 443 your-domain.com

# Check for known SSL/TLS vulnerabilities
nmap --script ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443 your-domain.com

# Full SSL audit
nmap --script "ssl-*" -p 443 your-domain.com
```

#### cURL

```bash
# Check TLS version and cipher used in connection
curl -vI https://your-domain.com 2>&1 | grep -E "SSL connection|TLS|cipher|subject|expire"

# Force specific TLS version
curl --tlsv1.2 --tls-max 1.2 -I https://your-domain.com
curl --tlsv1.3 --tls-max 1.3 -I https://your-domain.com

# Check if HTTP redirects to HTTPS
curl -sI http://your-domain.com | grep -i "location"

# Check HSTS header
curl -sI https://your-domain.com | grep -i "strict-transport-security"

# Check certificate details
curl --cert-status -v https://your-domain.com 2>&1 | grep -A5 "Server certificate"
```

#### sslyze (Python-based TLS scanner)

```bash
# Install
pip install sslyze

# Full scan
sslyze your-domain.com

# Check specific items
sslyze --certinfo --tlsv1_2 --tlsv1_3 --heartbleed --openssl_ccs your-domain.com

# Output as JSON
sslyze --json_out results.json your-domain.com
```

### 2.3 Quick TLS Health Check Script

A one-liner bash script to quickly check TLS configuration:

```bash
#!/bin/bash
# tls_check.sh - Quick TLS health check
# Usage: ./tls_check.sh your-domain.com

DOMAIN=$1
PORT=${2:-443}

echo "=== TLS Health Check: $DOMAIN:$PORT ==="
echo ""

# 1. Check certificate expiration
echo "[Certificate Expiration]"
echo | openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" 2>/dev/null | \
  openssl x509 -noout -dates 2>/dev/null || echo "  FAILED to retrieve certificate"
echo ""

# 2. Check TLS versions
echo "[TLS Version Support]"
for version in tls1 tls1_1 tls1_2 tls1_3; do
  result=$(echo | openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" -"$version" 2>&1)
  if echo "$result" | grep -q "CONNECTED" && ! echo "$result" | grep -q "alert"; then
    if [ "$version" = "tls1" ] || [ "$version" = "tls1_1" ]; then
      echo "  $version: ENABLED (INSECURE - should be disabled)"
    else
      echo "  $version: ENABLED (OK)"
    fi
  else
    if [ "$version" = "tls1" ] || [ "$version" = "tls1_1" ]; then
      echo "  $version: DISABLED (GOOD)"
    else
      echo "  $version: DISABLED (WARNING - should be enabled)"
    fi
  fi
done
echo ""

# 3. Check cipher suite (current negotiation)
echo "[Negotiated Cipher]"
echo | openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" 2>/dev/null | \
  grep "Cipher is" || echo "  FAILED"
echo ""

# 4. Check HSTS header
echo "[HSTS Header]"
hsts=$(curl -sI "https://$DOMAIN" 2>/dev/null | grep -i "strict-transport-security")
if [ -n "$hsts" ]; then
  echo "  $hsts"
else
  echo "  NOT SET (should be configured)"
fi
echo ""

# 5. Check HTTP to HTTPS redirect
echo "[HTTP to HTTPS Redirect]"
redirect=$(curl -sI "http://$DOMAIN" 2>/dev/null | grep -i "location")
if echo "$redirect" | grep -qi "https"; then
  echo "  $redirect"
else
  echo "  NO REDIRECT (should redirect to HTTPS)"
fi
echo ""

# 6. Check certificate subject and issuer
echo "[Certificate Info]"
echo | openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" 2>/dev/null | \
  openssl x509 -noout -subject -issuer 2>/dev/null || echo "  FAILED"
echo ""

echo "=== For detailed analysis, use: ==="
echo "  SSL Labs:    https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo "  testssl.sh:  ./testssl.sh $DOMAIN"
```

---

## 3. Nginx TLS Configuration

### 3.1 Recommended TLS Configuration

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # ----- Certificate Paths -----
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # ----- TLS Protocol Versions -----
    # Only TLS 1.2 and 1.3 (disable SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    ssl_protocols TLSv1.2 TLSv1.3;

    # ----- Cipher Suites -----
    # Strong AEAD ciphers with forward secrecy
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;

    # ----- ECDH Curve -----
    ssl_ecdh_curve X25519:secp384r1:secp256r1;

    # ----- Session Caching -----
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;  # Disable for forward secrecy

    # ----- OCSP Stapling -----
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # ----- DH Parameters (for DHE ciphers, optional with ECDHE-only) -----
    # Generate: openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
    # ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    # ----- HSTS -----
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # ... rest of server configuration ...
}

# ----- HTTP to HTTPS Redirect -----
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;

    # Redirect all HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}
```

### 3.2 Generate DH Parameters (if using DHE ciphers)

```bash
# Generate 4096-bit DH parameters (may take several minutes)
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096

# Or use 2048-bit for faster generation (acceptable minimum)
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
```

### 3.3 Verify Nginx TLS Configuration

```bash
# Test configuration syntax
sudo nginx -t

# Check which TLS modules are compiled
nginx -V 2>&1 | grep -o "with-http_ssl_module"
nginx -V 2>&1 | grep -o "with-http_v2_module"

# Check OpenSSL version used by Nginx
nginx -V 2>&1 | grep -o "built with OpenSSL.*"

# Reload after changes
sudo systemctl reload nginx
```

---

## 4. Apache HTTP Server TLS Configuration

### 4.1 Recommended TLS Configuration

```apache
# Enable required modules
# a2enmod ssl headers rewrite

<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html

    # ----- Enable SSL -----
    SSLEngine on

    # ----- Certificate Paths -----
    SSLCertificateFile      /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/example.com/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/example.com/chain.pem

    # ----- TLS Protocol Versions -----
    # Only TLS 1.2 and 1.3
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # ----- Cipher Suites -----
    # TLS 1.3 ciphers (Apache 2.4.43+)
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256

    # TLS 1.2 ciphers
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

    # Server chooses the cipher order
    SSLHonorCipherOrder on

    # ----- Disable SSL Compression (prevents CRIME attack) -----
    SSLCompression off

    # ----- OCSP Stapling -----
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off

    # ----- HSTS -----
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # ... rest of configuration ...
</VirtualHost>

# ----- OCSP Stapling Cache (must be outside VirtualHost) -----
SSLStaplingCache "shmcb:logs/ssl_stapling(128000)"

# ----- HTTP to HTTPS Redirect -----
<VirtualHost *:80>
    ServerName example.com
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>
```

### 4.2 Verify Apache TLS Configuration

```bash
# Check if SSL module is loaded
apachectl -M | grep ssl

# Test configuration syntax
apachectl configtest
# or
apache2ctl -t

# Check Apache and OpenSSL versions
apache2 -v
openssl version

# Check current SSL configuration
apachectl -t -D DUMP_MODULES 2>&1 | grep ssl

# Restart after changes
sudo systemctl restart apache2
# or
sudo systemctl restart httpd
```

---

## 5. Apache Tomcat TLS Configuration

### 5.1 Recommended server.xml Configuration

```xml
<!-- HTTPS Connector with NIO2 protocol (Tomcat 9+) -->
<Connector port="8443"
           protocol="org.apache.coyote.http11.Http11Nio2Protocol"
           maxThreads="200"
           SSLEnabled="true"
           scheme="https"
           secure="true"
           server=" "
           xpoweredBy="false">

    <SSLHostConfig
        protocols="TLSv1.2+TLSv1.3"
        ciphers="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256"
        honorCipherOrder="true"
        certificateVerification="none">

        <!-- Option A: PEM certificate files (Tomcat 9.0.1+) -->
        <Certificate
            certificateFile="conf/certs/fullchain.pem"
            certificateKeyFile="conf/certs/privkey.pem"
            type="RSA" />

        <!-- Option B: Java Keystore -->
        <!--
        <Certificate
            certificateKeystoreFile="conf/keystore.p12"
            certificateKeystorePassword="changeit"
            certificateKeystoreType="PKCS12"
            type="RSA" />
        -->
    </SSLHostConfig>
</Connector>

<!-- Redirect HTTP to HTTPS -->
<Connector port="8080"
           protocol="HTTP/1.1"
           redirectPort="8443"
           server=" "
           xpoweredBy="false" />
```

### 5.2 Create Java Keystore from PEM Files

```bash
# Convert PEM to PKCS12
openssl pkcs12 -export \
  -in fullchain.pem \
  -inkey privkey.pem \
  -out keystore.p12 \
  -name tomcat \
  -password pass:changeit

# Import PKCS12 into Java Keystore (JKS)
keytool -importkeystore \
  -srckeystore keystore.p12 \
  -srcstoretype PKCS12 \
  -srcstorepass changeit \
  -destkeystore keystore.jks \
  -deststoretype JKS \
  -deststorepass changeit

# Verify keystore contents
keytool -list -v -keystore keystore.p12 -storetype PKCS12 -storepass changeit
```

### 5.3 Force HTTPS in web.xml

```xml
<!-- Add to WEB-INF/web.xml -->
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Entire Application</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```

### 5.4 Verify Tomcat TLS Configuration

```bash
# Check Java and Tomcat versions
java -version
$CATALINA_HOME/bin/version.sh

# Test TLS connection to Tomcat
openssl s_client -connect localhost:8443 -servername localhost

# Check supported protocols
openssl s_client -connect localhost:8443 -tls1_2
openssl s_client -connect localhost:8443 -tls1_3

# Check catalina logs for SSL errors
tail -f $CATALINA_HOME/logs/catalina.out | grep -i ssl
```

---

## 6. Node.js (Express) TLS Configuration

### 6.1 HTTPS Server with TLS Configuration

```javascript
const https = require('https');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');

const app = express();

// ----- TLS Options -----
const tlsOptions = {
  // Certificate files
  key: fs.readFileSync('/etc/letsencrypt/live/example.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/example.com/fullchain.pem'),
  ca: fs.readFileSync('/etc/letsencrypt/live/example.com/chain.pem'),

  // Minimum TLS version (TLS 1.2)
  minVersion: 'TLSv1.2',

  // Maximum TLS version (TLS 1.3)
  maxVersion: 'TLSv1.3',

  // Cipher suites for TLS 1.2
  ciphers: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
  ].join(':'),

  // Prefer server cipher order
  honorCipherOrder: true,

  // ECDH curve
  ecdhCurve: 'X25519:P-256:P-384',

  // Disable session tickets for forward secrecy
  // (set to true if performance is more important)
  secureOptions:
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TICKET,
};

// ----- Create HTTPS Server -----
const server = https.createServer(tlsOptions, app);

server.listen(443, () => {
  console.log('HTTPS server running on port 443');
});

// ----- HTTP to HTTPS Redirect -----
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(301, {
    Location: `https://${req.headers.host}${req.url}`,
  });
  res.end();
}).listen(80);
```

### 6.2 Check Node.js TLS Support

```bash
# Check Node.js version (TLS 1.3 requires Node.js 12+)
node -v

# Check OpenSSL version used by Node.js
node -e "console.log(process.versions.openssl)"

# List supported ciphers
node -e "console.log(require('crypto').getCiphers().join('\n'))"

# List supported TLS versions
node -e "console.log(require('tls').DEFAULT_MIN_VERSION, require('tls').DEFAULT_MAX_VERSION)"
```

### 6.3 Reverse Proxy Setup (Recommended for Production)

For production environments, it is recommended to terminate TLS at a reverse proxy (Nginx or Apache) rather than in Node.js directly:

```nginx
# Nginx reverse proxy for Node.js
server {
    listen 443 ssl http2;
    server_name example.com;

    # TLS configuration (see Section 3)
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 7. Certificate Management with Let's Encrypt

### 7.1 Install Certbot

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install certbot

# With Nginx plugin
sudo apt install python3-certbot-nginx

# With Apache plugin
sudo apt install python3-certbot-apache

# CentOS/RHEL
sudo dnf install certbot python3-certbot-nginx
# or
sudo dnf install certbot python3-certbot-apache

# macOS (via Homebrew)
brew install certbot
```

### 7.2 Obtain Certificates

```bash
# ----- Nginx (automatic configuration) -----
sudo certbot --nginx -d example.com -d www.example.com

# ----- Apache (automatic configuration) -----
sudo certbot --apache -d example.com -d www.example.com

# ----- Standalone (for servers not running on port 80/443) -----
sudo certbot certonly --standalone -d example.com -d www.example.com

# ----- Webroot (server already running) -----
sudo certbot certonly --webroot -w /var/www/html -d example.com -d www.example.com

# ----- DNS challenge (for wildcard certificates) -----
sudo certbot certonly --manual --preferred-challenges dns -d "*.example.com" -d example.com

# ----- Dry run (test without actually obtaining cert) -----
sudo certbot certonly --dry-run --nginx -d example.com
```

### 7.3 Certificate Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Force renewal
sudo certbot renew --force-renewal

# Set up auto-renewal (cron)
# This cron job runs twice daily at random minute
echo "0 */12 * * * root certbot renew --quiet --deploy-hook 'systemctl reload nginx'" | \
  sudo tee /etc/cron.d/certbot-renew

# Or use systemd timer (preferred on modern systems)
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Check timer status
sudo systemctl list-timers | grep certbot
```

### 7.4 Certificate Files Location

```
/etc/letsencrypt/live/example.com/
  cert.pem       - Server certificate only
  chain.pem      - Intermediate certificate(s)
  fullchain.pem  - cert.pem + chain.pem (use this for ssl_certificate)
  privkey.pem    - Private key (use this for ssl_certificate_key)
```

### 7.5 Monitor Certificate Expiration

```bash
# Check certificate expiration
sudo certbot certificates

# Check specific domain expiration via OpenSSL
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -dates

# Script to alert on expiring certificates (30-day warning)
#!/bin/bash
DOMAIN="example.com"
DAYS_WARNING=30
EXPIRY=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | \
  openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [ "$DAYS_LEFT" -lt "$DAYS_WARNING" ]; then
  echo "WARNING: Certificate for $DOMAIN expires in $DAYS_LEFT days ($EXPIRY)"
fi
```

### 7.6 Self-Signed Certificates (Testing Only)

```bash
# Generate a self-signed certificate (DO NOT use in production)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/selfsigned.key \
  -out /etc/ssl/certs/selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate with Subject Alternative Names (SAN)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout selfsigned.key \
  -out selfsigned.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"
```

---

## 8. Common TLS Vulnerabilities

### 8.1 Protocol-Level Vulnerabilities

| Vulnerability | Affected | Fix |
|---------------|----------|-----|
| **POODLE** (CVE-2014-3566) | SSLv3 | Disable SSLv3 |
| **BEAST** (CVE-2011-3389) | TLS 1.0 with CBC ciphers | Disable TLS 1.0, use GCM ciphers |
| **CRIME** (CVE-2012-4929) | TLS compression | Disable TLS compression |
| **BREACH** (CVE-2013-3587) | HTTP compression with secrets in response | Disable HTTP compression for sensitive pages, use CSRF tokens |
| **Lucky13** (CVE-2013-0169) | CBC ciphers in TLS | Use AEAD ciphers (GCM, CHACHA20) |
| **Sweet32** (CVE-2016-2183) | 64-bit block ciphers (3DES) | Disable 3DES ciphers |
| **DROWN** (CVE-2016-0800) | SSLv2 | Disable SSLv2 on all servers sharing a certificate |
| **Heartbleed** (CVE-2014-0160) | OpenSSL 1.0.1 to 1.0.1f | Update OpenSSL to 1.0.1g or later |
| **ROBOT** (2017) | RSA key exchange | Disable RSA key exchange, use ECDHE |
| **Raccoon** (CVE-2020-1968) | DH key exchange with TLS 1.2 | Use ECDHE, upgrade to TLS 1.3 |
| **Logjam** (CVE-2015-4000) | Export DHE ciphers, weak DH | Disable export ciphers, use 2048+ bit DH |

### 8.2 Certificate Vulnerabilities

| Issue | Description | Fix |
|-------|-------------|-----|
| **Expired certificate** | Certificate past its validity period | Set up auto-renewal with certbot |
| **Self-signed certificate** | Not trusted by browsers | Use a trusted CA (e.g., Let's Encrypt) |
| **Incomplete chain** | Missing intermediate certificates | Include full certificate chain in config |
| **Wildcard misuse** | Wildcard cert on public-facing subdomains | Use specific certs or limit wildcard scope |
| **Weak key** | RSA key < 2048 bits or ECDSA < 256 bits | Generate new key with RSA 2048+ or ECDSA P-256+ |
| **SHA-1 signature** | Deprecated hash algorithm | Reissue with SHA-256 |
| **Missing SAN** | Only CN, no Subject Alternative Name | Reissue with proper SAN entries |
| **No CAA record** | Any CA can issue certificates for domain | Add DNS CAA records |

### 8.3 How to Verify You Are Not Vulnerable

```bash
# Check for POODLE (SSLv3)
openssl s_client -connect example.com:443 -ssl3 2>&1 | grep -i "alert\|error"
# Expected: handshake failure or error

# Check for BEAST (TLS 1.0)
openssl s_client -connect example.com:443 -tls1 2>&1 | grep -i "alert\|error"
# Expected: handshake failure

# Check for Heartbleed
nmap --script ssl-heartbleed -p 443 example.com
# Expected: "NOT VULNERABLE"

# Check for CRIME (compression)
openssl s_client -connect example.com:443 2>&1 | grep "Compression"
# Expected: "Compression: NONE"

# Check for weak ciphers (RC4, DES, 3DES, NULL)
openssl s_client -connect example.com:443 -cipher 'RC4:DES:3DES:NULL:EXPORT' 2>&1
# Expected: handshake failure

# Check for weak DH (Logjam)
openssl s_client -connect example.com:443 -cipher 'EDH' 2>&1 | grep "Server Temp Key"
# Expected: DH, 2048 bits or higher (or ECDH)

# Check certificate key size
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -noout -text | grep "Public-Key"
# Expected: RSA (2048 bit) or higher

# Check for insecure renegotiation
openssl s_client -connect example.com:443 2>&1 | grep "Secure Renegotiation"
# Expected: "Secure Renegotiation IS supported"
```

---

## 9. Best Practices Checklist

Use this checklist to verify your TLS/HTTPS configuration is secure:

### Protocol & Cipher Configuration

- [ ] Only TLS 1.2 and TLS 1.3 are enabled
- [ ] SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 are disabled
- [ ] Only AEAD cipher suites are used (GCM, CHACHA20-POLY1305)
- [ ] Forward secrecy is enabled (ECDHE key exchange)
- [ ] Server cipher order preference is enabled
- [ ] No RC4, DES, 3DES, NULL, or EXPORT ciphers
- [ ] SSL/TLS compression is disabled

### Certificate Management

- [ ] Certificate is issued by a trusted CA (not self-signed in production)
- [ ] RSA key is at least 2048 bits (4096 recommended) or ECDSA P-256+
- [ ] Certificate uses SHA-256 or stronger signature algorithm
- [ ] Full certificate chain is properly configured
- [ ] Certificate includes correct Subject Alternative Names (SAN)
- [ ] Certificate is not expired and has auto-renewal configured
- [ ] DNS CAA records are configured
- [ ] Certificate Transparency logs are monitored

### HTTPS Enforcement

- [ ] HTTP (port 80) redirects to HTTPS (port 443) with 301
- [ ] HSTS header is set with `max-age=31536000` (1 year minimum)
- [ ] HSTS includes `includeSubDomains` directive
- [ ] HSTS includes `preload` directive (and domain is submitted to preload list)
- [ ] No mixed content (HTTP resources on HTTPS pages)

### OCSP & Revocation

- [ ] OCSP Stapling is enabled
- [ ] OCSP responses are verified
- [ ] Stapling cache is properly configured

### Server Configuration

- [ ] Server version information is hidden
- [ ] Session ticket keys are rotated regularly (or tickets are disabled)
- [ ] DH parameters are at least 2048 bits (if DHE ciphers are used)
- [ ] ECDH curves are properly configured (X25519, P-256, P-384)
- [ ] Session cache timeout is reasonable (1 day or less)

### Monitoring & Maintenance

- [ ] SSL Labs score is A+ (or A minimum)
- [ ] Certificate expiration monitoring is in place
- [ ] TLS configuration is regularly audited
- [ ] OpenSSL/server software is kept up to date
- [ ] Security advisories are monitored for TLS vulnerabilities

---

## 10. Troubleshooting TLS Issues

### Certificate Errors

**"SSL certificate problem: unable to get local issuer certificate"**
- Intermediate certificates are missing from the chain
- Fix: Include `fullchain.pem` instead of just `cert.pem`

```bash
# Check certificate chain
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | grep -A1 "Certificate chain"

# Verify chain completeness
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt fullchain.pem
```

**"SSL certificate has expired"**
```bash
# Check expiration
openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -noout -dates

# Force renewal
sudo certbot renew --force-renewal
sudo systemctl reload nginx  # or apache2
```

**"SSL certificate name mismatch"**
```bash
# Check certificate domains
openssl x509 -in cert.pem -noout -text | grep -A1 "Subject Alternative Name"

# Ensure server_name matches certificate SAN
```

### Protocol & Cipher Issues

**"no protocols available" or "wrong version number"**
- Client and server have no common TLS version
- Check if server supports the expected TLS versions

```bash
# Test each protocol version
for v in tls1 tls1_1 tls1_2 tls1_3; do
  echo -n "$v: "
  openssl s_client -connect example.com:443 -$v </dev/null 2>&1 | grep "Protocol  :"
done
```

**"no ciphers available" or "handshake failure"**
- Client and server have no common cipher suites
- Check configured ciphers match what client supports

```bash
# List server-supported ciphers
nmap --script ssl-enum-ciphers -p 443 example.com
```

### OCSP Stapling Issues

**OCSP stapling not working**
```bash
# Test OCSP stapling
openssl s_client -connect example.com:443 -servername example.com -status </dev/null 2>/dev/null | grep -A3 "OCSP Response"

# If "no response sent", check:
# 1. ssl_stapling is enabled
# 2. ssl_trusted_certificate points to the chain file
# 3. DNS resolver is configured and reachable
# 4. Firewall allows outbound OCSP connections (port 80 to CA)

# For Nginx, test OCSP responder manually
openssl x509 -in cert.pem -noout -ocsp_uri
# Then verify OCSP response
openssl ocsp -issuer chain.pem -cert cert.pem -url <ocsp-uri> -no_nonce
```

### Performance Issues

**Slow TLS handshake**
- Enable session caching to avoid full handshakes on reconnection
- Enable OCSP stapling to avoid client-side OCSP lookups
- Consider enabling TLS session tickets (trade-off with forward secrecy)
- Use ECDHE (faster than DHE) and ECDSA certificates (faster than RSA)

**High CPU usage from TLS**
```bash
# Check if hardware acceleration is available
openssl engine
openssl speed aes-256-gcm

# Consider ECDSA certificates (much faster than RSA for signing)
# RSA 2048: ~1000 signatures/sec
# ECDSA P-256: ~10000+ signatures/sec
```

### Mixed Content Warnings

If browsers show mixed content warnings after enabling HTTPS:

```bash
# Find HTTP references in your HTML/JS/CSS
grep -rn "http://" /var/www/html/ --include="*.html" --include="*.js" --include="*.css" | grep -v "https://"

# Use CSP to automatically upgrade HTTP to HTTPS
# Add this to your CSP: upgrade-insecure-requests
```
