/**
 * Node.js (Express) - Security Headers & Secure Cookie Configuration
 *
 * This configuration uses the 'helmet' middleware for security headers
 * and demonstrates secure cookie settings for Express applications.
 *
 * Dependencies:
 *   npm install express helmet cookie-parser express-session
 */

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// ---------------------------------------------------------------------------
// 1. Security Headers via Helmet
// ---------------------------------------------------------------------------
app.use(
  helmet({
    // Strict-Transport-Security
    // Forces HTTPS for 1 year, includes subdomains, allows preload list
    strictTransportSecurity: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },

    // Content-Security-Policy
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Adjust if using inline styles
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        childSrc: ["'none'"],
        workerSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },

    // X-Content-Type-Options: nosniff
    xContentTypeOptions: true,

    // X-Frame-Options: DENY
    frameguard: { action: 'deny' },

    // Referrer-Policy
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

    // X-XSS-Protection (legacy, but still useful for older browsers)
    xXssProtection: true,

    // Cross-Origin-Opener-Policy
    crossOriginOpenerPolicy: { policy: 'same-origin' },

    // Cross-Origin-Resource-Policy
    crossOriginResourcePolicy: { policy: 'same-origin' },

    // Cross-Origin-Embedder-Policy
    crossOriginEmbedderPolicy: { policy: 'require-corp' },

    // Remove X-Powered-By header
    hidePoweredBy: true,

    // X-DNS-Prefetch-Control
    dnsPrefetchControl: { allow: false },

    // X-Download-Options (IE-specific)
    ieNoOpen: true,

    // X-Permitted-Cross-Domain-Policies
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  })
);

// ---------------------------------------------------------------------------
// 2. Permissions-Policy Header (not covered by helmet by default)
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
  );
  next();
});

// ---------------------------------------------------------------------------
// 3. Cache-Control for sensitive pages
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

// ---------------------------------------------------------------------------
// 4. Secure Cookie Configuration
// ---------------------------------------------------------------------------

// 4a. Cookie Parser with signed cookies
app.use(cookieParser(process.env.COOKIE_SECRET || 'change-this-secret-in-production'));

// 4b. Session configuration with secure cookies
app.use(
  session({
    name: '__Host-session', // __Host- prefix enforces Secure + Path=/ + no Domain
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,         // Only sent over HTTPS
      httpOnly: true,        // Not accessible via JavaScript
      sameSite: 'strict',    // Strict same-site enforcement
      maxAge: 3600000,       // 1 hour in milliseconds
      path: '/',             // Cookie valid for entire site
      // domain is intentionally omitted for __Host- prefix cookies
    },
  })
);

// 4c. Example: Setting a secure cookie manually
app.get('/set-preference', (req, res) => {
  res.cookie('user_preference', 'dark_mode', {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 86400000, // 24 hours
    path: '/',
    signed: true,
  });
  res.send('Preference saved');
});

// ---------------------------------------------------------------------------
// 5. Example route
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Node.js server with security headers enabled');
});

// ---------------------------------------------------------------------------
// 6. Start server
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
