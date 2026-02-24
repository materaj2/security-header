/**
 * AngularJS - Security Headers & Secure Cookie Configuration
 *
 * AngularJS is a client-side framework, so security headers must be set
 * on the server that serves the AngularJS application. This file provides:
 *
 * 1. An Express server configured to serve an AngularJS app with security headers
 * 2. AngularJS client-side security configurations ($http interceptors, CSP mode, etc.)
 *
 * Dependencies:
 *   npm install express helmet cookie-parser
 */

// ===========================================================================
// PART 1: Express Server Configuration for Serving AngularJS Apps
// ===========================================================================

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// Security headers via Helmet
app.use(
  helmet({
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // AngularJS requires 'unsafe-eval' for template compilation in development.
        // In production, use pre-compiled templates (templateCache) to remove this.
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    xContentTypeOptions: true,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    crossOriginEmbedderPolicy: false, // May need to be disabled if loading external resources
    hidePoweredBy: true,
  })
);

// Permissions-Policy
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
  );
  next();
});

// Cache-Control for HTML pages (allow caching for static assets)
app.use((req, res, next) => {
  if (req.path.endsWith('.html') || req.path === '/') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
});

// Secure cookie settings
app.use(cookieParser());

// XSRF/CSRF token endpoint for AngularJS
// AngularJS automatically reads cookies named XSRF-TOKEN and sends them as X-XSRF-TOKEN header
app.use((req, res, next) => {
  if (!req.cookies['XSRF-TOKEN']) {
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('XSRF-TOKEN', token, {
      secure: true,
      httpOnly: false, // Must be readable by AngularJS for CSRF protection
      sameSite: 'strict',
      path: '/',
    });
  }
  next();
});

// Validate XSRF token on state-changing requests
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const cookieToken = req.cookies['XSRF-TOKEN'];
    const headerToken = req.headers['x-xsrf-token'];
    if (!cookieToken || cookieToken !== headerToken) {
      return res.status(403).json({ error: 'CSRF token validation failed' });
    }
  }
  next();
});

// Session cookie configuration
app.use((req, res, next) => {
  // Set a secure session cookie (example)
  if (!req.cookies['__Host-session']) {
    res.cookie('__Host-session', 'session-value-here', {
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 3600000,
      path: '/',
    });
  }
  next();
});

// Serve AngularJS static files
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AngularJS server running on port ${PORT}`);
});


// ===========================================================================
// PART 2: AngularJS Client-Side Security Configuration
// Save this section as a separate file in your AngularJS app (e.g., app-security.js)
// ===========================================================================

/*
// ---------------------------------------------------------------------------
// Enable CSP-compatible mode in AngularJS
// This disables eval()-based template compilation
// ---------------------------------------------------------------------------

// In your index.html, add ng-csp directive:
// <html ng-app="myApp" ng-csp>

// ---------------------------------------------------------------------------
// AngularJS Security Module
// ---------------------------------------------------------------------------

angular.module('appSecurity', [])

  // Configure $http defaults for secure communication
  .config(['$httpProvider', function($httpProvider) {
    // Enable XSRF/CSRF protection (AngularJS does this by default)
    // Customize cookie/header names if your server uses different names
    $httpProvider.defaults.xsrfCookieName = 'XSRF-TOKEN';
    $httpProvider.defaults.xsrfHeaderName = 'X-XSRF-TOKEN';

    // Set default headers
    $httpProvider.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';
    $httpProvider.defaults.headers.common['Accept'] = 'application/json';
  }])

  // HTTP Interceptor for security-related request/response handling
  .factory('securityInterceptor', ['$q', '$window', function($q, $window) {
    return {
      // Add security headers to every outgoing request
      request: function(config) {
        // Ensure credentials are sent with same-origin requests only
        config.withCredentials = false;

        // Add cache-busting for API calls to prevent cached sensitive data
        if (config.url && config.url.indexOf('/api/') !== -1) {
          config.headers['Cache-Control'] = 'no-cache, no-store';
          config.headers['Pragma'] = 'no-cache';
        }

        return config;
      },

      // Handle authentication errors globally
      responseError: function(rejection) {
        if (rejection.status === 401) {
          // Redirect to login on unauthorized response
          $window.location.href = '/login';
        }
        if (rejection.status === 403) {
          // Handle forbidden (e.g., CSRF failure)
          console.error('Access forbidden - possible CSRF issue');
        }
        return $q.reject(rejection);
      }
    };
  }])

  .config(['$httpProvider', function($httpProvider) {
    $httpProvider.interceptors.push('securityInterceptor');
  }])

  // Configure $sce (Strict Contextual Escaping) - whitelist trusted URLs only
  .config(['$sceDelegateProvider', function($sceDelegateProvider) {
    $sceDelegateProvider.trustedResourceUrlList([
      'self', // Allow same-origin resources
      // Add trusted CDN or API domains below:
      // 'https://trusted-cdn.example.com/**'
    ]);

    // Explicitly block everything else
    $sceDelegateProvider.bannedResourceUrlList([
      'http://**', // Block all HTTP resources
    ]);
  }])

  // Sanitize user inputs using $sanitize
  // Requires: angular-sanitize.js
  // Add 'ngSanitize' to your module dependencies
  .directive('secureBindHtml', ['$sanitize', function($sanitize) {
    return {
      restrict: 'A',
      link: function(scope, element, attrs) {
        scope.$watch(attrs.secureBindHtml, function(newVal) {
          if (newVal) {
            element.html($sanitize(newVal));
          }
        });
      }
    };
  }]);

// Add 'appSecurity' to your main module dependencies:
// angular.module('myApp', ['ngSanitize', 'appSecurity']);
*/
