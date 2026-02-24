/**
 * Next.js - Security Headers & Secure Cookie Configuration
 *
 * This file contains two parts:
 * 1. next.config.js - Security headers configuration
 * 2. middleware.ts - Cookie security and additional header enforcement
 *
 * Works with Next.js 13+ (App Router and Pages Router)
 */

// ===========================================================================
// PART 1: next.config.js - Add this to your Next.js configuration
// ===========================================================================

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Disable X-Powered-By header
  poweredByHeader: false,

  // Security headers applied to all routes
  async headers() {
    return [
      {
        // Apply to all routes
        source: '/(.*)',
        headers: [
          // Strict-Transport-Security
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
          // Content-Security-Policy
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Next.js requires these in dev; tighten with nonces in production
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: https:",
              "font-src 'self'",
              "connect-src 'self'",
              "media-src 'self'",
              "object-src 'none'",
              "frame-src 'none'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              "upgrade-insecure-requests",
            ].join('; '),
          },
          // X-Content-Type-Options
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          // X-Frame-Options
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          // Referrer-Policy
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          // Permissions-Policy
          {
            key: 'Permissions-Policy',
            value: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
          },
          // X-XSS-Protection (legacy)
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          // Cross-Origin-Opener-Policy
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin',
          },
          // Cross-Origin-Resource-Policy
          {
            key: 'Cross-Origin-Resource-Policy',
            value: 'same-origin',
          },
          // Cross-Origin-Embedder-Policy
          {
            key: 'Cross-Origin-Embedder-Policy',
            value: 'require-corp',
          },
          // Cache-Control for HTML pages
          {
            key: 'Cache-Control',
            value: 'no-store, no-cache, must-revalidate, proxy-revalidate',
          },
        ],
      },
      {
        // Static assets can be cached
        source: '/_next/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;


// ===========================================================================
// PART 2: middleware.ts - Save as middleware.ts in your project root
// ===========================================================================

/*
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // -------------------------------------------------------------------------
  // CSP with Nonce (Production-recommended approach)
  // -------------------------------------------------------------------------
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const cspHeader = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' data: https:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ');

  response.headers.set('Content-Security-Policy', cspHeader);

  // Pass nonce to the page via a custom header (read it in your layout)
  response.headers.set('X-Nonce', nonce);

  // -------------------------------------------------------------------------
  // Secure Cookie Configuration
  // -------------------------------------------------------------------------

  // Example: Set a secure CSRF token cookie
  if (!request.cookies.get('csrf-token')) {
    const csrfToken = crypto.randomUUID();
    response.cookies.set('csrf-token', csrfToken, {
      httpOnly: false,       // Needs to be readable by client for CSRF
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: 3600,          // 1 hour
    });
  }

  // Example: Enforce secure attributes on session cookies
  const sessionCookie = request.cookies.get('next-auth.session-token');
  if (sessionCookie) {
    response.cookies.set('next-auth.session-token', sessionCookie.value, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 86400,         // 24 hours
    });
  }

  return response;
}

// Apply middleware to all routes except static files and API health checks
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
*/


// ===========================================================================
// PART 3: API Route Secure Cookie Example (App Router)
// Save as app/api/auth/login/route.ts
// ===========================================================================

/*
// app/api/auth/login/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST(request: Request) {
  const body = await request.json();

  // ... your authentication logic here ...

  const response = NextResponse.json({ success: true });

  // Set secure session cookie
  const cookieStore = await cookies();
  cookieStore.set('__Host-session', 'your-session-token', {
    httpOnly: true,          // Not accessible via JavaScript
    secure: true,            // HTTPS only
    sameSite: 'strict',      // Strict same-site policy
    path: '/',               // Valid for entire site
    maxAge: 3600,            // 1 hour
  });

  // Set secure refresh token cookie
  cookieStore.set('__Host-refresh', 'your-refresh-token', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 604800,          // 7 days
  });

  return response;
}
*/
