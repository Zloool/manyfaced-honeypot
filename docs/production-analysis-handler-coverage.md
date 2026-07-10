# Production Analysis: Handler Coverage Gaps

**Date:** 2026-05-05  
**Source:** production PostgreSQL database (`honeypot_bears`, all-time) + recent journalctl logs 
**Total recorded bots:** ~17,500+ dialogue entries  

---

## Executive Summary

The honeypot currently has **11 specialized HTTP handlers** covering WordPress, Drupal, phpMyAdmin, cPanel/WHM, Jenkins, Tomcat, WebDAV, Bitrix, and config disclosure. However, production data reveals significant coverage gaps — the vast majority of bot traffic hits paths that fall through to the generic handler.

### Key Finding: 97% of all requests hit the root path `/` (17,033 hits)

This is the single biggest gap. The root path currently triggers only the `GenericHandler`, which serves a "monster page" — but this could be dramatically improved with targeted responses for common root-path probing patterns.

---

## Current Handler Coverage Matrix

| Handler | Domain | Status | Production Hits (top paths) |
|---------|--------|--------|---------------------------|
| WordPress | wordpress | ✅ Active | 1x `/wp-login.php`, 1x `/wp-admin` |
| Drupal | drupal | ✅ Active | Minimal hits |
| phpMyAdmin | phpmyadmin | ✅ Active | No top-50 hits |
| cPanel/WHM | cpanel | ✅ Active | 1x `/whm/`, 1x `/webmail/` |
| Jenkins | jenkins | ✅ Active | No top-50 hits |
| Tomcat | tomcat | ✅ Active | No top-50 hits |
| WebDAV | webdav | ✅ Active | No top-50 hits |
| Bitrix | bitrix | ✅ Active | No top-50 hits |
| Config Disclosure | config_disclosure | ✅ Active | No top-50 hits |
| Generic | generic | ✅ Fallback | **17,033x root path** + all unmatched |

---

## Missing/Incomplete Handler Coverage

### 🔴 CRITICAL: High-Frequency Unhandled Paths

#### 1. Root Path `/` — 17,033 hits (97% of traffic)
**Current:** GenericHandler "monster page"  
**Problem:** Bots hitting root are the largest group but get a generic response. Many will leave without probing deeper.  
**Recommendation:** Create a `RootProbeHandler` that serves different responses based on:
- User-Agent (scanners vs. automated tools)
- Request headers (Accept, Referer)
- Time-based rotation of fake service banners

#### 2. Favicon — 36 hits
**Path:** `/favicon.ico`  
**Current:** Falls to generic handler  
**Recommendation:** Serve a realistic favicon that triggers bot fingerprinting (some scanners check for specific favicon hashes).

#### 3. Login Paths — 8x `/login`, 4x `/j_spring_security_check`
**Paths:** `/login`, `/j_spring_security_check`, `/user/register`, `/user/`  
**Current:** Falls to generic handler  
**Recommendation:** Create a `SpringSecurityHandler` or extend existing handlers with Spring Security login page emulation. The `/j_spring_security_check` path is specifically from Spring Security applications — this is a distinct attack pattern worth capturing separately.

### 🟡 HIGH: Medium-Frequency Unhandled Paths (2-5 hits each)

#### 4. Environment Files — 4x `/.env`
**Path:** `/.env`  
**Current:** Falls to generic handler  
**Recommendation:** Add to ConfigDisclosureHandler or create dedicated `.env` response with fake database credentials, API keys, and secrets. This is a very common scanner target.

#### 5. Sitemap — 3x `/sitemap.xml`
**Path:** `/sitemap.xml`  
**Current:** Falls to generic handler  
**Recommendation:** Serve a realistic sitemap.xml that lists fake pages across all registered handlers (WordPress posts, phpMyAdmin paths, Jenkins jobs, etc.). This encourages deeper probing.

#### 6. API Endpoints — 3x each: `/api/route`, `/api`
**Paths:** `/api`, `/api/route`, `/v2/api-docs`, `/v3/api-docs`, `/swagger/v1/swagger.json`, `/swagger-ui.html`, `/swagger/index.html`, `/swagger.json`  
**Current:** Falls to generic handler  
**Recommendation:** Create an `APIHandler` that serves:
- Fake OpenAPI/Swagger specs with endpoints pointing to other handlers
- API versioning responses (`/v2/api-docs`, `/v3/api-docs`)
- GraphQL endpoint emulation (`/graphql`)

#### 7. Next.js Paths — 3x each: `/_next/server`, `/_next`
**Paths:** `/_next`, `/_next/server`  
**Current:** Falls to generic handler  
**Recommendation:** Create a `NextJSHandler` that serves realistic Next.js responses including:
- `_next/static/` asset paths
- API routes (`/_next/api/...`)
- Page router paths

#### 8. WebSocket/SSE — 2x each: `/sse`, `/mcp`
**Paths:** `/sse`, `/mcp`  
**Current:** Falls to generic handler (HTTP only, no WS support)  
**Recommendation:** These are emerging attack vectors. Even HTTP-level responses with appropriate headers (`Upgrade: websocket`) would capture more bot behavior.

#### 9. App Root — 2x `/app`
**Path:** `/app`  
**Current:** Falls to generic handler  
**Recommendation:** Could be handled by GenericHandler with a specific response, or added as a path pattern in an existing handler.

#### 10. SDK Endpoints — 2x `/SDK/webLanguage`
**Path:** `/SDK/webLanguage`  
**Current:** Falls to generic handler  
**Recommendation:** Common in Java/Spring applications. Could be part of a `SpringHandler`.

#### 11. Security.txt — 2x `/.well-known/security.txt`, 1x `/security.txt`
**Paths:** `/.well-known/security.txt`, `/security.txt`  
**Current:** Falls to generic handler  
**Recommendation:** Serve a realistic security.txt with contact email, PGP key, and preferred-encryption fields. This is increasingly common in scanner activity.

#### 12. Git Config — 2x `/.git/config`
**Path:** `/.git/config` (not just `/.git`)  
**Current:** Falls to generic handler  
**Recommendation:** Add to ConfigDisclosureHandler. Serve a realistic `.git/config` with remote URLs and credentials.

#### 13. Path Traversal — 2x URL-encoded variants
**Path:** `/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`  
**Current:** Falls to generic handler  
**Recommendation:** Already partially handled by GenericHandler's path traversal detection, but could be more specific with realistic `/etc/passwd` content.

### 🟠 MEDIUM: Single-Hit Patterns Worth Capturing

#### 14. PHP Eval RCE — Multiple paths
**Paths:** `/*/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (15+ variants)  
**Current:** Falls to generic handler  
**Recommendation:** This is a known phpunit RCE exploit pattern. Create an `EvalStdinHandler` that serves realistic PHP error pages with stack traces, encouraging further exploitation attempts.

#### 15. Swagger/OpenAPI — Multiple paths
**Paths:** `/swagger/v1/swagger.json`, `/swagger-ui.html`, `/swagger/index.html`, `/swagger.json`, `/swagger-ui.html`  
**Current:** Falls to generic handler (see #6 API Endpoints)  
**Recommendation:** Part of the APIHandler recommendation above.

#### 16. Docker Registry — 1x `/v2/_catalog`
**Path:** `/v2/_catalog`  
**Current:** Falls to generic handler  
**Recommendation:** Create a `DockerRegistryHandler` that serves fake registry responses with image listings, encouraging push/pull attempts.

#### 17. Wiki — 1x `/wiki`
**Path:** `/wiki`  
**Current:** Falls to generic handler  
**Recommendation:** Could be part of a general CMS handler or a dedicated Confluence/MediaWiki handler.

#### 18. Server Status — 1x `/server-status`, 1x `/server`
**Paths:** `/server-status`, `/server`  
**Current:** Falls to generic handler  
**Recommendation:** Apache/Nginx server-status pages are common scanner targets. Serve fake status pages with active connections, request counts, etc.

#### 19. ThinkPHP RCE — 1x complex path
**Path:** `/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`  
**Current:** Falls to generic handler  
**Recommendation:** Create a `ThinkPHPHandler` that emulates ThinkPHP's routing and serves realistic RCE responses.

---

## Priority Recommendations

### Phase 1: Quick Wins (High Impact, Low Effort)
1. **Root path enhancement** — Add specific root-path responses in GenericHandler based on User-Agent patterns
2. **ConfigDisclosure expansion** — Add `/.env`, `/.git/config`, `/security.txt` to existing handler
3. **Favicon response** — Serve a realistic favicon.ico that triggers bot fingerprinting

### Phase 2: New Handlers (Medium Effort)
4. **APIHandler** — Handle `/api/*`, `/v*/api-docs`, Swagger paths, OpenAPI specs
5. **SpringSecurityHandler** — Handle `/j_spring_security_check`, `/login`, Spring-specific patterns
6. **NextJSHandler** — Handle `/_next/*` paths with realistic Next.js responses
7. **EvalStdinHandler** — Handle the phpunit eval-stdin.php RCE pattern

### Phase 3: Advanced (Higher Effort)
8. **DockerRegistryHandler** — Handle `/v2/_catalog` and Docker registry API
9. **ThinkPHPHandler** — Handle ThinkPHP routing and RCE patterns
10. **WebSocket/SSE support** — Upgrade http_handler to handle WebSocket upgrades for `/sse`, `/mcp`

---

## Data Quality Notes

- The `46.166.165.71:805` entry (29 hits) appears to be a malformed path from the client honeypot's own reporting — this is likely an internal artifact, not a real bot request.
- Most single-hit paths are from automated scanners that probe many paths quickly and move on. Capturing these with realistic responses could increase dwell time and data quality.
- The root path dominance (97%) suggests bots are using broad-spectrum scanners that hit `/` first before probing specific paths.

---

## Metrics to Track Post-Implementation

1. **Root path response diversity** — Are different User-Agents getting different responses?
2. **Dwell time improvement** — Do bots stay longer when they encounter realistic responses for their probe paths?
3. **Handler match rate** — What percentage of requests hit a specialized handler vs. generic fallback?
4. **New path discovery** — Are new bot patterns emerging that need additional handlers?
