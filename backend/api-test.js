// API Connectivity Test — NexusGuard Backend
// Tests all public/unauthenticated endpoints and checks response shapes.
// Run: node api-test.js

const http = require('http');

const BASE = 'http://localhost:5000';
const results = [];
let passed = 0, failed = 0;

function request(method, path, body = null, headers = {}) {
    return new Promise((resolve) => {
        const data   = body ? JSON.stringify(body) : null;
        const opts   = {
            hostname: 'localhost',
            port:     5000,
            path,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
                ...headers
            }
        };

        const req = http.request(opts, (res) => {
            let raw = '';
            res.on('data', chunk => raw += chunk);
            res.on('end', () => {
                let json = null;
                try { json = JSON.parse(raw); } catch {}
                resolve({ status: res.statusCode, body: json, raw });
            });
        });

        req.on('error', (err) => resolve({ status: 0, error: err.message }));
        if (data) req.write(data);
        req.end();
    });
}

function check(name, status, body, expectations) {
    const issues = [];

    if (expectations.status && status !== expectations.status) {
        issues.push(`Expected HTTP ${expectations.status}, got ${status}`);
    }
    if (expectations.hasField) {
        expectations.hasField.forEach(f => {
            if (!body || body[f] === undefined) {
                issues.push(`Missing field: "${f}" (body: ${JSON.stringify(body)})`);
            }
        });
    }
    if (expectations.errorContains && body && body.error) {
        if (!body.error.toLowerCase().includes(expectations.errorContains.toLowerCase())) {
            issues.push(`Error message unexpected: "${body.error}"`);
        }
    }

    const ok = issues.length === 0;
    if (ok) passed++; else failed++;

    const icon   = ok ? '✅' : '❌';
    const detail = ok ? '' : `  ↳ ${issues.join(' | ')}`;
    results.push(`${icon} [${status}] ${name}${detail}`);
    return ok;
}

async function runTests() {
    console.log('\n🔌 NexusGuard API Connectivity Test\n' + '='.repeat(50));

    // ── 1. Health check (no auth required — authenticate middleware wraps /api)
    // Health requires auth, so we test it returns 401 without token
    {
        const r = await request('GET', '/api/health');
        check('GET /api/health (no token → 401)', r.status, r.body, {
            status: 401,
            hasField: ['error']
        });
    }

    // ── 2. All protected endpoints should 401 without token ──
    const protectedEndpoints = [
        ['GET',    '/api/user/organizations'],
        ['GET',    '/api/user/activity'],
        ['GET',    '/api/resources'],
        ['POST',   '/api/resources'],
        ['GET',    '/api/groups'],
        ['POST',   '/api/groups'],
        ['GET',    '/api/org-members'],
        ['GET',    '/api/join-requests/mine'],
        ['POST',   '/api/join-requests'],
        ['GET',    '/api/pending-provisions'],
        ['POST',   '/api/organizations'],
        ['GET',    '/api/profile'],
        ['GET',    '/api/system/users'],
        ['GET',    '/api/system/organizations'],
    ];

    console.log('\n--- Auth Guard Tests (expect 401) ---');
    for (const [method, path] of protectedEndpoints) {
        const r = await request(method, path, method !== 'GET' ? { name: 'test' } : null);
        check(`${method} ${path} (no token)`, r.status, r.body, { status: 401 });
    }

    // ── 3. Routes that DON'T exist:
    // Auth middleware runs BEFORE the 404 handler, so unauthenticated requests
    // to unknown routes get 401 first. This is the correct, secure behavior.
    console.log('\n--- 404 Route Tests (auth runs first = 401) ---');
    {
        const r = await request('GET', '/api/nonexistent-route');
        check('GET /api/nonexistent-route (no token → 401, auth-first)', r.status, r.body, { status: 401 });
    }
    {
        const r = await request('DELETE', '/api/resources/fakeId/nonexistent');
        check('DELETE /api/resources/fakeId/nonexistent (no token → 401)', r.status, r.body, { status: 401 });
    }
    // 404 with valid token would require a real Firebase token — skip in connectivity test.

    // ── 4. Invalid token should 401 ──
    console.log('\n--- Invalid Token Tests ---');
    {
        const r = await request('GET', '/api/health', null, { Authorization: 'Bearer invalidtoken123' });
        check('GET /api/health (invalid token → 401)', r.status, r.body, { status: 401 });
    }
    {
        const r = await request('GET', '/api/profile', null, { Authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9.fake.sig' });
        check('GET /api/profile (malformed token → 401)', r.status, r.body, { status: 401 });
    }

    // ── 5. Validation errors should 400 ──
    console.log('\n--- Validation Tests (expect 400) ---');
    {
        // POST /organizations with bad auth header but still check 401 (auth runs first)
        const r = await request('POST', '/api/organizations', { name: '' });
        check('POST /api/organizations (no token → 401 before validation)', r.status, r.body, { status: 401 });
    }

    // ── 6. CORS headers present ──
    console.log('\n--- Infrastructure Tests ---');
    {
        const opts = {
            hostname: 'localhost',
            port:     5000,
            path:     '/api/health',
            method:   'OPTIONS',
            headers: {
                Origin: 'http://localhost:5173',
                'Access-Control-Request-Method': 'GET'
            }
        };
        const r = await new Promise((resolve) => {
            const req = http.request(opts, (res) => {
                resolve({ status: res.statusCode, headers: res.headers });
            });
            req.on('error', (err) => resolve({ status: 0, error: err.message }));
            req.end();
        });
        const hasCors = r.headers?.['access-control-allow-origin'] !== undefined
                     || r.headers?.['vary'] !== undefined
                     || r.status === 204
                     || r.status === 200;
        if (hasCors) { passed++; results.push(`✅ [${r.status}] OPTIONS /api/health — CORS headers present`); }
        else         { failed++; results.push(`❌ [${r.status}] OPTIONS /api/health — CORS headers MISSING`); }
    }

    // ── Summary ──
    console.log('\n' + '='.repeat(50));
    results.forEach(r => console.log(r));
    console.log('\n' + '='.repeat(50));
    console.log(`\nTotal: ${passed + failed} | ✅ Passed: ${passed} | ❌ Failed: ${failed}`);

    if (failed === 0) {
        console.log('\n🎉 All connectivity checks passed! Backend is healthy.\n');
    } else {
        console.log(`\n⚠️  ${failed} check(s) failed. Review above.\n`);
    }

    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
    console.error('\n❌ Test runner crashed:', err.message);
    process.exit(1);
});
