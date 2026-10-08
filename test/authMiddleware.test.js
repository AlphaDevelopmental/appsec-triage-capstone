const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const jwt = require('jsonwebtoken');
const express = require('express');

const MODULE_PATH = path.join(__dirname, '..', 'src', 'middleware', 'authMiddleware.js');

// Generated per run so no signing key literal is committed.
const SIGNING_KEY = crypto.randomBytes(32).toString('hex');
process.env.AUTH_JWT_SIGNING_KEY = SIGNING_KEY;
const authMiddleware = require(MODULE_PATH);

let server;
let url;

before(async () => {
  const app = express();
  app.get('/protected', authMiddleware, (req, res) => res.json({ user: req.user }));
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  url = `http://127.0.0.1:${server.address().port}/protected`;
});

after(() => server.close());

function request(authorization) {
  return fetch(url, { headers: authorization ? { authorization } : {} });
}

async function assertDenied(authorization) {
  const res = await request(authorization);
  const body = await res.text();
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(body), { error: 'Invalid token' });
  assert.doesNotMatch(body, /JsonWebTokenError|authMiddleware\.js|node_modules|\n\s+at /);
}

// F-01: hardcoded JWT signing secret
test('F-01: source contains no hardcoded JWT signing secret', () => {
  const src = fs.readFileSync(MODULE_PATH, 'utf8');
  assert.doesNotMatch(src, /JWT_SECRET\s*=\s*['"`]/);
  assert.match(src, /process\.env\.AUTH_JWT_SIGNING_KEY/);
});

test('F-01: module refuses to load without AUTH_JWT_SIGNING_KEY (no fallback secret)', () => {
  const env = { ...process.env };
  delete env.AUTH_JWT_SIGNING_KEY;
  const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(MODULE_PATH)})`], { env });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr.toString(), /AUTH_JWT_SIGNING_KEY is not set/);
});

test('F-01: token signed with a key other than the configured one is rejected', async () => {
  const token = jwt.sign({ sub: 'attacker' }, crypto.randomBytes(32).toString('hex'), { algorithm: 'HS256' });
  await assertDenied(`Bearer ${token}`);
});

test('valid HS256 token signed with the configured key is accepted', async () => {
  const token = jwt.sign({ sub: 'user-1' }, SIGNING_KEY, { algorithm: 'HS256' });
  const res = await request(`Bearer ${token}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.user.sub, 'user-1');
});

// F-02: missing algorithm allowlist
for (const algorithm of ['HS384', 'HS512']) {
  test(`F-02: ${algorithm} token is rejected by the HS256 allowlist`, async () => {
    const token = jwt.sign({ sub: 'user-1' }, SIGNING_KEY, { algorithm });
    await assertDenied(`Bearer ${token}`);
  });
}

test('F-02: unsigned alg=none token is rejected', async () => {
  const token = jwt.sign({ sub: 'admin' }, null, { algorithm: 'none' });
  await assertDenied(`Bearer ${token}`);
});

test('F-02: verify is called with an explicit algorithms allowlist', () => {
  const src = fs.readFileSync(MODULE_PATH, 'utf8');
  assert.match(src, /jwt\.verify\([^)]*algorithms:\s*\[\s*'HS256'\s*\]/);
});

// F-03: verification errors escape to the default error handler (500 + stack trace)
test('F-03: malformed token returns 401 without stack trace', async () => {
  await assertDenied('Bearer garbage');
});

test('F-03: scheme without token returns 401 without stack trace', async () => {
  await assertDenied('Bearer');
});

test('F-03: expired token returns 401 without stack trace', async () => {
  const token = jwt.sign({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) - 60 }, SIGNING_KEY, { algorithm: 'HS256' });
  await assertDenied(`Bearer ${token}`);
});

test('missing Authorization header still returns 401 No token', async () => {
  const res = await request();
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'No token' });
});
