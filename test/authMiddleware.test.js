const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

const MODULE = require.resolve('../src/middleware/authMiddleware');
// Test-only key generated per run; not a real credential.
const TEST_KEY = require('node:crypto').randomBytes(32).toString('hex');

// Load the middleware fresh so it picks up the current AUTH_JWT_SIGNING_KEY.
function loadMiddleware(key) {
  if (key === undefined) delete process.env.AUTH_JWT_SIGNING_KEY;
  else process.env.AUTH_JWT_SIGNING_KEY = key;
  delete require.cache[MODULE];
  return require(MODULE);
}

// Run the middleware with a mock req/res; resolves with what it did.
async function run(middleware, authorization) {
  const req = { headers: authorization === undefined ? {} : { authorization } };
  const result = { status: null, body: null, nextCalled: false };
  const res = {
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
  };
  await middleware(req, res, () => { result.nextCalled = true; });
  result.user = req.user;
  return result;
}

// F-01: the signing key must come from AUTH_JWT_SIGNING_KEY, not source code.
test('F-01: accepts a token signed with the key from AUTH_JWT_SIGNING_KEY', async () => {
  const auth = loadMiddleware(TEST_KEY);
  const token = jwt.sign({ sub: 'user-1' }, TEST_KEY, { algorithm: 'HS256' });
  const r = await run(auth, `Bearer ${token}`);
  assert.strictEqual(r.nextCalled, true);
  assert.strictEqual(r.user.sub, 'user-1');
});

test('F-01: denies every token when AUTH_JWT_SIGNING_KEY is unset or empty', async () => {
  for (const key of [undefined, '']) {
    const auth = loadMiddleware(key);
    const token = jwt.sign({ sub: 'user-1' }, 'any-key', { algorithm: 'HS256' });
    const r = await run(auth, `Bearer ${token}`);
    assert.strictEqual(r.nextCalled, false);
    assert.strictEqual(r.status, 401);
  }
});

// F-02: only the allow-listed algorithm (HS256) may be accepted.
test('F-02: rejects a correctly signed token that uses a non-allow-listed algorithm', async () => {
  const auth = loadMiddleware(TEST_KEY);
  for (const algorithm of ['HS384', 'HS512']) {
    const token = jwt.sign({ sub: 'user-1' }, TEST_KEY, { algorithm });
    const r = await run(auth, `Bearer ${token}`);
    assert.strictEqual(r.nextCalled, false, `${algorithm} must be rejected`);
    assert.strictEqual(r.status, 401);
  }
});

// F-03: verification errors must be handled as a 401 denial, not thrown.
test('F-03: invalid, malformed or missing tokens get 401 without throwing', async () => {
  const auth = loadMiddleware(TEST_KEY);
  const badSig = jwt.sign({ sub: 'user-1' }, 'wrong-key', { algorithm: 'HS256' });
  for (const authorization of [`Bearer ${badSig}`, 'Bearer abc.def.ghi', 'Bearer']) {
    const r = await run(auth, authorization);
    assert.strictEqual(r.nextCalled, false);
    assert.strictEqual(r.status, 401);
    assert.deepStrictEqual(r.body, { error: 'Invalid token' });
  }
});
