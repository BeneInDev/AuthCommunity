const { test } = require('node:test');
const assert = require('node:assert/strict');
const registerRoutes = require('../src/web/server');
const { createVerifiedUsersRepository } = require('../src/database/verified-users');
const { createAuthUsersStore } = require('../src/database/supabase');

const user = { id: '123456789012345678', username: 'tester', avatar: null, email: 'private@example.invalid' };
const secrets = ['private-access', 'private-refresh', user.email, '192.0.2.1', 'private-device', 'private-secret', 'private-code'];
const unsafeError = () => Object.assign(new Error(secrets.join(' ')), { response: { data: secrets } });

function fixture(t, { failAt, status = 200, roleFails = false, logFails = false, configured = true } = {}) {
    for (const [key, value] of Object.entries({ GUILD_ID: 'test-guild', ROLE_ID: 'test-role', LOG_CHANNEL_ID: 'test-channel', REDIRECT_URI: 'https://example.test/oauth2/callback', CLIENT_ID: '123', CLIENT_SECRET: 'x'.repeat(32), OAUTH_STATE_SECRET: '' })) {
        const previous = process.env[key];
        process.env[key] = value;
        t.after(() => { if (previous === undefined) delete process.env[key]; else process.env[key] = previous; });
    }
    const logs = [];
    t.mock.method(console, 'error', (...args) => logs.push(args));
    t.mock.method(console, 'log', (...args) => logs.push(args));
    const calls = [];
    const routes = {};
    const rendered = [];
    const redirects = [];
    const webhookMessages = [];
    const records = new Map();
    const persistentUsers = createAuthUsersStore({
        env: configured ? { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'private-secret' } : {},
        fetch: async () => {
            calls.push('supabase');
            if (failAt === 'supabase') throw unsafeError();
            return new Response(JSON.stringify(status === 200 ? { discord_id: user.id } : { message: secrets.join(' ') }),
                { status, headers: { 'Content-Type': 'application/json' } });
        }
    });
    const users = { set: (id, record) => {
        calls.push('json');
        if (failAt === 'json') throw unsafeError();
        records.set(id, record);
    } };
    const guild = { name: 'Test server', icon: null, members: { fetch: async id => {
        assert.equal(id, user.id);
        return { roles: { add: async role => {
            calls.push('role'); assert.equal(role, 'test-role'); if (roleFails) throw unsafeError();
        } } };
    } } };
    const webhook = { name: 'OAuth2', send: async data => {
        calls.push('webhook'); if (logFails) throw unsafeError(); webhookMessages.push(data);
    } };
    const client = {
        guilds: { cache: new Map([['test-guild', guild]]) },
        channels: { cache: new Map([['test-channel', { fetchWebhooks: async () => [webhook] }]]) }
    };
    registerRoutes({ get: (path, handler) => { routes[path] = handler; } }, client, {
        database: { users, config: { get: () => undefined } },
        verifiedUsers: createVerifiedUsersRepository({ legacyUsers: users, persistentUsers }),
        http: {
            post: async (_url, _body, options) => {
                assert.equal(options.timeout, 10000);
                assert.equal(options.maxRedirects, 0);
                assert.ok(options.signal instanceof AbortSignal);
                calls.push('token'); if (failAt === 'token') throw unsafeError();
                return { data: { access_token: secrets[0], refresh_token: secrets[1], token_type: 'Bearer' } };
            },
            get: async (_url, options) => { assert.equal(options.timeout, 10000); calls.push('profile'); if (failAt === 'profile') throw unsafeError(); return { data: user }; }
        }
    });
    const req = { query: { code: 'private-code' }, headers: { 'x-forwarded-for': '192.0.2.1', 'user-agent': 'private-device' }, socket: {} };
    const res = { set: () => {}, cookie: (name, value) => { req.headers.cookie = `${name}=${value}`; }, clearCookie: () => {}, redirect: url => redirects.push(url), render: (view, data) => rendered.push({ view, data }) };
    routes['/oauth2/start'](req, res);
    req.query.state = new URL(redirects.pop()).searchParams.get('state');
    function assertPrivate() {
        const output = JSON.stringify({ logs, rendered, redirects, webhookMessages });
        for (const secret of secrets) assert.equal(output.includes(secret), false, 'Private value leaked');
    }
    return { run: () => routes['/oauth2/callback'](req, res), req, res, routes, calls, rendered, redirects, records, assertPrivate };
}

test('successful OAuth preserves JSON, role and success page only after Supabase confirms', async t => {
    const f = fixture(t);
    await f.run();
    assert.deepEqual(f.calls, ['token', 'profile', 'supabase', 'json', 'role', 'webhook']);
    assert.equal(f.rendered[0].view, 'success.html');
    assert.equal(f.rendered[0].data.userId, user.id);
    assert.equal(f.records.get(user.id).access_token, secrets[0]);
    assert.equal(f.records.get(user.id).refresh_token, secrets[1]);
    assert.equal(f.records.get(user.id).email, user.email);
    assert.equal(f.records.get(user.id).ip, '192.0.2.1');
    f.assertPrivate();
});

for (const failAt of ['token', 'profile', 'supabase', 'json']) {
    test(`${failAt} failure never confirms verification or leaks provider errors`, async t => {
        const f = fixture(t, { failAt });
        await f.run();
        assert.deepEqual(f.redirects, ['/error']);
        assert.equal(f.rendered.length, 0);
        assert.equal(f.calls.includes('role'), false);
        assert.equal(f.calls.includes('webhook'), false);
        assert.equal(f.records.size, 0);
        f.assertPrivate();
    });
}

test('Supabase authorization rejection does not fall back to JSON success', async t => {
    const f = fixture(t, { status: 403 });
    await f.run();
    assert.deepEqual(f.redirects, ['/error']);
    assert.equal(f.calls.includes('json'), false);
    f.assertPrivate();
});

test('missing configuration leaves routes available but blocks verification success', async t => {
    const f = fixture(t, { configured: false });
    await f.run();
    assert.deepEqual(f.redirects, ['/error']);
    assert.equal(f.calls.includes('json'), false);
    f.assertPrivate();
});

test('role and webhook failures are safe and do not undo confirmed persistence', async t => {
    const f = fixture(t, { roleFails: true, logFails: true });
    await f.run();
    assert.equal(f.records.size, 1);
    assert.equal(f.rendered[0].view, 'success.html');
    f.assertPrivate();
});

test('missing or malformed OAuth code cannot start a verification', async t => {
    const f = fixture(t);
    for (const code of [undefined, '', ' ', ['private-code']]) {
        f.req.query.code = code;
        await f.run();
    }
    assert.equal(f.redirects.length, 4);
    assert.equal(f.calls.length, 0);
    f.assertPrivate();
});

test('public error page ignores arbitrary query content and private values', t => {
    const f = fixture(t);
    f.routes['/error']({ query: { msg: `<script>${secrets.join(' ')}</script>` } }, f.res);
    assert.equal(f.rendered[0].view, 'error.html');
    assert.equal(f.rendered[0].data.error.includes('<script>'), false);
    f.assertPrivate();
});

for (const variant of ['missing', 'tampered', 'array', 'other-browser']) {
    test(`OAuth callback rejects ${variant} state before any external request`, async t => {
        const f = fixture(t);
        if (variant === 'missing') delete f.req.query.state;
        if (variant === 'tampered') f.req.query.state = f.req.query.state.slice(0, -1) + '!';
        if (variant === 'array') f.req.query.state = [f.req.query.state];
        if (variant === 'other-browser') delete f.req.headers.cookie;
        await f.run();
        assert.deepEqual(f.calls, []);
        assert.deepEqual(f.redirects, ['/error']);
        f.assertPrivate();
    });
}
