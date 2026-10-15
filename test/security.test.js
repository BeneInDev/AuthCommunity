const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createOAuthState, verificationUrl, TTL_MS } = require('../src/web/oauth-state');
const { renderHtml } = require('../src/web/html');
const { requireOwner } = require('../src/security/authorization');
const { externalRequestOptions } = require('../src/http-options');
const axios = require('axios');
const http = require('node:http');

const env = { REDIRECT_URI: 'https://example.test/oauth2/callback', CLIENT_ID: '123', CLIENT_SECRET: 'x'.repeat(32) };
function browser() {
    const jar = new Map();
    return { jar, response: { cookie: (name, value, options) => jar.set(name, { value, options }), clearCookie: name => jar.delete(name) },
        request: state => ({ query: { state }, headers: { cookie: [...jar].map(([name, c]) => `${name}=${c.value}`).join('; '), 'x-forwarded-proto': 'http' } }) };
}

test('state binds the browser and expires; works across instances behind TLS termination', () => {
    let now = 1800000000000;
    const a = createOAuthState({ env, now: () => now });
    const b = createOAuthState({ env: { ...env }, now: () => now });
    const first = browser();
    const state = new URL(a.start(first.response)).searchParams.get('state');
    const cookie = first.jar.get('__Host-authcommunity-oauth');
    assert.deepEqual(cookie.options, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: TTL_MS });
    const other = browser(); a.start(other.response);
    assert.equal(b.consume(other.request(state), other.response), false);
    assert.equal(b.consume(first.request(state), first.response), true);
    assert.equal(first.jar.size, 0);
    assert.equal(b.consume(first.request(state), first.response), false);
    const expired = new URL(a.start(first.response)).searchParams.get('state');
    now += TTL_MS;
    assert.equal(b.consume(first.request(expired), first.response), false);
});

test('state rejects changed signature, cookie, expiry, redirect origin and duplicate cookies', () => {
    const a = createOAuthState({ env });
    for (const variant of ['signature', 'cookie', 'expiry', 'origin', 'duplicate']) {
        const b = browser();
        let state = new URL(a.start(b.response)).searchParams.get('state');
        const req = b.request(state);
        if (variant === 'signature') req.query.state = state.slice(0, -1) + '!';
        if (variant === 'cookie') req.headers.cookie = '__Host-authcommunity-oauth=' + 'z'.repeat(43);
        if (variant === 'expiry') req.query.state = '9999999999999' + state.slice(13);
        if (variant === 'duplicate') req.headers.cookie += '; ' + req.headers.cookie;
        const validator = variant === 'origin' ? createOAuthState({ env: { ...env, REDIRECT_URI: 'https://other.test/oauth2/callback' } }) : a;
        assert.equal(validator.consume(req, b.response), false);
    }
});

test('OAuth configuration rejects insecure public URLs and weak signing keys', () => {
    assert.equal(verificationUrl(env), 'https://example.test/oauth2/start');
    assert.throws(() => verificationUrl({ REDIRECT_URI: 'http://example.test/oauth2/callback' }));
    assert.throws(() => createOAuthState({ env: { ...env, CLIENT_SECRET: '' } }).start(browser().response));
    const b = browser();
    createOAuthState({ env: { ...env, REDIRECT_URI: 'http://localhost:3000/oauth2/callback' } }).start(b.response);
    assert.equal(b.jar.get('authcommunity-oauth').options.secure, false);
});

test('HTML escapes text and attributes once and prevents template replacement injection', () => {
    const html = renderHtml('<p><%= userName %></p><img alt="<%= guildName %>">', {
        userName: '<script>alert(1)</script>$&<%= guildName %>', guildName: '" onerror="alert(1)\'&'
    });
    assert.equal(html.includes('<script>'), false);
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /&quot; onerror=&quot;/);
    assert.match(html, /&#39;&amp;/);
    assert.match(html, /\$&amp;&lt;%= guildName %&gt;/);
});

test('URL attributes reject unsafe schemes, origins and path injection', () => {
    for (const url of ['javascript:alert(1)', 'https://evil.test/x', 'https://discord.com/channels/1\'onclick=evil', 'https://discord.com@evil.test/channels/1']) {
        assert.equal(renderHtml('<a href="<%= guildUrl %>">', { guildUrl: url }), '<a href="">');
    }
    assert.equal(renderHtml('<a href="<%= guildUrl %>">', { guildUrl: 'https://discord.com/channels/123' }), '<a href="https://discord.com/channels/123">');
    assert.equal(renderHtml('<img src="<%= userAvatar %>">', { userAvatar: 'data:text/html,evil' }), '<img src="">');
});

test('owner authorization fails closed when owner is not configured', async () => {
    let denied = 0;
    const interaction = { user: { id: 'owner' }, reply: async () => denied++ };
    assert.equal(await requireOwner(interaction, ''), false);
    assert.equal(await requireOwner(interaction, 'other'), false);
    assert.equal(await requireOwner(interaction, 'owner'), true);
    assert.equal(denied, 2);
});

test('Axios aborts an unresponsive HTTP request without credentials or external network', async t => {
    const server = http.createServer(() => {});
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    await assert.rejects(axios.get(`http://127.0.0.1:${server.address().port}`, {
        ...externalRequestOptions(50), proxy: false
    }), error => ['ERR_CANCELED', 'ECONNABORTED'].includes(error.code));
});

test('proxy-from-env 2.x preserves HTTPS_PROXY, lowercase precedence and NO_PROXY exclusion', t => {
    const names = ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'];
    const saved = Object.fromEntries(names.map(key => [key, process.env[key]]));
    names.forEach(key => delete process.env[key]);
    t.after(() => { for (const key of names) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; } });
    const { getProxyForUrl } = require('proxy-from-env');
    process.env.HTTPS_PROXY = 'http://proxy.example:8080';
    assert.equal(getProxyForUrl('https://discord.com/api'), 'http://proxy.example:8080');
    process.env.https_proxy = 'http://lower.example:8080';
    assert.equal(getProxyForUrl('https://discord.com/api'), 'http://lower.example:8080');
    process.env.NO_PROXY = 'discord.com,.supabase.co';
    assert.equal(getProxyForUrl('https://discord.com/api'), '');
    assert.equal(getProxyForUrl('https://example.supabase.co/rest/v1'), '');
    assert.equal(getProxyForUrl('https://discord.com.evil.test'), 'http://lower.example:8080');
});

test('real Express start route uses configured HTTPS origin despite spoofed proxy headers', async t => {
    const express = require('express');
    const registerRoutes = require('../src/web/server');
    const app = express();
    registerRoutes(app, {}, { database: { users: {}, config: {} }, verifiedUsers: {}, oauthState: createOAuthState({ env }) });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const response = await fetch(`http://127.0.0.1:${server.address().port}/oauth2/start`, {
        redirect: 'manual', headers: { 'X-Forwarded-Proto': 'http', 'X-Forwarded-Host': 'evil.test' }
    });
    assert.equal(response.status, 302);
    assert.match(response.headers.get('set-cookie'), /^__Host-authcommunity-oauth=/);
    assert.match(response.headers.get('set-cookie'), /; Secure/);
    assert.match(response.headers.get('set-cookie'), /; HttpOnly/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    const target = new URL(response.headers.get('location'));
    assert.equal(target.origin, 'https://discord.com');
    assert.equal(target.searchParams.get('redirect_uri'), env.REDIRECT_URI);
    assert.ok(target.searchParams.get('state'));
});
