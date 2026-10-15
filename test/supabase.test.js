const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createAuthUsersStore } = require('../src/database/supabase');
const { createVerifiedUsersRepository } = require('../src/database/verified-users');

const env = { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'test-only-placeholder' };
const user = {
    id: '123456789012345678', username: 'tester', avatar: null,
    access_token: 'private-access', refresh_token: 'private-refresh',
    email: 'private@example.invalid', ip: '192.0.2.1', userDevice: 'private-device'
};
const timestamp = '2026-10-09T12:00:00.000Z';
const reply = (body, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' }
});

test('SDK writes only the five approved fields and updates repeated verifications', async () => {
    const rows = new Map();
    const store = createAuthUsersStore({ env, fetch: async (url, options) => {
        const endpoint = new URL(url);
        assert.equal(endpoint.pathname, '/rest/v1/auth_users');
        assert.equal(endpoint.searchParams.get('on_conflict'), 'discord_id');
        assert.equal(endpoint.searchParams.get('select'), 'discord_id');
        assert.equal(options.method, 'POST');
        const headers = new Headers(options.headers);
        assert.match(headers.get('prefer'), /resolution=merge-duplicates/);
        assert.equal(headers.get('content-profile'), 'public');
        const row = JSON.parse(options.body);
        assert.deepEqual(Object.keys(row).sort(), ['avatar', 'discord_id', 'updated_at', 'username', 'verified_at']);
        assert.equal(typeof row.discord_id, 'string');
        assert.equal(headers.get('apikey'), env.SUPABASE_SECRET_KEY);
        rows.set(row.discord_id, row);
        return reply({ discord_id: row.discord_id });
    } });
    await store.saveVerifiedUser(user, timestamp);
    const later = '2026-10-09T13:00:00.000Z';
    await store.saveVerifiedUser({ ...user, username: 'renamed', avatar: 'avatar-hash' }, later);
    assert.equal(rows.size, 1);
    assert.deepEqual(rows.get(user.id), {
        discord_id: user.id, username: 'renamed', avatar: 'avatar-hash', verified_at: later, updated_at: later
    });
});

test('missing avatar becomes null', async () => {
    const store = createAuthUsersStore({ env, fetch: async (_url, options) => {
        assert.equal(JSON.parse(options.body).avatar, null);
        return reply({ discord_id: user.id });
    } });
    await store.saveVerifiedUser({ id: user.id, username: user.username }, timestamp);
});

test('configuration failures are lazy, safe and never send requests', async () => {
    for (const invalidEnv of [{}, { ...env, SUPABASE_SECRET_KEY: '' }, { ...env, SUPABASE_URL: 'private-invalid-url' },
        { ...env, SUPABASE_URL: 'http://example.supabase.co' }]) {
        const store = createAuthUsersStore({ env: invalidEnv, fetch: () => assert.fail('Unexpected network request') });
        await assert.rejects(store.saveVerifiedUser(user, timestamp), { message: 'SUPABASE_CONFIGURATION_INVALID' });
    }
});

test('invalid IDs and timestamps are rejected without sending private input', async () => {
    const store = createAuthUsersStore({ env, fetch: () => assert.fail('Unexpected network request') });
    await assert.rejects(store.saveVerifiedUser({ ...user, id: Number(user.id) }, timestamp), { message: 'VERIFIED_USER_INVALID' });
    await assert.rejects(store.saveVerifiedUser(user, 'invalid'), { message: 'VERIFIED_USER_INVALID' });
});

test('HTTP errors, empty confirmations and transport failures are sanitized', async () => {
    const privateBody = { message: JSON.stringify(user), details: env.SUPABASE_SECRET_KEY };
    const failures = [
        async () => reply(privateBody, 401),
        async () => reply(privateBody, 400),
        async () => reply(null),
        async () => reply({ discord_id: '999999999999999999' }),
        async () => { throw new Error(JSON.stringify(privateBody)); }
    ];
    for (const fetch of failures) {
        await assert.rejects(createAuthUsersStore({ env, fetch }).saveVerifiedUser(user, timestamp),
            { message: 'AUTH_USERS_SAVE_FAILED' });
    }
});

test('slow requests are aborted and cannot report success', async () => {
    let aborted = false;
    const store = createAuthUsersStore({ env, timeoutMs: 10, fetch: (_url, { signal }) => new Promise((_resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Test request exceeded timeout')), 1000);
        const abort = () => { aborted = true; clearTimeout(timer); reject(signal.reason); };
        if (signal.aborted) abort();
        else signal.addEventListener('abort', abort, { once: true });
    }) });
    await assert.rejects(store.saveVerifiedUser(user, timestamp), { message: 'AUTH_USERS_SAVE_FAILED' });
    assert.equal(aborted, true);
});

test('repository persists first and preserves the complete legacy record', async () => {
    const calls = [];
    const record = { ...user, verifiedAt: timestamp };
    const repository = createVerifiedUsersRepository({
        persistentUsers: { saveVerifiedUser: async (data, date) => { assert.equal(data, record); assert.equal(date, timestamp); calls.push('persistent'); } },
        legacyUsers: { set: (id, data) => { assert.equal(id, user.id); assert.equal(data, record); calls.push('legacy'); } }
    });
    await repository.saveVerification(record);
    assert.deepEqual(calls, ['persistent', 'legacy']);
});

test('repository never writes legacy verification after a persistent failure', async () => {
    const repository = createVerifiedUsersRepository({
        persistentUsers: { saveVerifiedUser: async () => { throw new Error('AUTH_USERS_SAVE_FAILED'); } },
        legacyUsers: { set: () => assert.fail('Unexpected JSON write') }
    });
    await assert.rejects(repository.saveVerification({ ...user, verifiedAt: timestamp }));
});

test('legacy write failures propagate instead of confirming completion', async () => {
    const repository = createVerifiedUsersRepository({
        persistentUsers: { saveVerifiedUser: async () => {} },
        legacyUsers: { set: () => { throw new Error('Disk failure'); } }
    });
    await assert.rejects(repository.saveVerification({ ...user, verifiedAt: timestamp }), { message: 'LEGACY_USERS_SAVE_FAILED' });
});
