const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const { createOAuthTokenCrypto, tokenCryptoFromEnvironment } = require('../src/security/oauth-token-crypto');
const { createOAuthRepositories } = require('../src/database/oauth-repositories');

const key = () => randomBytes(32).toString('base64url');
const context = () => ({ authorizationId: randomUUID(), discordId: '9000000000000000000', clientId: '9000000000000000001' });
const tokens = () => ({ access_token: randomBytes(32).toString('base64url'), refresh_token: randomBytes(32).toString('base64url') });

test('AES-GCM round trip binds identity and emits fresh nonces without plaintext', () => {
    const crypto = createOAuthTokenCrypto({ keys: { test: key() }, activeKeyId: 'test' });
    const identity = context(), plaintext = tokens(), nonces = new Set();
    for (let i = 0; i < 256; i++) {
        const envelope = crypto.encrypt(plaintext, identity);
        assert.deepEqual(crypto.decrypt(envelope, identity), plaintext);
        assert.equal(JSON.stringify(envelope).includes(plaintext.access_token), false);
        assert.equal(JSON.stringify(envelope).includes(plaintext.refresh_token), false);
        nonces.add(envelope.nonce);
    }
    assert.equal(nonces.size, 256);
});

test('ciphertext, nonce, tag, key id, version and AAD tampering fail closed', () => {
    const crypto = createOAuthTokenCrypto({ keys: { one: key(), two: key() }, activeKeyId: 'one' });
    const identity = context(), envelope = crypto.encrypt(tokens(), identity);
    for (const field of ['ciphertext','nonce','tag']) {
        const changed = Buffer.from(envelope[field], 'base64url'); changed[0] ^= 1;
        assert.throws(() => crypto.decrypt({ ...envelope, [field]: changed.toString('base64url') }, identity), { message: 'OAUTH_TOKEN_DECRYPT_FAILED' });
    }
    for (const invalid of [{ ...envelope, key_id: 'two' }, { ...envelope, v: 2 }, { ...envelope, extra: 'untrusted' }, { ...envelope, nonce: '' }]) {
        assert.throws(() => crypto.decrypt(invalid, identity), { message: 'OAUTH_TOKEN_DECRYPT_FAILED' });
    }
    for (const changed of [{ ...identity, authorizationId: randomUUID() }, { ...identity, discordId: '9000000000000000002' },
        { ...identity, clientId: '9000000000000000003' }]) {
        assert.throws(() => crypto.decrypt(envelope, changed), { message: 'OAUTH_TOKEN_DECRYPT_FAILED' });
    }
});

test('rotation preserves tokens, authenticates old data and supports retirement of old key', () => {
    const old = key(), next = key(), identity = context(), plaintext = tokens();
    const before = createOAuthTokenCrypto({ keys: { old }, activeKeyId: 'old' }).encrypt(plaintext, identity);
    const during = createOAuthTokenCrypto({ keys: { old, next }, activeKeyId: 'next' });
    const rotated = during.rotate(before, identity);
    assert.equal(rotated.key_id, 'next');
    assert.notEqual(rotated.nonce, before.nonce);
    assert.deepEqual(during.decrypt(before, identity), plaintext);
    const after = createOAuthTokenCrypto({ keys: { next }, activeKeyId: 'next' });
    assert.deepEqual(after.decrypt(rotated, identity), plaintext);
    assert.throws(() => after.decrypt(before, identity), { message: 'OAUTH_TOKEN_DECRYPT_FAILED' });
    const wrong = createOAuthTokenCrypto({ keys: { next: key() }, activeKeyId: 'next' });
    assert.throws(() => wrong.decrypt(rotated, identity), { message: 'OAUTH_TOKEN_DECRYPT_FAILED' });
});

test('configuration and payload failures disclose no material', () => {
    const k = key();
    for (const options of [{}, { keys: { one: 'invalid' }, activeKeyId: 'one' }, { keys: { one: k }, activeKeyId: 'absent' },
        { keys: { one: k, two: k }, activeKeyId: 'one' }]) {
        assert.throws(() => createOAuthTokenCrypto(options), { message: 'OAUTH_TOKEN_KEY_CONFIGURATION_INVALID' });
    }
    assert.throws(() => tokenCryptoFromEnvironment({ OAUTH_TOKEN_KEYS: 'not json' }), { message: 'OAUTH_TOKEN_KEY_CONFIGURATION_INVALID' });
    const crypto = createOAuthTokenCrypto({ keys: { one: k }, activeKeyId: 'one' });
    assert.throws(() => crypto.encrypt({ ...tokens(), email: 'not-accepted' }, context()), { message: 'OAUTH_TOKEN_ENCRYPT_FAILED' });
    assert.throws(() => crypto.encrypt(tokens(), { ...context(), discordId: 123 }), { message: 'OAUTH_TOKEN_ENCRYPT_FAILED' });
});

test('repository sends ciphertext only, uses bounded RPC and requires explicit consent', async () => {
    const crypto = createOAuthTokenCrypto({ keys: { test: key() }, activeKeyId: 'test' });
    const captured = [];
    const client = { schema: schema => { assert.equal(schema, 'public'); return { rpc: (name, params) => {
        captured.push({ name, params });
        return { retry: value => { assert.equal(value, false); return { abortSignal: signal => {
            assert.ok(signal instanceof AbortSignal); return Promise.resolve({ data: 1, error: null });
        } }; } };
    } }; } };
    const repositories = createOAuthRepositories({ client, crypto });
    const identity = context(), plaintext = tokens();
    await repositories.authorizations.create({ id: identity.authorizationId, discordId: identity.discordId, clientId: identity.clientId,
        tokens: plaintext, expiresAt: new Date(Date.now()+3600000).toISOString(), scopes: ['identify','guilds.join'] });
    assert.equal(captured[0].name, 'ac_oauth_create_authorization');
    assert.deepEqual(crypto.decrypt(captured[0].params.p_envelope, identity), plaintext);
    assert.equal(JSON.stringify(captured).includes(plaintext.access_token), false);
    assert.throws(() => repositories.consents.grant({ accepted: false }), { message: 'OAUTH_EXPLICIT_CONSENT_REQUIRED' });
    assert.equal(captured.length, 1);
});

test('repository sanitizes provider errors and rejected network requests', async () => {
    for (const rejects of [false,true]) {
        const crypto = createOAuthTokenCrypto({ keys: { test: key() }, activeKeyId: 'test' });
        const client = { schema: () => ({ rpc: () => ({ retry: () => ({ abortSignal: async () => {
            if (rejects) throw new Error('sensitive-provider-details');
            return { error: { message: 'sensitive-provider-details' } };
        } }) }) }) };
        await assert.rejects(createOAuthRepositories({ client, crypto }).authorizations.get(randomUUID()), { message: 'OAUTH_REPOSITORY_OPERATION_FAILED' });
    }
});
