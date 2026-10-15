const { createCipheriv, createDecipheriv, randomBytes } = require('node:crypto');

function decode(value, size) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 16384) throw new Error();
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value || (size && bytes.length !== size)) throw new Error();
    return bytes;
}

function contextData(context, keyId) {
    if (!context || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(context.authorizationId) ||
        typeof context.discordId !== 'string' || !/^\d{17,20}$/.test(context.discordId) ||
        typeof context.clientId !== 'string' || !/^\d{17,20}$/.test(context.clientId)) throw new Error();
    return Buffer.from(JSON.stringify(['authcommunity:oauth-tokens', 1, keyId,
        context.authorizationId, context.discordId, context.clientId]));
}

function validateTokens(tokens) {
    if (!tokens || Object.keys(tokens).sort().join(',') !== 'access_token,refresh_token' ||
        typeof tokens.access_token !== 'string' || !tokens.access_token || tokens.access_token.length > 4096 ||
        !(tokens.refresh_token === null || (typeof tokens.refresh_token === 'string' && tokens.refresh_token.length > 0 && tokens.refresh_token.length <= 4096))) {
        throw new Error();
    }
}

// No dotenv, network, disk writes or secret generation at module load.
function createOAuthTokenCrypto({ keys, activeKeyId } = {}) {
    const keyring = new Map();
    try {
        if (!keys || Array.isArray(keys) || typeof keys !== 'object' || Object.keys(keys).length > 16) throw new Error();
        const material = new Set();
        for (const [id, encoded] of Object.entries(keys)) {
            if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error();
            const key = decode(encoded, 32);
            if (material.has(encoded)) throw new Error();
            material.add(encoded);
            keyring.set(id, key);
        }
        if (!keyring.has(activeKeyId)) throw new Error();
    } catch { throw new Error('OAUTH_TOKEN_KEY_CONFIGURATION_INVALID'); }

    function encrypt(tokens, context) {
        try {
            validateTokens(tokens);
            const aad = contextData(context, activeKeyId);
            const nonce = randomBytes(12); // fresh CSPRNG nonce for every encryption/rotation
            const cipher = createCipheriv('aes-256-gcm', keyring.get(activeKeyId), nonce, { authTagLength: 16 });
            cipher.setAAD(aad);
            const plaintext = Buffer.from(JSON.stringify(tokens));
            try {
                const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
                return { v: 1, key_id: activeKeyId, nonce: nonce.toString('base64url'),
                    ciphertext: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
            } finally { plaintext.fill(0); }
        } catch { throw new Error('OAUTH_TOKEN_ENCRYPT_FAILED'); }
    }

    function decrypt(envelope, context) {
        try {
            if (!envelope || Object.keys(envelope).sort().join(',') !== 'ciphertext,key_id,nonce,tag,v' ||
                envelope.v !== 1 || !keyring.has(envelope.key_id)) throw new Error();
            const decipher = createDecipheriv('aes-256-gcm', keyring.get(envelope.key_id), decode(envelope.nonce, 12), { authTagLength: 16 });
            decipher.setAAD(contextData(context, envelope.key_id));
            decipher.setAuthTag(decode(envelope.tag, 16));
            const plaintext = Buffer.concat([decipher.update(decode(envelope.ciphertext)), decipher.final()]);
            try {
                const tokens = JSON.parse(plaintext.toString('utf8'));
                validateTokens(tokens);
                return tokens;
            } finally { plaintext.fill(0); }
        } catch { throw new Error('OAUTH_TOKEN_DECRYPT_FAILED'); }
    }

    return Object.freeze({ encrypt, decrypt, rotate: (envelope, context) => encrypt(decrypt(envelope, context), context) });
}

function tokenCryptoFromEnvironment(env = process.env) {
    try { return createOAuthTokenCrypto({ keys: JSON.parse(env.OAUTH_TOKEN_KEYS), activeKeyId: env.OAUTH_TOKEN_ACTIVE_KEY_ID }); }
    catch { throw new Error('OAUTH_TOKEN_KEY_CONFIGURATION_INVALID'); }
}

module.exports = { createOAuthTokenCrypto, tokenCryptoFromEnvironment };
