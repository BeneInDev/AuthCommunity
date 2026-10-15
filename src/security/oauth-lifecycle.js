const { randomUUID } = require('node:crypto');
const { externalRequestOptions } = require('../http-options');

// OAuth metadata comes from Discord's token response, never from requested scopes.
function tokenData(data, now = Date.now()) {
    if (!data || typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 4096 ||
        typeof data.refresh_token !== 'string' || !data.refresh_token || data.refresh_token.length > 4096 ||
        typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer' ||
        !Number.isSafeInteger(data.expires_in) || data.expires_in <= 0 || data.expires_in > 31536000 ||
        typeof data.scope !== 'string' || data.scope.length > 2048) throw new Error('OAUTH_TOKEN_RESPONSE_INVALID');
    const scopes = [...new Set(data.scope.split(/\s+/).filter(Boolean))];
    if (!scopes.includes('identify') || !scopes.includes('guilds.join') || scopes.length > 32) throw new Error('OAUTH_SCOPE_MISSING');
    return { tokens: { access_token: data.access_token, refresh_token: data.refresh_token },
        expiresAt: new Date(now + data.expires_in * 1000).toISOString(), scopes };
}

function createOAuthLifecycle({ repositories, http, env = process.env, now = Date.now }) {
    async function post(path, params) {
        const body = new URLSearchParams({ client_id: env.CLIENT_ID, client_secret: env.CLIENT_SECRET, ...params });
        return http.post(`https://discord.com/api/oauth2/${path}`, body,
            { ...externalRequestOptions(), maxRedirects: 0, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    }
    return {
        async complete(flow, code) {
            try {
                if (await repositories.flows.claimCallback(flow) !== true) throw new Error();
                const response = await post('token', { grant_type: 'authorization_code', code, redirect_uri: env.REDIRECT_URI });
                const granted = tokenData(response.data, now());
                const user = await http.get('https://discord.com/api/users/@me', {
                    ...externalRequestOptions(), maxRedirects: 0, headers: { Authorization: `Bearer ${granted.tokens.access_token}` }
                });
                const discordId = user.data?.id;
                if (typeof discordId !== 'string' || !/^\d{17,20}$/.test(discordId)) throw new Error();
                if (flow.originGuildId && (flow.subjectId !== discordId || flow.originGuildId !== flow.guildId)) throw new Error();
                const previous = await repositories.authorizations.find(discordId, env.CLIENT_ID);
                const id = previous?.id || randomUUID();
                const persist = flow.originGuildId ? repositories.guilds.complete : repositories.flows.complete;
                const result = await persist({ ...granted, id, version: previous?.version ?? null,
                    profile: { username: user.data.username, avatar: user.data.avatar },
                    discordId, clientId: env.CLIENT_ID, consentId: randomUUID(), flowId: flow.id,
                    sessionHash: flow.sessionHash, stateHash: flow.stateHash, guildId: flow.guildId, validSeconds: flow.validSeconds });
                if (result !== id) throw new Error();
                return { authorizationId: id };
            } catch { throw new Error('OAUTH_VERIFICATION_FAILED'); }
        },
        // Backend-only entry points. Caller must authenticate the owner before invoking.
        async refresh(id) {
            let record, leaseId;
            try {
                const current = await repositories.authorizations.get(id);
                if (!current || current.client_id !== env.CLIENT_ID || current.status !== 'active') throw new Error();
                leaseId = randomUUID();
                record = await repositories.authorizations.claimRefresh(id, current.version, leaseId);
                const tokens = repositories.authorizations.decrypt(record);
                const response = await post('token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
                const granted = tokenData(response.data, now());
                const version = await repositories.authorizations.finishRefresh(record, leaseId, granted.tokens, granted.expiresAt, granted.scopes);
                if (!Number.isSafeInteger(version) || version <= record.version) throw new Error();
                return { version };
            } catch {
                if (record) {
                    try { await repositories.authorizations.abandonRefresh(id, record.version, leaseId); } catch { /* stays blocked by its lease */ }
                }
                throw new Error('OAUTH_REFRESH_FAILED');
            }
        },
        async revoke(id) {
            try {
                const current = await repositories.authorizations.get(id);
                if (!current || current.client_id !== env.CLIENT_ID) throw new Error();
                const record = await repositories.authorizations.beginRevocation(id);
                if (record.status === 'revoked') return;
                const tokens = repositories.authorizations.decrypt(record);
                await post('token/revoke', { token: tokens.refresh_token || tokens.access_token,
                    token_type_hint: tokens.refresh_token ? 'refresh_token' : 'access_token' });
                if (await repositories.authorizations.finishRevocation(id, record.version) !== true) throw new Error();
            } catch { throw new Error('OAUTH_REVOCATION_PENDING'); }
        }
    };
}
module.exports = { createOAuthLifecycle, tokenData };
