const { randomBytes, randomUUID, createHash, createHmac, timingSafeEqual } = require('node:crypto');
const TTL = 600000;
const hash = value => createHash('sha256').update(value).digest('hex');

function createConsentState({ env = process.env, now = Date.now, multi = false } = {}) {
    const callback = new URL(env.REDIRECT_URI);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(callback.hostname);
    if (callback.username || callback.password || callback.search || callback.hash ||
        (callback.protocol !== 'https:' && !(local && callback.protocol === 'http:' && env.NODE_ENV !== 'production')) ||
        typeof env.OAUTH_STATE_SECRET !== 'string' || env.OAUTH_STATE_SECRET.length < 32 ||
        typeof env.CLIENT_SECRET !== 'string' || !env.CLIENT_SECRET || env.OAUTH_STATE_SECRET === env.CLIENT_SECRET ||
        (!multi && !/^\d{17,20}$/.test(env.GUILD_ID)) || !/^\d{17,20}$/.test(env.CLIENT_ID)) throw new Error('OAUTH_CONFIGURATION_INVALID');
    const days = Number(env.OAUTH_CONSENT_DAYS || 30);
    if (!Number.isInteger(days) || days < 1 || days > 90) throw new Error('OAUTH_CONFIGURATION_INVALID');
    const secure = callback.protocol === 'https:';
    const cookie = secure ? '__Host-authcommunity-consent' : 'authcommunity-consent';
    const options = { httpOnly: true, secure, sameSite: 'lax', path: '/' };
    const sign = (payload, session) => createHmac('sha256', env.OAUTH_STATE_SECRET)
        .update(JSON.stringify([multi ? 'authcommunity-consent-v3' : 'authcommunity-consent-v2', callback.href, env.CLIENT_ID, session, payload])).digest('base64url');
    const encode = (data, session) => {
        const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
        return `${payload}.${sign(payload, session)}`;
    };
    function read(req, state, stage) {
        if (typeof state !== 'string' || state.length > 2048) throw new Error('OAUTH_STATE_INVALID');
        const cookies = (req.headers.cookie || '').split(';').map(s => s.trim()).filter(s => s.startsWith(`${cookie}=`));
        if (cookies.length !== 1) throw new Error('OAUTH_STATE_INVALID');
        const session = cookies[0].slice(cookie.length + 1);
        const parts = state.split('.');
        if (!/^[A-Za-z0-9_-]{43}$/.test(session) || parts.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(parts[1]) ||
            !timingSafeEqual(Buffer.from(parts[1]), Buffer.from(sign(parts[0], session)))) throw new Error('OAUTH_STATE_INVALID');
        const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        if (multi && (!/^\d{17,20}$/.test(data.guildId) || data.originGuildId !== data.guildId || !/^\d{17,20}$/.test(data.subjectId) || !Number.isSafeInteger(data.configVersion))) throw new Error('OAUTH_STATE_INVALID');
        if (data.stage !== stage || (!multi && data.guildId !== env.GUILD_ID) || !Number.isSafeInteger(data.exp) ||
            data.exp <= now() || data.exp > now() + TTL || data.validSeconds !== days * 86400) throw new Error('OAUTH_STATE_INVALID');
        return { data, session, sessionHash: hash(session), stateHash: hash(state) };
    }
    return {
        days, origin: callback.origin,
        start(res, binding = {}) {
            const session = randomBytes(32).toString('base64url');
            res.cookie(cookie, session, { ...options, maxAge: TTL });
            return encode({ ...(multi ? binding : {}), id: randomUUID(), guildId: multi ? binding.guildId : env.GUILD_ID, exp: now() + TTL,
                validSeconds: days * 86400, policyVersion: 'guild-join-v1', stage: 'consent' }, session);
        },
        accept(req) {
            if (req.headers.origin !== callback.origin || req.body?.accepted !== 'yes') throw new Error('OAUTH_CONSENT_REQUIRED');
            const { data, session } = read(req, req.body.state, 'consent');
            const state = encode({ ...data, stage: 'callback' }, session);
            const url = new URL('https://discord.com/api/oauth2/authorize');
            url.search = new URLSearchParams({ client_id: env.CLIENT_ID, redirect_uri: callback.href,
                response_type: 'code', scope: 'identify guilds.join', prompt: 'consent', state }).toString();
            return { ...data, sessionHash: hash(session), stateHash: hash(state), url: url.href };
        },
        callback(req, res) {
            res.clearCookie(cookie, options);
            if (req.query.error || typeof req.query.code !== 'string' || !req.query.code || req.query.code.length > 4096 ||
                Object.keys(req.query).some(key => !['code','state'].includes(key))) throw new Error('OAUTH_CALLBACK_INVALID');
            const parsed = read(req, req.query.state, 'callback');
            return { ...parsed.data, sessionHash: parsed.sessionHash, stateHash: parsed.stateHash };
        }
    };
}
module.exports = { createConsentState };
