const { randomBytes, createHmac, timingSafeEqual } = require('node:crypto');

const TTL_MS = 10 * 60 * 1000;

function callbackUrl(env = process.env) {
    const url = new URL(env.REDIRECT_URI);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.username || url.password || url.search || url.hash ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && local && env.NODE_ENV !== 'production'))) {
        throw new Error('OAUTH_CONFIGURATION_INVALID');
    }
    return url;
}

function verificationUrl(env = process.env) {
    return new URL('/oauth2/start', callbackUrl(env)).href;
}

function createOAuthState({ env = process.env, now = Date.now } = {}) {
    function settings() {
        const url = callbackUrl(env);
        // Domain separation allows a stable existing secret without a new deployment setting.
        const secret = env.OAUTH_STATE_SECRET || env.CLIENT_SECRET;
        if (typeof secret !== 'string' || secret.length < 32) throw new Error('OAUTH_CONFIGURATION_INVALID');
        const secure = url.protocol === 'https:';
        return { url, secret, cookie: secure ? '__Host-authcommunity-oauth' : 'authcommunity-oauth',
            options: { httpOnly: true, secure, sameSite: 'lax', path: '/' } };
    }
    const sign = (payload, session, config) => createHmac('sha256', config.secret)
        .update(JSON.stringify(['authcommunity-oauth-v1', config.url.href, session, payload])).digest('base64url');

    return {
        start(res) {
            const config = settings();
            const session = randomBytes(32).toString('base64url');
            const payload = `${now() + TTL_MS}.${randomBytes(32).toString('base64url')}`;
            const state = `${payload}.${sign(payload, session, config)}`;
            res.cookie(config.cookie, session, { ...config.options, maxAge: TTL_MS });
            const url = new URL('https://discord.com/api/oauth2/authorize');
            url.search = new URLSearchParams({ client_id: env.CLIENT_ID, redirect_uri: config.url.href,
                response_type: 'code', scope: 'identify email guilds.join', state }).toString();
            return url.href;
        },
        consume(req, res) {
            const config = settings();
            // Cookie deletion also covers expired, denied and malformed callbacks.
            res.clearCookie(config.cookie, config.options);
            const cookies = (req.headers.cookie || '').split(';').map(part => part.trim())
                .filter(part => part.startsWith(`${config.cookie}=`));
            if (cookies.length !== 1) return false;
            const session = cookies[0].slice(config.cookie.length + 1);
            const state = req.query.state;
            if (!/^[A-Za-z0-9_-]{43}$/.test(session) || typeof state !== 'string' || state.length > 150) return false;
            const match = /^(\d{13})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/.exec(state);
            if (!match) return false;
            const expiry = Number(match[1]);
            const time = now();
            if (expiry <= time || expiry > time + TTL_MS) return false;
            const expected = sign(`${match[1]}.${match[2]}`, session, config);
            return timingSafeEqual(Buffer.from(match[3]), Buffer.from(expected));
        }
    };
}

module.exports = { createOAuthState, verificationUrl, TTL_MS };
