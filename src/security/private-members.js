const services = new WeakMap();
function enabled(env = process.env) {
    if (!env.OAUTH_MEMBER_JOIN_ENABLED || env.OAUTH_MEMBER_JOIN_ENABLED === 'false') return false;
    if (env.OAUTH_MEMBER_JOIN_ENABLED !== 'true' || env.OAUTH_PRIVATE_ENABLED !== 'true') throw new Error('MEMBER_JOIN_CONFIGURATION_INVALID');
    return true;
}
async function initialize(client, env = process.env) {
    if (!enabled(env) || services.has(client)) return;
    try {
        if (!/^\d{17,20}$/.test(env.GUILD_ID) || !/^\d{17,20}$/.test(env.CLIENT_ID) || !env.TOKEN || !env.CLIENT_SECRET) throw new Error();
        const http = require('axios');
        const repositories = require('../database/oauth-repositories').oauthRepositoriesFromEnvironment(env);
        const lifecycle = require('./oauth-lifecycle').createOAuthLifecycle({ repositories, http, env });
        const observer = require('./member-observer').createMemberObserver({ client, repositories, env });
        const service = require('./member-join-service').createMemberJoinService({ repositories, lifecycle, http, observer, env });
        services.set(client,service);
        await observer.start();
    } catch { throw new Error('MEMBER_JOIN_CONFIGURATION_INVALID'); }
}
function get(client) {
    const service=services.get(client);
    if (!service) throw new Error('MEMBER_JOIN_UNAVAILABLE');
    return service;
}
module.exports = { enabled, initialize, get };
