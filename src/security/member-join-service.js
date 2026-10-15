const { randomUUID } = require('node:crypto');
const { externalRequestOptions } = require('../http-options');

function createMemberJoinService({ repositories, lifecycle, http, observer, env = process.env, now = Date.now }) {
    const valid = record => record && record.client_id === env.CLIENT_ID && record.status === 'active' &&
        !record.refresh_lease_id && Array.isArray(record.scopes) && record.scopes.includes('guilds.join');
    const usable = record => valid(record) && Date.parse(record.access_expires_at) > now() + 30000;
    // Never retry a PUT automatically. A 429 stops the batch and persists its cooldown.
    const rateLimit = response => {
        const value = Number(response.data?.retry_after ?? response.headers?.['retry-after']);
        return Number.isFinite(value) && value > 0 && value <= 604800 ? Math.ceil(value) : 604800;
    };
    return {
        async run({ guildId, amount }) {
            if (guildId !== env.GUILD_ID || !/^\d{17,20}$/.test(guildId) ||
                !Number.isInteger(amount) || amount < 1 || amount > 100 || !observer.safe()) throw new Error('MEMBER_JOIN_UNAVAILABLE');
            const summary = { joined: 0, already_member: 0, pending: 0, failed: 0, uncertain: 0, skipped: 0, stopped: false };
            let candidates;
            try { candidates = await repositories.membership.candidates(guildId, env.CLIENT_ID, observer.id, amount); }
            catch { throw new Error('MEMBER_JOIN_UNAVAILABLE'); }
            if (!Array.isArray(candidates)) throw new Error('MEMBER_JOIN_UNAVAILABLE');
            const started = now();
            for (const candidate of candidates.slice(0, amount)) {
                if (!observer.safe() || now() - started > 120000) { summary.stopped = true; break; }
                const operation = { id: randomUUID(), leaseId: randomUUID(), consentId: candidate.consent_id,
                    guildId, clientId: env.CLIENT_ID, observerId: observer.id };
                let reserved = false, sent = false, result = 'failed', failureCode = 'authorization_unavailable', httpStatus = null, retrySeconds = 0;
                try {
                    let record = await repositories.authorizations.get(candidate.authorization_id);
                    if (!valid(record) || record.discord_id !== candidate.discord_id || !/^\d{17,20}$/.test(record.discord_id)) throw new Error();
                    if (!usable(record)) {
                        try { await lifecycle.refresh(record.id); }
                        catch { observer.block(); summary.stopped = true; throw new Error(); }
                        record = await repositories.authorizations.get(record.id);
                    }
                    if (!usable(record) || !observer.safe()) throw new Error();
                    const claim = await repositories.membership.reserve(operation);
                    if (claim?.operation_id !== operation.id || claim.authorization_id !== record.id || claim.discord_id !== record.discord_id) throw new Error();
                    reserved = true;
                    const url = `https://discord.com/api/v10/guilds/${guildId}/members/${record.discord_id}`;
                    const options = () => ({ ...externalRequestOptions(), validateStatus: () => true,
                        headers: { Authorization: `Bot ${env.TOKEN}`, 'Content-Type': 'application/json' } });
                    if (!observer.safe()) throw new Error();
                    failureCode = 'preflight_failed';
                    const present = await http.get(url, options());
                    httpStatus = present.status;
                    if (present.status === 200) {
                        result = present.data?.pending === true ? 'pending' : 'already_member'; failureCode = null;
                    } else if (present.status === 429) {
                        failureCode = 'rate_limited'; retrySeconds = rateLimit(present); summary.stopped = true;
                    } else if (present.status === 404 && present.data?.code === 10007) {
                        failureCode = 'authorization_unavailable';
                        record = await repositories.membership.dispatch(operation);
                        if (!usable(record) || record.id !== claim.authorization_id || record.discord_id !== claim.discord_id || !observer.safe()) throw new Error();
                        const tokens = repositories.authorizations.decrypt(record);
                        sent = true;
                        httpStatus = null;
                        const response = await http.put(url, { access_token: tokens.access_token }, options());
                        httpStatus = response.status;
                        failureCode = null;
                        if (response.status === 201) result = response.data?.pending === true ? 'pending' : 'joined';
                        else if (response.status === 204) result = 'already_member';
                        else if (response.status === 429) {
                            result = 'failed';failureCode = 'rate_limited';retrySeconds = rateLimit(response);summary.stopped = true;
                        } else if (!(response.status >= 400 && response.status < 500)) {
                            result = 'uncertain';failureCode = 'transport_unknown';summary.stopped = true;
                        } else { result = 'failed';failureCode = 'discord_rejected'; }
                    }
                } catch {
                    if (!reserved) { summary.skipped++; if (summary.stopped) break; continue; }
                    if (sent) { result = 'uncertain'; failureCode = 'transport_unknown'; summary.stopped = true; }
                }
                try {
                    const confirmed = await repositories.membership.finish({ ...operation, result, failureCode, httpStatus, retrySeconds });
                    if (confirmed !== true) throw new Error();
                    summary[result]++;
                } catch {
                    // Discord might have accepted the member. Do not claim durable success or resend.
                    summary.uncertain++;summary.stopped = true;
                    observer.block();
                }
                if (summary.stopped) break;
            }
            return summary;
        }
    };
}
module.exports = { createMemberJoinService };
