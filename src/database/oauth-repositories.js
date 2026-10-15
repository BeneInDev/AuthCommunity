const { createClient } = require('@supabase/supabase-js');
const { tokenCryptoFromEnvironment } = require('../security/oauth-token-crypto');

// Only instantiated by the opt-in flow; never uses legacy JSON as fallback.
function createOAuthRepositories({ client, crypto, timeoutMs = 10000 }) {
    if (!client || !crypto) throw new Error('OAUTH_REPOSITORY_CONFIGURATION_INVALID');
    async function rpc(name, params) {
        try {
            const { data, error } = await client.schema('public').rpc(name, params)
                .retry(false).abortSignal(AbortSignal.timeout(timeoutMs));
            if (error) throw new Error();
            return data;
        } catch {
            // Provider details may contain parameters/ciphertext. Never propagate them.
            throw new Error('OAUTH_REPOSITORY_OPERATION_FAILED');
        }
    }
    const context = record => ({ authorizationId: record.id, discordId: record.discord_id, clientId: record.client_id });
    return Object.freeze({
        guilds: Object.freeze({
            syncOwner: (guildId,ownerId) => rpc('ac_guild_sync_owner',{p_guild_id:guildId,p_owner_id:ownerId}),
            get: (guildId,actorId) => rpc('ac_guild_get',{p_guild_id:guildId,p_actor_id:actorId}),
            public: guildId => rpc('ac_guild_public',{p_guild_id:guildId}),
            save: ({guildId,actorId,version,roleId,logChannelId,message,active,adminIds=null}) => rpc('ac_guild_save',{
                p_guild_id:guildId,p_actor_id:actorId,p_version:version,p_role_id:roleId,p_log_channel_id:logChannelId,
                p_message:message,p_active:active,p_admin_ids:adminIds}),
            createFlow: flow => rpc('ac_guild_create_flow',{p_id:flow.id,p_session_hash:flow.sessionHash,p_state_hash:flow.stateHash,
                p_guild_id:flow.guildId,p_origin_id:flow.originGuildId,p_discord_id:flow.subjectId,p_version:flow.configVersion,p_policy_version:flow.policyVersion}),
            complete: data => rpc('ac_guild_complete',{p:{id:data.id,version:data.version,discord_id:data.discordId,client_id:data.clientId,
                envelope:crypto.encrypt(data.tokens,{authorizationId:data.id,discordId:data.discordId,clientId:data.clientId}),
                expires_at:data.expiresAt,scopes:data.scopes,consent_id:data.consentId,flow_id:data.flowId,
                session_hash:data.sessionHash,state_hash:data.stateHash,guild_id:data.guildId,valid_seconds:data.validSeconds,
                username:data.profile.username,avatar:data.profile.avatar ?? null}})
        }),
        effects: Object.freeze({
            claim: leaseId => rpc('ac_guild_claim_effect',{p_lease_id:leaseId}),
            dispatch: (id,leaseId) => rpc('ac_guild_dispatch_effect',{p_id:id,p_lease_id:leaseId}),
            finish: ({id,leaseId,status,code=null,messageId=null,delay=0}) => rpc('ac_guild_finish_effect',{
                p_id:id,p_lease_id:leaseId,p_status:status,p_code:code,p_message_id:messageId,p_delay:delay})
        }),
        membership: Object.freeze({
            watch: (guildId, clientId, observerId, reset) => rpc('ac_oauth_watch_guild', {
                p_guild_id: guildId, p_client_id: clientId, p_observer_id: observerId, p_reset: reset }),
            pause: (guildId, clientId, observerId) => rpc('ac_oauth_pause_guild', {
                p_guild_id: guildId, p_client_id: clientId, p_observer_id: observerId }),
            departure: (guildId, clientId, discordId) => rpc('ac_oauth_record_departure', {
                p_guild_id: guildId, p_client_id: clientId, p_discord_id: discordId }),
            candidates: (guildId, clientId, observerId, limit) => rpc('ac_oauth_join_candidates', {
                p_guild_id: guildId, p_client_id: clientId, p_observer_id: observerId, p_limit: limit }),
            reserve: ({ id, consentId, guildId, clientId, leaseId, observerId }) => rpc('ac_oauth_reserve_member', {
                p_id: id, p_consent_id: consentId, p_guild_id: guildId, p_client_id: clientId,
                p_lease_id: leaseId, p_observer_id: observerId }),
            dispatch: ({ id, leaseId, observerId, guildId, clientId }) => rpc('ac_oauth_dispatch_member', {
                p_id: id, p_lease_id: leaseId, p_observer_id: observerId, p_guild_id: guildId, p_client_id: clientId }),
            finish: ({ id, leaseId, result, failureCode = null, httpStatus = null, retrySeconds = 0 }) => rpc('ac_oauth_finish_member', {
                p_id: id, p_lease_id: leaseId, p_result: result, p_failure_code: failureCode,
                p_http_status: httpStatus, p_retry_seconds: retrySeconds })
        }),
        authorizations: Object.freeze({
            find: (discordId, clientId) => rpc('ac_oauth_find_authorization', { p_discord_id: discordId, p_client_id: clientId }),
            beginRevocation: id => rpc('ac_oauth_begin_revocation', { p_id: id }),
            finishRevocation: (id, version) => rpc('ac_oauth_finish_revocation', { p_id: id, p_version: version }),
            create: ({ id, discordId, clientId, tokens, expiresAt, scopes }) => rpc('ac_oauth_create_authorization', {
                p_id: id, p_discord_id: discordId, p_client_id: clientId,
                p_envelope: crypto.encrypt(tokens, { authorizationId: id, discordId, clientId }),
                p_expires_at: expiresAt, p_scopes: scopes
            }),
            get: id => rpc('ac_oauth_get_authorization', { p_id: id }),
            // Explicit decryption; get/list never implicitly return plaintext tokens.
            decrypt: record => crypto.decrypt(record.envelope, context(record)),
            rotateKey: record => rpc('ac_oauth_rotate_key', { p_id: record.id, p_version: record.version,
                p_envelope: crypto.rotate(record.envelope, context(record)) }),
            claimRefresh: (id, version, leaseId) => rpc('ac_oauth_claim_refresh', { p_id: id, p_version: version, p_lease_id: leaseId }),
            finishRefresh: (record, leaseId, tokens, expiresAt, scopes) => rpc('ac_oauth_finish_refresh', {
                p_id: record.id, p_version: record.version, p_lease_id: leaseId,
                p_envelope: crypto.encrypt(tokens, context(record)), p_expires_at: expiresAt, p_scopes: scopes
            }),
            abandonRefresh: (id, version, leaseId) => rpc('ac_oauth_abandon_refresh', { p_id: id, p_version: version, p_lease_id: leaseId }),
            revokeLocally: id => rpc('ac_oauth_revoke_authorization', { p_id: id })
        }),
        flows: Object.freeze({
            claimCallback: ({ id, sessionHash, stateHash, guildId }) => rpc('ac_oauth_claim_callback', {
                p_id: id, p_session_hash: sessionHash, p_state_hash: stateHash, p_guild_id: guildId
            }),
            complete: ({ id, version = null, discordId, clientId, tokens, expiresAt, scopes,
                consentId, flowId, sessionHash, stateHash, guildId, validSeconds }) => rpc('ac_oauth_complete_callback', {
                p_id: id, p_version: version, p_discord_id: discordId, p_client_id: clientId,
                p_envelope: crypto.encrypt(tokens, { authorizationId: id, discordId, clientId }),
                p_expires_at: expiresAt, p_scopes: scopes, p_consent_id: consentId, p_flow_id: flowId,
                p_session_hash: sessionHash, p_state_hash: stateHash, p_guild_id: guildId, p_valid_seconds: validSeconds
            }),
            create: ({ id, sessionHash, stateHash, guildId, policyVersion }) => rpc('ac_oauth_create_flow', {
                p_id: id, p_session_hash: sessionHash, p_state_hash: stateHash, p_guild_id: guildId, p_policy_version: policyVersion
            })
        }),
        consents: Object.freeze({
            grant: ({ id, authorizationId, flowId, sessionHash, stateHash, accepted, validSeconds }) => {
                if (accepted !== true) throw new Error('OAUTH_EXPLICIT_CONSENT_REQUIRED');
                return rpc('ac_oauth_grant_consent', { p_id: id, p_authorization_id: authorizationId,
                    p_flow_id: flowId, p_session_hash: sessionHash, p_state_hash: stateHash,
                    p_accepted: true, p_valid_seconds: validSeconds });
            },
            revoke: id => rpc('ac_oauth_revoke_consent', { p_id: id }),
            listEligible: (guildId, clientId, limit = 100) => rpc('ac_oauth_list_eligible', {
                p_guild_id: guildId, p_client_id: clientId, p_limit: limit
            })
        }),
        operations: Object.freeze({
            claim: ({ id, consentId, guildId, clientId, leaseId }) => rpc('ac_oauth_claim_join', {
                p_id: id, p_consent_id: consentId, p_guild_id: guildId, p_client_id: clientId, p_lease_id: leaseId
            }),
            finish: (id, leaseId, result) => rpc('ac_oauth_finish_join', { p_id: id, p_lease_id: leaseId, p_result: result })
        })
    });
}

function oauthRepositoriesFromEnvironment(env = process.env) {
    try {
        const url = new URL(env.SUPABASE_URL);
        if (url.protocol !== 'https:' || url.username || url.password || !env.SUPABASE_SECRET_KEY?.trim()) throw new Error();
        const crypto = tokenCryptoFromEnvironment(env);
        const client = createClient(url.href, env.SUPABASE_SECRET_KEY, {
            auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
        });
        return createOAuthRepositories({ client, crypto });
    } catch { throw new Error('OAUTH_REPOSITORY_CONFIGURATION_INVALID'); }
}

module.exports = { createOAuthRepositories, oauthRepositoriesFromEnvironment };
