const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');
const { PGlite } = require('@electric-sql/pglite');
const { createOAuthTokenCrypto } = require('../src/security/oauth-token-crypto');

// In-memory PostgreSQL only. No .env loading, credentials, real users or TCP connection.
let db;
const crypto = createOAuthTokenCrypto({ keys: { ephemeral: randomBytes(32).toString('base64url') }, activeKeyId: 'ephemeral' });
const guild = '9000000000000000002', clientId = '9000000000000000001';
let serial = 0n;
const hash = () => randomBytes(32).toString('hex');
const query = async (sql, params = []) => (await db.query(sql, params)).rows;
const call = async (name, args) => {
    if (!/^ac_(oauth|guild)_[a-z_]+$/.test(name)) throw new Error('Invalid test function');
    if (name === 'ac_oauth_list_eligible') return query('SELECT * FROM public.ac_oauth_list_eligible($1,$2,$3)', args);
    return (await query(`SELECT public.${name}(${args.map((_, i) => `$${i+1}`).join(',')}) AS result`, args))[0].result;
};

before(async () => {
    db = new PGlite();
    await db.exec(`CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated;
        CREATE TABLE public.auth_users(discord_id text PRIMARY KEY, username text, avatar text, verified_at timestamptz, updated_at timestamptz);
        INSERT INTO public.auth_users(discord_id,username) VALUES ('9000000000000000000','synthetic-sentinel');`);
    const directory = path.join(__dirname, '../supabase/migrations');
    for (const file of fs.readdirSync(directory).filter(f => f.endsWith('.sql')).sort()) {
        await db.exec(fs.readFileSync(path.join(directory, file), 'utf8'));
    }
});
after(async () => { if (db) await db.close(); });

async function authorization(scopes = ['identify','guilds.join']) {
    const id = randomUUID(), discordId = String(9000000000000000100n + serial++);
    const envelope = crypto.encrypt({ access_token: randomUUID(), refresh_token: randomUUID() }, { authorizationId: id, discordId, clientId });
    await call('ac_oauth_create_authorization', [id,discordId,clientId,envelope,new Date(Date.now()+3600000).toISOString(),scopes]);
    return { id,discordId,envelope };
}
async function flow(target = guild) {
    const f = { id: randomUUID(), session: hash(), state: hash() };
    await call('ac_oauth_create_flow', [f.id,f.session,f.state,target,'test-policy']);
    return f;
}
async function consent(a, f = null) {
    f ||= await flow(); const id = randomUUID();
    await call('ac_oauth_grant_consent', [id,a.id,f.id,f.session,f.state,true,3600]);
    return { id, flow: f };
}

test('migrations preserve auth_users and protect all private tables with RLS', async () => {
    assert.deepEqual(await query('SELECT discord_id,username FROM public.auth_users'), [{ discord_id:'9000000000000000000',username:'synthetic-sentinel' }]);
    const tables = await query("SELECT relname,relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='private' AND relkind='r'");
    assert.equal(tables.length, 8); assert.ok(tables.every(t => t.relrowsecurity));
    assert.equal((await query('SELECT count(*)::int AS n FROM private.guild_consents'))[0].n, 0);
});

test('all RPCs have fixed search_path; anonymous users cannot execute or read ciphertext', async () => {
    const functions = await query("SELECT p.oid,p.proname,p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND (p.proname LIKE 'ac_oauth_%' OR p.proname LIKE 'ac_guild_%')");
    assert.equal(functions.length, 34);
    for (const f of functions) {
        assert.equal(f.prosecdef,true); assert.deepEqual(f.proconfig,['search_path=pg_catalog']);
        const permissions = await query("SELECT has_function_privilege('anon',$1::oid,'EXECUTE') AS anon,has_function_privilege('authenticated',$1::oid,'EXECUTE') AS authenticated,has_function_privilege('service_role',$1::oid,'EXECUTE') AS backend", [f.oid]);
        assert.deepEqual(permissions[0],{ anon:false,authenticated:false,backend:f.proname !== 'ac_oauth_claim_join' });
    }
    for (const role of ['anon','authenticated','service_role']) {
        assert.equal((await query("SELECT has_table_privilege($1,'private.oauth_authorizations','SELECT') AS allowed",[role]))[0].allowed,false);
    }
    await db.exec('SET ROLE anon');
    try { await assert.rejects(call('ac_oauth_get_authorization',[randomUUID()]), /permission denied/); }
    finally { await db.exec('RESET ROLE'); }
    await db.exec('SET ROLE service_role');
    try { assert.equal(await call('ac_oauth_get_authorization',[randomUUID()]),null); }
    finally { await db.exec('RESET ROLE'); }
});

test('constraints reject plaintext envelopes, duplicate identity, invalid expiry and missing scopes', async () => {
    const a = await authorization();
    await assert.rejects(call('ac_oauth_create_authorization',[randomUUID(),a.discordId,clientId,a.envelope,new Date(Date.now()+60000).toISOString(),['identify']]), /unique constraint/);
    await assert.rejects(call('ac_oauth_rotate_key',[a.id,1,{ access_token:'forbidden',refresh_token:'forbidden' }]), /check constraint/);
    await assert.rejects(call('ac_oauth_rotate_key',[a.id,1,{ ...a.envelope,tag:null }]), /check constraint/);
    await assert.rejects(authorization([]), /check constraint/);
    await assert.rejects(call('ac_oauth_create_authorization',[randomUUID(),'9000000000000000500',clientId,a.envelope,'2000-01-01T00:00:00Z',['identify']]), /EXPIRY_INVALID/);
    const before = await call('ac_oauth_get_authorization',[a.id]); assert.equal(before.version,1);
});

test('consent is explicit, destination-bound, expires and consumes its flow once', async () => {
    const a = await authorization(), f = await flow();
    await assert.rejects(call('ac_oauth_grant_consent',[randomUUID(),a.id,f.id,f.session,f.state,false,3600]), /CONSENT_INVALID/);
    await assert.rejects(call('ac_oauth_grant_consent',[randomUUID(),a.id,f.id,hash(),f.state,true,3600]), /FLOW_INVALID/);
    const c = await consent(a,f);
    await assert.rejects(call('ac_oauth_grant_consent',[randomUUID(),a.id,f.id,f.session,f.state,true,3600]), /FLOW_INVALID/);
    assert.equal((await call('ac_oauth_list_eligible',[guild,clientId,100])).some(row=>row.consent_id===c.id),true);
    assert.equal((await call('ac_oauth_list_eligible',['9000000000000000003',clientId,100])).length,0);
    await db.query("UPDATE private.guild_consents SET granted_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",[c.id]);
    assert.equal((await call('ac_oauth_list_eligible',[guild,clientId,100])).some(row=>row.consent_id===c.id),false);
    const expired = await flow();
    await db.query("UPDATE private.oauth_flows SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",[expired.id]);
    await assert.rejects(consent(a,expired), /FLOW_INVALID/);
});

test('consent failure rolls back flow consumption and does not import legacy users', async () => {
    const a = await authorization(), existing = await consent(a), f = await flow();
    await assert.rejects(call('ac_oauth_grant_consent',[existing.id,a.id,f.id,f.session,f.state,true,3600]), /unique constraint/);
    assert.equal((await query('SELECT consumed_at FROM private.oauth_flows WHERE id=$1',[f.id]))[0].consumed_at,null);
    assert.equal((await query('SELECT status FROM private.guild_consents WHERE id=$1',[existing.id]))[0].status,'active');
    const withoutScope = await authorization(['identify']);
    await assert.rejects(consent(withoutScope), /AUTHORIZATION_UNAVAILABLE/);
});

test('refresh leases and CAS reject competing/stale writes and revocation cannot be undone', async () => {
    const a = await authorization(), lease=randomUUID();
    const claimed = await call('ac_oauth_claim_refresh',[a.id,1,lease]); assert.equal(claimed.version,2);
    await assert.rejects(call('ac_oauth_claim_refresh',[a.id,1,randomUUID()]), /CONFLICT/);
    await assert.rejects(call('ac_oauth_rotate_key',[a.id,2,a.envelope]), /CONFLICT/);
    await assert.rejects(call('ac_oauth_finish_refresh',[a.id,2,randomUUID(),a.envelope,new Date(Date.now()+3600000).toISOString(),['identify']]), /CONFLICT/);
    assert.equal(await call('ac_oauth_finish_refresh',[a.id,2,lease,a.envelope,new Date(Date.now()+3600000).toISOString(),['identify','guilds.join']]),3);
    const c=await consent(a); await call('ac_oauth_revoke_authorization',[a.id]);
    const revoked=await call('ac_oauth_get_authorization',[a.id]); assert.equal(revoked.envelope,null); assert.equal(revoked.status,'revoked');
    assert.equal((await query('SELECT status FROM private.guild_consents WHERE id=$1',[c.id]))[0].status,'revoked');
    await assert.rejects(call('ac_oauth_rotate_key',[a.id,revoked.version,a.envelope]), /CONFLICT/);
    await assert.rejects(call('ac_oauth_finish_refresh',[a.id,2,lease,a.envelope,new Date(Date.now()+3600000).toISOString(),['identify']]), /CONFLICT/);
});

test('expired refresh cannot be resumed and requires reauthorization', async () => {
    const a=await authorization(), lease=randomUUID();await call('ac_oauth_claim_refresh',[a.id,1,lease]);
    await db.query("UPDATE private.oauth_authorizations SET refresh_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[a.id]);
    await assert.rejects(call('ac_oauth_finish_refresh',[a.id,2,lease,a.envelope,new Date(Date.now()+3600000).toISOString(),['identify']]), /CONFLICT/);
    await call('ac_oauth_abandon_refresh',[a.id,2,lease]);
    assert.equal((await call('ac_oauth_get_authorization',[a.id])).status,'reauth_required');
});

test('join reservation enforces destination, scope and single use; late outcome is uncertain', async () => {
    const a=await authorization(), c=await consent(a), id=randomUUID(), lease=randomUUID();
    await assert.rejects(call('ac_oauth_claim_join',[id,c.id,'9000000000000000003',clientId,lease]), /CONSENT_UNAVAILABLE/);
    const claimed=await call('ac_oauth_claim_join',[id,c.id,guild,clientId,lease]);
    assert.equal(claimed.discord_id,a.discordId);assert.equal(Object.hasOwn(claimed,'envelope'),false);
    await assert.rejects(call('ac_oauth_claim_join',[randomUUID(),c.id,guild,clientId,randomUUID()]), /CONSENT_UNAVAILABLE/);
    assert.equal(await call('ac_oauth_finish_join',[id,randomUUID(),'joined']),false);
    await db.query("UPDATE private.member_join_operations SET created_at=clock_timestamp()-interval '2 hours',lease_expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",[id]);
    assert.equal(await call('ac_oauth_finish_join',[id,lease,'joined']),false);
    assert.equal(await call('ac_oauth_finish_join',[id,lease,'uncertain']),true);
    assert.equal(await call('ac_oauth_finish_join',[id,lease,'joined']),false);
});

test('key rotation CAS preserves identity and rejects stale updates', async () => {
    const a=await authorization();
    const envelope=crypto.rotate(a.envelope,{authorizationId:a.id,discordId:a.discordId,clientId});
    assert.equal(await call('ac_oauth_rotate_key',[a.id,1,envelope]),2);
    await assert.rejects(call('ac_oauth_rotate_key',[a.id,1,a.envelope]), /CONFLICT/);
    const updated=await call('ac_oauth_get_authorization',[a.id]);assert.equal(updated.discord_id,a.discordId);
    assert.deepEqual(updated.envelope,envelope);
});

async function pendingCallback(a = null) {
    const f=await flow();
    assert.equal(await call('ac_oauth_claim_callback',[f.id,f.session,f.state,guild]),true);
    const id=a?.id || randomUUID(), discordId=a?.discordId || String(9000000000000000100n + serial++);
    const envelope=crypto.encrypt({access_token:randomUUID(),refresh_token:randomUUID()}, {authorizationId:id,discordId,clientId});
    return { f,id, args:[id,a ? (await call('ac_oauth_get_authorization',[id])).version : null,discordId,clientId,envelope,
        new Date(Date.now()+3600000).toISOString(),['identify','guilds.join'],randomUUID(),f.id,f.session,f.state,guild,2592000] };
}

test('callback atomically commits encrypted authorization and 30-day consent; replay rolls back', async () => {
    const p=await pendingCallback();
    assert.equal(await call('ac_oauth_claim_callback',[p.f.id,p.f.session,p.f.state,guild]),false);
    assert.equal(await call('ac_oauth_complete_callback',p.args),p.id);
    const c=(await query('SELECT status,extract(epoch FROM expires_at-granted_at)::float8 AS lifetime FROM private.guild_consents WHERE id=$1',[p.args[7]]))[0];
    assert.equal(c.status,'active');assert.ok(Math.abs(c.lifetime-2592000)<1);
    await assert.rejects(call('ac_oauth_complete_callback',p.args));
    assert.equal((await call('ac_oauth_get_authorization',[p.id])).version,1);
    assert.equal((await query('SELECT count(*)::int AS n FROM public.auth_users'))[0].n,1);
});

test('wrong destination, missing scope and expired callback leave no authorization or consent', async () => {
    for (const kind of ['destination','scope','expired']) {
        const p=await pendingCallback();
        if(kind==='destination') p.args[11]='9000000000000000099';
        if(kind==='scope') p.args[6]=['identify'];
        if(kind==='expired') await db.query("UPDATE private.oauth_flows SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",[p.f.id]);
        await assert.rejects(call('ac_oauth_complete_callback',p.args));
        assert.equal(await call('ac_oauth_get_authorization',[p.id]),null);
        assert.equal((await query('SELECT count(*)::int AS n FROM private.guild_consents WHERE id=$1',[p.args[7]]))[0].n,0);
    }
});

test('reauthorization failure rolls back credentials; successful reauthorization uses current version', async () => {
    const a=await authorization(), c=await consent(a), p=await pendingCallback(a);
    p.args[7]=c.id;
    await assert.rejects(call('ac_oauth_complete_callback',p.args), /unique constraint/);
    assert.deepEqual((await call('ac_oauth_get_authorization',[a.id])).envelope,a.envelope);
    p.args[7]=randomUUID();
    assert.equal(await call('ac_oauth_complete_callback',p.args),a.id);
    assert.equal((await call('ac_oauth_get_authorization',[a.id])).version,2);
    assert.equal((await query('SELECT status FROM private.guild_consents WHERE id=$1',[c.id]))[0].status,'revoked');
});

test('revocation blocks use before provider confirmation, rejects stale refresh and retains recoverable ciphertext', async () => {
    const a=await authorization(), c=await consent(a), lease=randomUUID();
    const refresh=await call('ac_oauth_claim_refresh',[a.id,1,lease]);
    const pending=await call('ac_oauth_begin_revocation',[a.id]);
    assert.equal(pending.status,'revocation_pending');assert.deepEqual(pending.envelope,a.envelope);
    assert.equal((await call('ac_oauth_list_eligible',[guild,clientId,100])).some(r=>r.consent_id===c.id),false);
    await assert.rejects(call('ac_oauth_begin_revocation',[a.id]),/CONFLICT/);
    await assert.rejects(call('ac_oauth_finish_refresh',[a.id,refresh.version,lease,a.envelope,new Date(Date.now()+3600000).toISOString(),['identify','guilds.join']]),/CONFLICT/);
    await assert.rejects(call('ac_oauth_finish_revocation',[a.id,pending.version-1]),/CONFLICT/);
    const p=await pendingCallback(a);await assert.rejects(call('ac_oauth_complete_callback',p.args),/CONFLICT/);
    await db.query("UPDATE private.oauth_authorizations SET refresh_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[a.id]);
    const retry=await call('ac_oauth_begin_revocation',[a.id]);
    await assert.rejects(call('ac_oauth_finish_revocation',[a.id,pending.version]),/CONFLICT/);
    assert.equal(await call('ac_oauth_finish_revocation',[a.id,retry.version]),true);
    assert.equal((await call('ac_oauth_get_authorization',[a.id])).envelope,null);
});

async function observedGuild() {
    const target=String(9000000000000001000n+serial++), observer=randomUUID();
    assert.equal(await call('ac_oauth_watch_guild',[target,clientId,observer,true]),true);
    const a=await authorization(), c=await consent(a,await flow(target));
    return {target,observer,a,c};
}
const reserveArgs = o => [randomUUID(),o.c.id,o.target,clientId,randomUUID(),o.observer];

test('guarded join atomically reserves consent once and emits a single dispatch permit', async () => {
    const o=await observedGuild(), first=reserveArgs(o), second=reserveArgs(o);
    const results=await Promise.allSettled([call('ac_oauth_reserve_member',first),call('ac_oauth_reserve_member',second)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    const args=results[0].status==='fulfilled'?first:second;
    const a=await call('ac_oauth_dispatch_member',[args[0],args[4],o.observer,o.target,clientId]);
    assert.equal(a.id,o.a.id);
    await assert.rejects(call('ac_oauth_dispatch_member',[args[0],args[4],o.observer,o.target,clientId]),/OPERATION_UNAVAILABLE/);
    assert.equal(await call('ac_oauth_finish_member',[args[0],args[4],'pending',null,201,0]),true);
    assert.equal(await call('ac_oauth_finish_member',[args[0],args[4],'joined',null,201,0]),false);
});

test('departure invalidates existing and in-flight consent; only a new flow can authorize again', async () => {
    const o=await observedGuild(), args=reserveArgs(o);
    await call('ac_oauth_reserve_member',args);
    await call('ac_oauth_record_departure',[o.target,clientId,o.a.discordId]);
    await assert.rejects(call('ac_oauth_dispatch_member',[args[0],args[4],o.observer,o.target,clientId]),/OPERATION_UNAVAILABLE/);
    const rows=await query('SELECT * FROM public.ac_oauth_join_candidates($1,$2,$3,$4)',[o.target,clientId,o.observer,100]);
    assert.equal(rows.length,0);
    const c=await consent(o.a,await flow(o.target));
    const next=await query('SELECT * FROM public.ac_oauth_join_candidates($1,$2,$3,$4)',[o.target,clientId,o.observer,100]);
    assert.equal(next[0].consent_id,c.id);
});

test('gateway gap invalidates earlier flows, including callbacks completed after recovery', async () => {
    const o=await observedGuild(), early=await flow(o.target);
    await call('ac_oauth_pause_guild',[o.target,clientId,o.observer]);
    await assert.rejects(call('ac_oauth_reserve_member',reserveArgs(o)),/OBSERVATION_UNAVAILABLE/);
    await call('ac_oauth_watch_guild',[o.target,clientId,o.observer,true]);
    const c=await consent(o.a,early);
    const rows=await query('SELECT * FROM public.ac_oauth_join_candidates($1,$2,$3,$4)',[o.target,clientId,o.observer,100]);
    assert.equal(rows.length,0);
    await assert.rejects(call('ac_oauth_reserve_member',[randomUUID(),c.id,o.target,clientId,randomUUID(),o.observer]),/CONSENT_UNAVAILABLE/);
    const fresh=await consent(o.a,await flow(o.target));
    assert.ok(await call('ac_oauth_reserve_member',[randomUUID(),fresh.id,o.target,clientId,randomUUID(),o.observer]));
});

test('consent absent, expired, revoked, wrong destination, missing scope and expired access cannot reserve', async () => {
    for (const kind of ['absent','expired','revoked','destination','scope','access']) {
        const o=await observedGuild(), args=reserveArgs(o);
        if(kind==='absent')args[1]=randomUUID();
        if(kind==='expired')await db.query("UPDATE private.guild_consents SET granted_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",[o.c.id]);
        if(kind==='revoked')await call('ac_oauth_revoke_consent',[o.c.id]);
        if(kind==='destination')args[2]=guild;
        if(kind==='scope')await db.query("UPDATE private.oauth_authorizations SET scopes=ARRAY['identify'] WHERE id=$1",[o.a.id]);
        if(kind==='access')await db.query("UPDATE private.oauth_authorizations SET access_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[o.a.id]);
        await assert.rejects(call('ac_oauth_reserve_member',args));
    }
});

test('candidate list permits refresh but dispatch rechecks revocation and expiry', async () => {
    const o=await observedGuild();
    await db.query("UPDATE private.oauth_authorizations SET access_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[o.a.id]);
    assert.equal((await query('SELECT * FROM public.ac_oauth_join_candidates($1,$2,$3,$4)',[o.target,clientId,o.observer,100])).length,1);
    await db.query("UPDATE private.oauth_authorizations SET access_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",[o.a.id]);
    const args=reserveArgs(o);await call('ac_oauth_reserve_member',args);
    await call('ac_oauth_begin_revocation',[o.a.id]);
    await assert.rejects(call('ac_oauth_dispatch_member',[args[0],args[4],o.observer,o.target,clientId]),/AUTHORIZATION_UNAVAILABLE/);
});

test('rate-limit cooldown is durable and observation ownership is exclusive', async () => {
    const o=await observedGuild(), args=reserveArgs(o);
    assert.equal(await call('ac_oauth_watch_guild',[o.target,clientId,randomUUID(),true]),false);
    await call('ac_oauth_reserve_member',args);
    assert.equal(await call('ac_oauth_finish_member',[args[0],args[4],'failed','rate_limited',429,120]),true);
    const c=await consent(o.a,await flow(o.target));
    await assert.rejects(call('ac_oauth_reserve_member',[randomUUID(),c.id,o.target,clientId,randomUUID(),o.observer]),/OBSERVATION_UNAVAILABLE/);
    assert.equal((await query('SELECT * FROM public.ac_oauth_join_candidates($1,$2,$3,$4)',[o.target,clientId,o.observer,100])).length,0);
    const stored=(await query('SELECT failure_code,http_status FROM private.member_join_operations WHERE id=$1',[args[0]]))[0];
    assert.deepEqual(stored,{failure_code:'rate_limited',http_status:429});
});

const owner='9000000000000000080',delegate='9000000000000000081';
async function configuredGuild() {
    const guildId=String(9000000000000003000n+serial++);
    await call('ac_guild_sync_owner',[guildId,owner]);
    await call('ac_guild_save',[guildId,owner,1,'9000000000000000090','9000000000000000091','Mensagem fictícia',true,[delegate]]);
    return guildId;
}
async function tenantPayload(guildId) {
    const id=randomUUID(),discordId=String(9000000000000004000n+serial++),flowId=randomUUID(),session=hash(),state=hash();
    const config=await call('ac_guild_get',[guildId,owner]);
    await call('ac_guild_create_flow',[flowId,session,state,guildId,guildId,discordId,config.version,'guild-join-v1']);
    await call('ac_oauth_claim_callback',[flowId,session,state,guildId]);
    return{id,version:null,discord_id:discordId,client_id:clientId,envelope:crypto.encrypt({access_token:randomUUID(),refresh_token:randomUUID()},
        {authorizationId:id,discordId,clientId}),expires_at:new Date(Date.now()+3600000).toISOString(),scopes:['identify','guilds.join'],
        consent_id:randomUUID(),flow_id:flowId,session_hash:session,state_hash:state,guild_id:guildId,valid_seconds:2592000,username:'synthetic-profile',avatar:null};
}

test('guild configuration enforces owner/delegate scope, CAS and owner transfer reset',async()=>{
    const a=await configuredGuild(),b=await configuredGuild();
    await call('ac_guild_save',[b,owner,2,null,null,'B',true,[]]);
    assert.equal((await call('ac_guild_get',[a,delegate])).guild_id,a);
    await assert.rejects(call('ac_guild_get',[b,delegate]),/PERMISSION/);
    await assert.rejects(call('ac_guild_save',[a,delegate,2,null,null,'A',true,[delegate]]),/PERMISSION/);
    assert.equal(await call('ac_guild_save',[a,delegate,2,null,null,'A',true,null]),3);
    await assert.rejects(call('ac_guild_save',[a,owner,2,null,null,'stale',true,[]]),/CONFLICT/);
    await call('ac_guild_sync_owner',[a,'9000000000000000082']);
    await assert.rejects(call('ac_guild_get',[a,owner]),/PERMISSION/);
    assert.equal(await call('ac_guild_public',[a]),null);
});

test('tenant callback atomically persists profile and two unique effects with isolated destinations',async()=>{
    const guildId=await configuredGuild(),p=await tenantPayload(guildId);
    assert.equal(await call('ac_guild_complete',[p]),p.id);
    assert.deepEqual(await query('SELECT username,avatar FROM public.auth_users WHERE discord_id=$1',[p.discord_id]),[{username:'synthetic-profile',avatar:null}]);
    const jobs=await query('SELECT guild_id,kind FROM private.verification_effects WHERE flow_id=$1 ORDER BY kind',[p.flow_id]);
    assert.deepEqual(jobs,[{guild_id:guildId,kind:'log'},{guild_id:guildId,kind:'role'}]);
    await assert.rejects(call('ac_guild_complete',[p]));
    assert.equal((await query('SELECT count(*)::int AS n FROM private.verification_effects WHERE flow_id=$1',[p.flow_id]))[0].n,2);
    const f=randomUUID(),session=hash(),state=hash();
    await call('ac_guild_create_flow',[f,session,state,guildId,guildId,p.discord_id,2,'guild-join-v1']);
    await call('ac_oauth_claim_callback',[f,session,state,guildId]);
    await call('ac_guild_complete',[{...p,version:1,flow_id:f,consent_id:randomUUID(),session_hash:session,state_hash:state,username:'updated-synthetic'}]);
    assert.deepEqual(await query('SELECT username FROM public.auth_users WHERE discord_id=$1',[p.discord_id]),[{username:'updated-synthetic'}]);
    const names=await query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='auth_users' ORDER BY ordinal_position");
    assert.deepEqual(names.map(r=>r.column_name),['discord_id','username','avatar','verified_at','updated_at']);
});

test('cross-guild, wrong identity and stale settings callbacks cannot save any profile',async()=>{
    const guildId=await configuredGuild(),other=await configuredGuild();
    for(const kind of ['guild','identity','version']){
        const p=await tenantPayload(guildId);
        if(kind==='guild')p.guild_id=other;
        if(kind==='identity')p.discord_id='9000000000000000999';
        if(kind==='version')await call('ac_guild_save',[guildId,owner,2,null,null,'changed',true,[]]);
        await assert.rejects(call('ac_guild_complete',[p]),/FLOW_INVALID/);
        assert.equal(await call('ac_oauth_get_authorization',[p.id]),null);
        assert.equal((await query('SELECT count(*)::int AS n FROM public.auth_users WHERE discord_id=$1',[p.discord_id]))[0].n,0);
    }
});

test('profile write failure rolls back authorization, consent and outbox together',async()=>{
    const p=await tenantPayload(await configuredGuild());
    await db.exec("CREATE FUNCTION public.test_profile_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SIMULATED_FAILURE'; END $$; CREATE TRIGGER test_profile_failure BEFORE INSERT ON public.auth_users FOR EACH ROW EXECUTE FUNCTION public.test_profile_failure();");
    try{await assert.rejects(call('ac_guild_complete',[p]),/SIMULATED_FAILURE/);}
    finally{await db.exec('DROP TRIGGER test_profile_failure ON public.auth_users; DROP FUNCTION public.test_profile_failure();');}
    assert.equal(await call('ac_oauth_get_authorization',[p.id]),null);
    assert.equal((await query('SELECT consumed_at FROM private.oauth_flows WHERE id=$1',[p.flow_id]))[0].consumed_at,null);
    assert.equal((await query('SELECT count(*)::int AS n FROM private.verification_effects WHERE flow_id=$1',[p.flow_id]))[0].n,0);
});

test('effect leases recover after restart, reject stale completions and cancel changed settings',async()=>{
    await db.exec("UPDATE private.verification_effects SET status='done'");
    const p=await tenantPayload(await configuredGuild());await call('ac_guild_complete',[p]);
    const leases=[randomUUID(),randomUUID()];
    const jobs=await Promise.all(leases.map(l=>call('ac_guild_claim_effect',[l])));
    assert.notEqual(jobs[0].id,jobs[1].id);
    assert.equal(await call('ac_guild_claim_effect',[randomUUID()]),null);
    await db.query("UPDATE private.verification_effects SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",[jobs[0].id]);
    const nextLease=randomUUID(),recovered=await call('ac_guild_claim_effect',[nextLease]);assert.equal(recovered.id,jobs[0].id);
    assert.equal(await call('ac_guild_finish_effect',[recovered.id,leases[0],'done',null,null,0]),false);
    await call('ac_guild_save',[p.guild_id,owner,2,null,null,'changed',true,[]]);
    assert.equal(await call('ac_guild_dispatch_effect',[recovered.id,nextLease]),false);
    assert.equal((await query('SELECT status FROM private.verification_effects WHERE id=$1',[recovered.id]))[0].status,'cancelled');
});

test('ambiguous old log is not resent after restart; nonce and effect identity stay stable',async()=>{
    await db.exec("UPDATE private.verification_effects SET status='done'");
    const p=await tenantPayload(await configuredGuild());await call('ac_guild_complete',[p]);
    await db.exec("UPDATE private.verification_effects SET status='done' WHERE kind='role'");
    const lease=randomUUID(),job=await call('ac_guild_claim_effect',[lease]);assert.equal(job.kind,'log');
    assert.equal(await call('ac_guild_dispatch_effect',[job.id,lease]),true);
    await db.query("UPDATE private.verification_effects SET lease_until=clock_timestamp()-interval '1 second',first_sent_at=clock_timestamp()-interval '3 minutes' WHERE id=$1",[job.id]);
    assert.equal(await call('ac_guild_claim_effect',[randomUUID()]),null);
    const stored=(await query('SELECT status,nonce FROM private.verification_effects WHERE id=$1',[job.id]))[0];
    assert.equal(stored.status,'uncertain');assert.equal(stored.nonce,job.nonce);
});
