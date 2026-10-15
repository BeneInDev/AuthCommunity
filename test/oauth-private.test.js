const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const express = require('express');
const { createConsentState } = require('../src/web/oauth-consent-state');
const { createOAuthLifecycle, tokenData } = require('../src/security/oauth-lifecycle');
const { createOAuthRepositories } = require('../src/database/oauth-repositories');
const { createOAuthTokenCrypto } = require('../src/security/oauth-token-crypto');
const register = require('../src/web/server');
const env = () => ({ CLIENT_ID:'9000000000000000001', GUILD_ID:'9000000000000000002',
    CLIENT_SECRET: randomBytes(32).toString('base64url'), OAUTH_STATE_SECRET:randomBytes(32).toString('base64url'),
    REDIRECT_URI:'https://example.test/oauth2/callback', OAUTH_PRIVATE_ENABLED:'true' });
const tokenResponse = () => ({ access_token:randomBytes(32).toString('base64url'),refresh_token:randomBytes(32).toString('base64url'),
    token_type:'Bearer',expires_in:3600,scope:'identify guilds.join' });

function browser(state) {
    const req={ headers:{ origin:'https://example.test' },body:{accepted:'yes'},query:{} };
    const res={ cookie:(name,value,options)=>{ assert.equal(options.secure,true);assert.equal(options.httpOnly,true);req.headers.cookie=`${name}=${value}`; }, clearCookie:()=>{} };
    req.body.state=state.start(res);
    return {req,res};
}

test('consent state binds browser, destination and stage; denies tampering, CSRF, missing checkbox and expiry', () => {
    const config=env();let now=Date.now();const state=createConsentState({env:config,now:()=>now});
    const b=browser(state), original=b.req.body.state;
    assert.throws(()=>state.accept({...b.req,headers:{...b.req.headers,origin:'https://attacker.invalid'}}));
    assert.throws(()=>state.accept({...b.req,body:{state:original}}));
    assert.throws(()=>state.accept({...b.req,body:{...b.req.body,state:`x${original}`}}));
    const other=browser(state);assert.throws(()=>state.accept({...b.req,headers:other.req.headers}));
    const accepted=state.accept(b.req), oauth=new URL(accepted.url).searchParams;
    assert.equal(oauth.get('scope'),'identify guilds.join');assert.equal(accepted.validSeconds,2592000);
    b.req.query={code:'synthetic-code',state:oauth.get('state')};
    assert.equal(state.callback(b.req,b.res).guildId,config.GUILD_ID);
    assert.equal(createConsentState({env:config,now:()=>now}).callback(b.req,b.res).guildId,config.GUILD_ID);
    assert.throws(()=>state.callback({...b.req,headers:{...b.req.headers,cookie:`${b.req.headers.cookie}; ${b.req.headers.cookie}`}},b.res));
    assert.throws(()=>state.callback({...b.req,query:{...b.req.query,guild_id:'9000000000000000003'}},b.res));
    assert.throws(()=>state.callback({...b.req,query:{code:'synthetic-code',state:original}},b.res));
    const different=createConsentState({env:{...config,GUILD_ID:'9000000000000000003'},now:()=>now});
    assert.throws(()=>different.callback(b.req,b.res));
    now+=600001;assert.throws(()=>state.callback(b.req,b.res));
});

test('private configuration requires independent secret and bounded consent lifetime', () => {
    for(const update of [{OAUTH_STATE_SECRET:''},{CLIENT_SECRET:''},{OAUTH_CONSENT_DAYS:'0'},{OAUTH_CONSENT_DAYS:'91'},{OAUTH_CONSENT_DAYS:'NaN'}]) {
        assert.throws(()=>createConsentState({env:{...env(),...update}}));
    }
    assert.equal(createConsentState({env:{...env(),OAUTH_CONSENT_DAYS:'7'}}).days,7);
});

test('token metadata uses actually granted scopes and rejects missing grants or invalid expiry', () => {
    const response=tokenResponse();response.scope+=' connections';
    const parsed=tokenData(response,0);assert.equal(parsed.expiresAt,'1970-01-01T01:00:00.000Z');
    assert.deepEqual(parsed.scopes,['identify','guilds.join','connections']);
    for(const update of [{scope:'identify'},{expires_in:-1},{expires_in:'3600'},{scope:null},{refresh_token:''}]) assert.throws(()=>tokenData({...response,...update}));
});

test('callback encrypts tokens through repository and never retries a claimed code', async () => {
    const config=env(), crypto=createOAuthTokenCrypto({keys:{test:randomBytes(32).toString('base64url')},activeKeyId:'test'});
    const captured=[];let claimed=false;
    const client={schema:()=>({rpc:(name,params)=>({retry:retry=>{assert.equal(retry,false);return{abortSignal:async signal=>{
        assert.ok(signal instanceof AbortSignal);captured.push({name,params});
        if(name==='ac_oauth_claim_callback'){const data=!claimed;claimed=true;return{data};}
        if(name==='ac_oauth_find_authorization')return{data:null};
        return {data:params.p_id};
    }};}})})};
    const repositories=createOAuthRepositories({client,crypto}), response=tokenResponse();let exchanges=0;
    const http={post:async(_url,_body,options)=>{exchanges++;assert.equal(options.timeout,10000);assert.equal(options.maxRedirects,0);return{data:response};},
        get:async()=>({data:{id:'9000000000000000000'}})};
    const service=createOAuthLifecycle({repositories,http,env:config});
    const flow={id:randomUUID(),guildId:config.GUILD_ID,sessionHash:'a'.repeat(64),stateHash:'b'.repeat(64),validSeconds:2592000};
    const result=await service.complete(flow,'synthetic-code');
    const write=captured.find(c=>c.name==='ac_oauth_complete_callback').params;
    assert.equal(JSON.stringify(captured).includes(response.access_token),false);
    assert.equal(JSON.stringify(captured).includes(response.refresh_token),false);
    assert.equal(crypto.decrypt(write.p_envelope,{authorizationId:result.authorizationId,discordId:write.p_discord_id,clientId:config.CLIENT_ID}).access_token,response.access_token);
    await assert.rejects(service.complete(flow,'synthetic-code'),{message:'OAUTH_VERIFICATION_FAILED'});assert.equal(exchanges,1);
});

test('refresh persists rotated tokens, while provider/persistence failures block further reuse', async () => {
    for(const failure of [null,'provider','database']) {
        const config=env(), response=tokenResponse(), events=[];
        const record={id:randomUUID(),client_id:config.CLIENT_ID,version:2,status:'active'};
        const repositories={authorizations:{get:async()=>({...record,version:1}),claimRefresh:async()=>record,
            decrypt:()=>({refresh_token:response.refresh_token}),finishRefresh:async(_record,_lease,tokens,expiry,scopes)=>{
                events.push('persist');assert.equal(tokens.access_token,response.access_token);assert.ok(expiry);assert.deepEqual(scopes,['identify','guilds.join']);
                if(failure==='database')throw new Error('private provider data');return 3;},abandonRefresh:async()=>events.push('abandon')}};
        const service=createOAuthLifecycle({repositories,env:config,http:{post:async(_url,body,options)=>{
            events.push('provider');assert.equal(body.get('grant_type'),'refresh_token');assert.equal(options.timeout,10000);
            if(failure==='provider')throw new Error('private provider data');return{data:response};}}});
        if(failure){await assert.rejects(service.refresh(record.id),{message:'OAUTH_REFRESH_FAILED'});assert.equal(events.at(-1),'abandon');}
        else assert.deepEqual(await service.refresh(record.id),{version:3});
    }
});

test('revocation blocks locally before Discord and only erases after confirmation; errors remain pending', async () => {
    for(const failure of [null,'provider','database']) {
        const config=env(), events=[], record={id:randomUUID(),client_id:config.CLIENT_ID,version:2,status:'revocation_pending'};
        const repositories={authorizations:{get:async()=>record,beginRevocation:async()=>{events.push('block');return record;},
            decrypt:()=>({access_token:'synthetic-access',refresh_token:'synthetic-refresh'}),finishRevocation:async()=>{
                events.push('erase');if(failure==='database')throw new Error('sensitive');return true;}}};
        const service=createOAuthLifecycle({repositories,env:config,http:{post:async(url,body,options)=>{
            events.push('discord');assert.ok(url.endsWith('/token/revoke'));assert.equal(body.get('token_type_hint'),'refresh_token');assert.equal(options.maxRedirects,0);
            if(failure==='provider')throw new Error('sensitive');return{data:{}};}}});
        if(failure)await assert.rejects(service.revoke(record.id),{message:'OAUTH_REVOCATION_PENDING'});
        else await service.revoke(record.id);
        assert.deepEqual(events,failure==='provider'?['block','discord']:['block','discord','erase']);
    }
});

async function webFixture(t, failure) {
    const config=env(), app=express();let exchanges=0, writes=0;
    const flows=new Map();
    const repositories={flows:{create:async f=>{if(failure==='create')throw new Error('sensitive');if(flows.has(f.id))throw new Error();flows.set(f.id,{...f});return f.id;},
        claimCallback:async f=>{const stored=flows.get(f.id);if(!stored||stored.claimed||stored.stateHash!==f.stateHash||stored.sessionHash!==f.sessionHash)return false;stored.claimed=true;return true;},
        complete:async data=>{writes++;if(failure==='persist')throw new Error('sensitive');return data.id;}},authorizations:{find:async()=>null}};
    register(app,{guilds:{cache:new Map([[config.GUILD_ID,{name:'<script>untrusted</script>'}]])}}, {
        env:config,oauthRepositories:repositories,database:{users:{set:()=>assert.fail('JSON fallback')},config:{get:()=>undefined}},
        verifiedUsers:{saveVerification:()=>assert.fail('legacy persistence')},
        http:{post:async()=>{exchanges++;return{data:tokenResponse()};},get:async()=>({data:{id:'9000000000000000000'}})} });
    const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
    const url=`http://127.0.0.1:${server.address().port}`;
    const request=async(path,options={})=>fetch(url+path,{redirect:'manual',...options});
    return{request,config,counts:()=>({exchanges,writes})};
}

test('opt-in real Express flow escapes destination, requires consent and does not reach legacy routes', async t => {
    const f=await webFixture(t);const start=await f.request('/oauth2/start');const html=await start.text();
    assert.equal(start.status,200);assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));
    assert.ok(html.includes('30 dias'));assert.ok(!html.includes('checked'));
    const cookie=start.headers.get('set-cookie').split(';')[0],state=/name="state" value="([^"]+)"/.exec(html)[1];
    const headers={cookie,origin:'https://example.test','content-type':'application/x-www-form-urlencoded'};
    const missing=await f.request('/oauth2/consent',{method:'POST',headers,body:new URLSearchParams({state})});assert.equal(missing.status,400);
    const accepted=await f.request('/oauth2/consent',{method:'POST',headers,body:new URLSearchParams({state,accepted:'yes'})});assert.equal(accepted.status,303);
    const callbackState=new URL(accepted.headers.get('location')).searchParams.get('state');
    const path='/oauth2/callback?'+new URLSearchParams({code:'synthetic-code',state:callbackState});
    const done=await f.request(path,{headers:{cookie}});assert.equal(done.status,200);assert.ok((await done.text()).includes('Autorização e consentimento registrados'));
    const replay=await f.request(path,{headers:{cookie}});assert.equal(replay.status,400);assert.deepEqual(f.counts(),{exchanges:1,writes:1});
    assert.equal((await f.request('/oauth2/start?guild_id=9000000000000000003')).status,400);
});

test('opt-in callback persistence failure returns generic failure without success or JSON fallback', async t => {
    const f=await webFixture(t,'persist'),start=await f.request('/oauth2/start'),html=await start.text();
    const cookie=start.headers.get('set-cookie').split(';')[0],state=/name="state" value="([^"]+)"/.exec(html)[1];
    const accepted=await f.request('/oauth2/consent',{method:'POST',headers:{cookie,origin:'https://example.test','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({state,accepted:'yes'})});
    const oauth=new URL(accepted.headers.get('location')).searchParams.get('state');
    const result=await f.request('/oauth2/callback?'+new URLSearchParams({state:oauth,code:'synthetic-code'}),{headers:{cookie}});
    assert.equal(result.status,400);assert.equal((await result.text()).includes('sensitive'),false);assert.equal(f.counts().writes,1);
});

test('failed consent storage and denied callbacks never exchange a code', async t => {
    const f=await webFixture(t,'create'),start=await f.request('/oauth2/start'),html=await start.text();
    const cookie=start.headers.get('set-cookie').split(';')[0],state=/name="state" value="([^"]+)"/.exec(html)[1];
    const failed=await f.request('/oauth2/consent',{method:'POST',headers:{cookie,origin:'https://example.test','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({state,accepted:'yes'})});
    assert.equal(failed.status,400);assert.equal(failed.headers.get('location'),null);
    const denied=await f.request('/oauth2/callback?error=access_denied',{headers:{cookie}});
    assert.equal(denied.status,400);assert.deepEqual(f.counts(),{exchanges:0,writes:0});
});

test('disabled private flow does not initialize its repositories or require new secrets', () => {
    const paths=[];
    for(const flag of [undefined,'false']) {
        const dependencies={env:{OAUTH_PRIVATE_ENABLED:flag},database:{users:{},config:{}},verifiedUsers:{},oauthState:{}};
        Object.defineProperty(dependencies,'oauthRepositories',{get:()=>assert.fail('private repositories initialized')});
        register({get:path=>paths.push(path)}, {}, dependencies);
    }
    assert.equal(paths.filter(p=>p==='/oauth2/start').length,2);
    assert.throws(()=>register({},{},{env:{OAUTH_PRIVATE_ENABLED:'typo'},database:{}}),{message:'OAUTH_CONFIGURATION_INVALID'});
});
