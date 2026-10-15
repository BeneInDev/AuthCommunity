const {test}=require('node:test');
const assert=require('node:assert/strict');
const {randomBytes,randomUUID}=require('node:crypto');
const {createGuildLinks}=require('../src/guilds/links');
const {createConsentState}=require('../src/web/oauth-consent-state');
const {createEffectsWorker}=require('../src/guilds/effects');
const {createOAuthLifecycle}=require('../src/security/oauth-lifecycle');
const {handle,handles}=require('../src/guilds/interactions');
const {enabled}=require('../src/guilds/runtime');
const express=require('express');
const register=require('../src/web/server');
const guild='9000000000000000002',other='9000000000000000003',user='9000000000000000004';
const env=()=>({CLIENT_ID:'9000000000000000001',CLIENT_SECRET:randomBytes(32).toString('base64url'),TOKEN:'synthetic-bot',
    OAUTH_STATE_SECRET:randomBytes(32).toString('base64url'),REDIRECT_URI:'https://example.test/oauth2/callback',OAUTH_PRIVATE_ENABLED:'true',OAUTH_MULTIGUILD_ENABLED:'true'});

test('guild tickets bind origin and subject, reject modification and expire',()=>{
    let now=Date.now();const links=createGuildLinks(env(),()=>now),ticket=new URL(links.issue(guild,user)).searchParams.get('ticket');
    assert.equal(links.read(ticket).subjectId,user);assert.equal(links.read(ticket).originGuildId,guild);
    assert.throws(()=>links.read(`x${ticket}`));now+=300001;assert.throws(()=>links.read(ticket));
});

test('multiguild state binds both guild and actor and cannot cross legacy state domain',()=>{
    const config=env(),state=createConsentState({env:config,multi:true}),req={headers:{origin:'https://example.test'},body:{accepted:'yes'},query:{}};
    const res={cookie:(name,value)=>{req.headers.cookie=`${name}=${value}`;},clearCookie:()=>{}};
    req.body.state=state.start(res,{guildId:guild,originGuildId:guild,subjectId:user,configVersion:1});
    const flow=state.accept(req);req.query={code:'synthetic-code',state:new URL(flow.url).searchParams.get('state')};
    assert.equal(state.callback(req,res).subjectId,user);
    assert.throws(()=>createConsentState({env:{...config,GUILD_ID:guild}}).callback(req,res));
    const [payload,signature]=req.query.state.split('.'),data=JSON.parse(Buffer.from(payload,'base64url').toString());data.guildId=other;
    req.query.state=`${Buffer.from(JSON.stringify(data)).toString('base64url')}.${signature}`;assert.throws(()=>state.callback(req,res));
});

test('callback verifies account binding before persisting tenant profile',async()=>{
    for(const mismatch of [false,true]) {
        let writes=0;const config=env(),data={access_token:randomUUID(),refresh_token:randomUUID(),expires_in:3600,scope:'identify guilds.join',token_type:'Bearer'};
        const repo={flows:{claimCallback:async()=>true,complete:()=>assert.fail('old persistence')},authorizations:{find:async()=>null},guilds:{complete:async p=>{writes++;assert.equal(p.profile.username,'synthetic');return p.id;}}};
        const service=createOAuthLifecycle({repositories:repo,env:config,http:{post:async()=>({data}),get:async()=>({data:{id:mismatch?other:user,username:'synthetic',avatar:null,email:'not-persisted'}})}});
        const result=service.complete({id:randomUUID(),guildId:guild,originGuildId:guild,subjectId:user},'code');
        if(mismatch){await assert.rejects(result,{message:'OAUTH_VERIFICATION_FAILED'});assert.equal(writes,0);}else{await result;assert.equal(writes,1);}
    }
});

function effects(kind,options={}) {
    const job={id:randomUUID(),guild_id:guild,discord_id:user,kind,target_id:'9000000000000000090',nonce:'synthetic-stable-nonce',attempts:1};
    let available=true;const calls=[],results=[];
    const repositories={effects:{claim:async()=>{if(!available)return null;available=false;return job;},dispatch:async()=>{calls.push('dispatch');return !options.changed;},
        finish:async result=>{results.push(result);if(options.finishFails)throw new Error('private');return true;}}};
    const http={get:async(url,request)=>{assert.equal(request.timeout,10000);assert.equal(request.maxRedirects,0);
        if(url.includes('/members/'))return options.member||{status:200,data:{roles:options.hasRole?[job.target_id]:[],pending:false}};
        return{status:200,data:{guild_id:options.foreign?other:guild}};},
        put:async()=>{calls.push('role');if(options.timeout)throw new Error('private');return{status:204};},
        post:async(_url,body)=>{calls.push(body);assert.equal(body.enforce_nonce,true);assert.equal(body.nonce,job.nonce);
            assert.equal(JSON.stringify(body).includes(user),false);if(options.timeout)throw new Error('private');return{status:200,data:{id:'9000000000000000088'}};}};
    return{worker:createEffectsWorker({repositories,http,env:env()}),calls,results,job};
}
test('role effect is idempotent and requires confirmed presence without screening',async()=>{
    for(const options of [{},{hasRole:true},{member:{status:404}},{member:{status:200,data:{pending:true}}}]){
        const f=effects('role',options);await f.worker.tick();
        assert.equal(f.calls.includes('role'),!options.hasRole&&!options.member);
        assert.equal(f.results[0].status,options.member?'pending':'done');
    }
});
test('logs use stable nonce, suppress mentions and reject channels from other guilds',async()=>{
    const f=effects('log');await f.worker.tick();assert.equal(f.results[0].status,'done');
    assert.deepEqual(f.calls.find(c=>typeof c==='object').allowed_mentions,{parse:[]});
    const foreign=effects('log',{foreign:true});await foreign.worker.tick();assert.equal(foreign.results[0].status,'failed');assert.equal(foreign.calls.length,1);
});
test('partial failures persist retry state; stale configuration never executes Discord writes',async()=>{
    const f=effects('log',{timeout:true});await f.worker.tick();assert.equal(f.results[0].status,'pending');assert.equal(f.results[0].code,'transport_unknown');
    const changed=effects('role',{changed:true});await changed.worker.tick();assert.deepEqual(changed.calls,['dispatch']);
    const lost=effects('role',{finishFails:true});await assert.rejects(lost.worker.tick());assert.equal(lost.calls.filter(c=>c==='role').length,1);
});
test('worker overlapping ticks cannot process the same local job twice',async()=>{
    const f=effects('role');await Promise.all([f.worker.tick(),f.worker.tick()]);assert.equal(f.calls.filter(c=>c==='role').length,1);
});

test('guild admin modal cannot switch guild through its custom ID or read foreign settings',async()=>{
    const replies=[],saves=[];const interaction={guildId:guild,guild:{id:guild},user:{id:user},customId:`guild_config:${other}:1`,
        reply:async data=>replies.push(data),fields:{getTextInputValue:()=>''}};
    const repo={guilds:{syncOwner:async id=>assert.equal(id,guild),get:async id=>{assert.equal(id,guild);return{version:1,owner_id:user};},save:async p=>saves.push(p)}};
    await handle(interaction,{}, {repositories:repo,env:env(),http:{get:async()=>({data:{id:guild,owner_id:user}})}});
    assert.equal(saves.length,0);assert.match(replies[0].content,/não autorizada/);
});
test('delegated administrator never writes administrator grants and owner controls them',async()=>{
    let saved;const replies=[],values={role:'',logs:'',message:'synthetic',active:'sim'};
    await handle({guildId:guild,guild:{id:guild},user:{id:user},customId:`guild_config:${guild}:1`,
        fields:{getTextInputValue:id=>values[id]},reply:async p=>replies.push(p)}, {},{
        env:env(),http:{get:async()=>({data:{id:guild,owner_id:other}})},repositories:{guilds:{syncOwner:async()=>true,
            get:async()=>({owner_id:other,version:1}),save:async p=>{saved=p;}}}});
    assert.equal(saved.adminIds,null);assert.equal(saved.guildId,guild);
});
test('multiguild flags are disabled by default and do not intercept puxar',()=>{
    assert.equal(enabled({}),false);assert.throws(()=>enabled({OAUTH_MULTIGUILD_ENABLED:'true'}));
    assert.equal(handles({isChatInputCommand:()=>true,commandName:'puxar'},env()),false);
});

test('configuration panel defers network work and opens a modal without another remote lookup',async()=>{
    let panel,modal;
    const interaction={guildId:guild,guild:{id:guild},user:{id:user},commandName:'configurar',deferred:false,
        deferReply:async()=>{interaction.deferred=true;},editReply:async p=>{panel=p;}};
    await handle(interaction,{}, {env:env(),http:{get:async()=>({data:{id:guild,owner_id:user}})},repositories:{guilds:{
        syncOwner:async()=>true,get:async()=>({guild_id:guild,owner_id:user,version:1,active:true,admin_ids:[],role_id:null,log_channel_id:null,verification_message:'a'.repeat(1700)})}}});
    assert.equal(panel.embeds[0].description.length,1700);
    await handle({guildId:guild,guild:{id:guild},user:{id:user},customId:`guild_open:${guild}:1`,message:{embeds:panel.embeds},
        showModal:async value=>{modal=value;},reply:()=>assert.fail('unexpected failure')},{},{env:env(),repositories:{},http:{get:()=>assert.fail('remote call before modal')}});
    assert.equal(modal.toJSON().components.length,5);
});

test('real Express tenant flow rejects guild parameters and persists only the signed account/server',async t=>{
    const config=env(),app=express(),flows=new Map();let saved;
    const repo={guilds:{public:async id=>({guild_id:id,active:true,version:1,verification_message:'<script>synthetic</script>'}),
        createFlow:async flow=>{flows.set(flow.id,flow);return flow.id;},complete:async p=>{saved=p;return p.id;}},
        authorizations:{find:async()=>null},flows:{claimCallback:async f=>{const old=flows.get(f.id);if(!old||old.used)return false;
            assert.equal(old.guildId,f.guildId);assert.equal(old.subjectId,user);old.used=true;return true;}}};
    register(app,{guilds:{cache:new Map([[guild,{name:'Synthetic guild'}]])}},{env:config,oauthRepositories:repo,
        database:{users:{set:()=>assert.fail('JSON fallback')},config:{}},verifiedUsers:{saveVerification:()=>assert.fail('legacy')},
        http:{post:async()=>({data:{access_token:randomUUID(),refresh_token:randomUUID(),token_type:'Bearer',expires_in:3600,scope:'identify guilds.join'}}),
            get:async()=>({data:{id:user,username:'synthetic',avatar:null}})}});
    const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
    const origin=`http://127.0.0.1:${server.address().port}`,request=(path,opts={})=>fetch(origin+path,{redirect:'manual',...opts});
    assert.equal((await request('/oauth2/start?guild_id='+guild)).status,400);
    const launch=new URL(createGuildLinks(config).issue(guild,user));
    const start=await request(launch.pathname+launch.search),html=await start.text();assert.equal(start.status,200);assert.ok(html.includes('&lt;script&gt;'));
    const cookie=start.headers.get('set-cookie').split(';')[0],state=/name="state" value="([^"]+)"/.exec(html)[1];
    const accept=await request('/oauth2/consent',{method:'POST',headers:{cookie,origin:'https://example.test','content-type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({state,accepted:'yes'})});assert.equal(accept.status,303);
    const callback='/oauth2/callback?'+new URLSearchParams({code:'synthetic-code',state:new URL(accept.headers.get('location')).searchParams.get('state')});
    const done=await request(callback,{headers:{cookie}});assert.equal(done.status,200);assert.equal(saved.guildId,guild);assert.equal(saved.discordId,user);
    assert.equal((await request(callback,{headers:{cookie}})).status,400);
});
