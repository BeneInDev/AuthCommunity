const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { Events } = require('discord.js');
const { createMemberJoinService } = require('../src/security/member-join-service');
const { createMemberObserver } = require('../src/security/member-observer');
const { enabled } = require('../src/security/private-members');
const env={GUILD_ID:'9000000000000000002',CLIENT_ID:'9000000000000000001',TOKEN:'synthetic-bot'};

function fixture(options={}) {
    const record={id:randomUUID(),discord_id:'9000000000000000000',client_id:env.CLIENT_ID,status:'active',scopes:['guilds.join'],
        access_expires_at:new Date(Date.now()+(options.expired?-1000:3600000)).toISOString()};
    const candidate={authorization_id:record.id,discord_id:record.discord_id,consent_id:randomUUID()};
    const calls=[],operations=[];let consumed=false, safe=true;
    const observer={id:randomUUID(),safe:()=>safe,block:()=>{safe=false;calls.push('block');}};
    const repositories={authorizations:{get:async()=>({...record}),decrypt:()=>({access_token:'synthetic-access'})},membership:{
        candidates:async()=>options.empty?[]:[candidate],
        reserve:async op=>{calls.push('reserve');if(consumed||options.reserveFails)throw new Error('private');consumed=true;return{operation_id:op.id,authorization_id:record.id,discord_id:record.discord_id};},
        dispatch:async()=>{calls.push('dispatch');if(options.dispatchFails)throw new Error('private');return{...record};},
        finish:async op=>{calls.push('finish');operations.push(op);if(options.finishFails)throw new Error('private');return true;}}};
    const lifecycle={refresh:async()=>{calls.push('refresh');if(options.refreshFails)throw new Error('private');record.access_expires_at=new Date(Date.now()+3600000).toISOString();}};
    const verifyHttp=opts=>{assert.equal(opts.timeout,10000);assert.equal(opts.maxRedirects,0);assert.ok(opts.signal instanceof AbortSignal);};
    const http={get:async(_url,opts)=>{verifyHttp(opts);calls.push('get');return options.present || {status:404,data:{code:10007}};},
        put:async(url,body,opts)=>{verifyHttp(opts);assert.ok(url.includes(env.GUILD_ID));assert.equal(body.access_token,'synthetic-access');calls.push('put');
            if(options.timeout)throw new Error('private-token');return options.response||{status:201,data:{pending:false}};}};
    const service=createMemberJoinService({repositories,lifecycle,http,observer,env});
    return{run:()=>service.run({guildId:env.GUILD_ID,amount:1}),service,calls,operations,record,observer,repositories};
}

test('authorized join refreshes expired access before reserving, dispatching and recording success',async()=>{
    const f=fixture({expired:true});const result=await f.run();assert.equal(result.joined,1);
    assert.deepEqual(f.calls,['refresh','reserve','get','dispatch','put','finish']);
    assert.equal(JSON.stringify(f.operations).includes('synthetic-access'),false);
});

test('missing consent or wrong destination never sends a member request',async()=>{
    const f=fixture({empty:true});assert.equal((await f.run()).joined,0);assert.deepEqual(f.calls,[]);
    await assert.rejects(f.service.run({guildId:'9000000000000000003',amount:1}),{message:'MEMBER_JOIN_UNAVAILABLE'});
    await assert.rejects(f.service.run({guildId:env.GUILD_ID,amount:101}));
});

for(const kind of ['scope','revoked','consumed','departure','refresh'])test(`${kind} blocks member inclusion`,async()=>{
    const f=fixture({reserveFails:kind==='consumed',dispatchFails:kind==='departure',expired:kind==='refresh',refreshFails:kind==='refresh'});
    if(kind==='scope')f.record.scopes=[];
    if(kind==='revoked')f.record.status='revoked';
    const result=await f.run();assert.equal(result.joined,0);assert.equal(f.calls.includes('put'),false);
});

test('concurrent executions and subsequent reuse send only one PUT for a consent',async()=>{
    const f=fixture();const results=await Promise.all([f.run(),f.run()]);
    assert.equal(results.reduce((n,r)=>n+r.joined,0),1);assert.equal(f.calls.filter(c=>c==='put').length,1);
    assert.equal((await f.run()).joined,0);assert.equal(f.calls.filter(c=>c==='put').length,1);
});

for(const pending of [false,true])test(`member already present (pending=${pending}) is not added again`,async()=>{
    const f=fixture({present:{status:200,data:{pending}}}),result=await f.run();
    assert.equal(result[pending?'pending':'already_member'],1);assert.equal(f.calls.includes('put'),false);
});

for(const response of [{status:201,data:{pending:true}},{status:204},{status:403},{status:500},{status:429,data:{retry_after:2.4}}]) {
    test(`Discord ${response.status} pending=${response.data?.pending===true} records a bounded result without retry`,async()=>{
        const f=fixture({response}),result=await f.run();
        const expected=response.status===201?'pending':response.status===204?'already_member':response.status===500?'uncertain':'failed';
        assert.equal(result[expected],1);assert.equal(f.calls.filter(c=>c==='put').length,1);
        if(response.status===429){assert.equal(f.operations[0].retrySeconds,3);assert.equal(result.stopped,true);}
    });
}

test('preflight rate limit stops before PUT and stores cooldown',async()=>{
    const f=fixture({present:{status:429,headers:{'retry-after':'4'}}});const result=await f.run();
    assert.equal(result.stopped,true);assert.equal(f.operations[0].retrySeconds,4);assert.equal(f.calls.includes('put'),false);
});

test('timeout is uncertain, while unconfirmed persistence never reports durable success',async()=>{
    for(const options of [{timeout:true},{finishFails:true}]){
        const f=fixture(options),result=await f.run();assert.equal(result.joined,0);assert.equal(result.uncertain,1);assert.equal(result.stopped,true);
        assert.equal(JSON.stringify(result).includes('private'),false);assert.equal(f.calls.filter(c=>c==='put').length,1);
    }
});

test('observer blocks departures immediately and resets continuity after gateway gaps',async()=>{
    const client=new EventEmitter();client.isReady=()=>true;client.guilds={cache:new Map([[env.GUILD_ID,{}]])};
    const calls=[];let heartbeat,resolveDeparture;
    const repositories={membership:{watch:async(_g,_c,_o,reset)=>{calls.push(['watch',reset]);return true;},pause:async()=>{calls.push(['pause']);return true;},
        departure:async()=>new Promise(resolve=>{resolveDeparture=()=>resolve(true);})}};
    const observer=createMemberObserver({client,repositories,env,schedule:fn=>{heartbeat=fn;return{unref(){}};}});
    await observer.start();assert.equal(observer.safe(),true);
    client.emit(Events.Raw,{t:'GUILD_MEMBER_REMOVE',d:{guild_id:env.GUILD_ID,user:{id:'9000000000000000000'}}});
    assert.equal(observer.safe(),false);await Promise.resolve();resolveDeparture();await observer.flush();assert.equal(observer.safe(),true);
    client.emit(Events.ShardDisconnect);assert.equal(observer.safe(),false);await observer.flush();
    client.emit(Events.ShardResume);await observer.flush();assert.equal(observer.safe(),true);
    assert.deepEqual(calls.filter(c=>c[0]==='watch'),[['watch',true],['watch',true]]);
    heartbeat();await observer.flush();await observer.close();assert.equal(observer.safe(),false);
});

test('observer write failures and lease age block inclusion until a fresh epoch',async()=>{
    let now=0,fail=false;const client=new EventEmitter();client.isReady=()=>true;client.guilds={cache:new Map([[env.GUILD_ID,{}]])};
    const resets=[];
    const repositories={membership:{watch:async(_g,_c,_o,reset)=>{resets.push(reset);if(fail)throw new Error('private');return true;},pause:async()=>true,departure:async()=>{throw new Error('private');}}};
    const observer=createMemberObserver({client,repositories,env,now:()=>now,schedule:()=>({unref(){}})});
    await observer.start();now=21000;assert.equal(observer.safe(),false);fail=true;await observer.start();assert.equal(observer.safe(),false);
    fail=false;await observer.start();assert.equal(observer.safe(),true);assert.equal(resets.at(-1),true);
    client.emit(Events.Raw,{t:'GUILD_MEMBER_REMOVE',d:{guild_id:env.GUILD_ID,user:{id:'9000000000000000000'}}});await observer.flush();assert.equal(observer.safe(),false);
    await observer.close();
});

test('private member mode is opt-in and requires private OAuth',()=>{
    assert.equal(enabled({}),false);assert.equal(enabled({OAUTH_MEMBER_JOIN_ENABLED:'false'}),false);
    assert.throws(()=>enabled({OAUTH_MEMBER_JOIN_ENABLED:'true'}));assert.throws(()=>enabled({OAUTH_MEMBER_JOIN_ENABLED:'typo'}));
    assert.equal(enabled({OAUTH_MEMBER_JOIN_ENABLED:'true',OAUTH_PRIVATE_ENABLED:'true'}),true);
});
