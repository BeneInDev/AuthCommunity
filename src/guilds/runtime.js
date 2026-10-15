const runtimes=new WeakMap();
function enabled(env=process.env) {
    if(!env.OAUTH_MULTIGUILD_ENABLED||env.OAUTH_MULTIGUILD_ENABLED==='false')return false;
    if(env.OAUTH_MULTIGUILD_ENABLED!=='true'||env.OAUTH_PRIVATE_ENABLED!=='true')throw new Error('GUILD_CONFIGURATION_INVALID');
    return true;
}
function get(client,env=process.env) {
    if(!enabled(env))throw new Error('GUILD_CONFIGURATION_INVALID');
    if(!runtimes.has(client)) {
        const repositories=require('../database/oauth-repositories').oauthRepositoriesFromEnvironment(env);
        const http=require('axios');
        runtimes.set(client,{repositories,http,env});
    }
    return runtimes.get(client);
}
function start(client,env=process.env) {
    if(!enabled(env))return;
    const runtime=get(client,env);
    if(runtime.timer)return;
    const worker=require('./effects').createEffectsWorker(runtime);
    const tick=()=>worker.tick().catch(()=>console.error('VERIFICATION_EFFECTS_UNAVAILABLE'));
    runtime.timer=setInterval(tick,10000);runtime.timer.unref();void tick();
}
module.exports={enabled,get,start};
