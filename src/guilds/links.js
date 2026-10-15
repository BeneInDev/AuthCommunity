const { createHmac,timingSafeEqual } = require('node:crypto');
function createGuildLinks(env, now=Date.now) {
    const callback=new URL(env.REDIRECT_URI);
    if(callback.protocol!=='https:' || callback.username || callback.password || !env.OAUTH_STATE_SECRET || env.OAUTH_STATE_SECRET.length<32) throw new Error('GUILD_LINK_CONFIGURATION');
    const sign=payload=>createHmac('sha256',env.OAUTH_STATE_SECRET).update(JSON.stringify(['guild-launch-v1',callback.href,env.CLIENT_ID,payload])).digest('base64url');
    return {
        issue(guildId,subjectId) {
            if(!/^\d{17,20}$/.test(guildId)||!/^\d{17,20}$/.test(subjectId))throw new Error('GUILD_LINK_INVALID');
            const payload=Buffer.from(JSON.stringify({guildId,originGuildId:guildId,subjectId,exp:now()+300000})).toString('base64url');
            const url=new URL('/oauth2/start',callback);url.searchParams.set('ticket',`${payload}.${sign(payload)}`);return url.href;
        },
        read(ticket) {
            if(typeof ticket!=='string'||ticket.length>1000)throw new Error('GUILD_LINK_INVALID');
            const [payload,signature,extra]=ticket.split('.');
            if(extra || !signature || !/^[A-Za-z0-9_-]{43}$/.test(signature)||!timingSafeEqual(Buffer.from(signature),Buffer.from(sign(payload))))throw new Error('GUILD_LINK_INVALID');
            const data=JSON.parse(Buffer.from(payload,'base64url').toString());
            if(!/^\d{17,20}$/.test(data.guildId)||data.guildId!==data.originGuildId||!/^\d{17,20}$/.test(data.subjectId)||
                !Number.isSafeInteger(data.exp)||data.exp<=now()||data.exp>now()+300000)throw new Error('GUILD_LINK_INVALID');
            return data;
        }
    };
}
module.exports={createGuildLinks};
