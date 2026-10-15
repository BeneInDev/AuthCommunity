const { randomUUID } = require('node:crypto');
const { Events } = require('discord.js');

function createMemberObserver({ client, repositories, env, now = Date.now, schedule = setInterval }) {
    const id = randomUUID();
    let healthyAt = -Infinity, reset = true, connected = true, blocked = false, pending = 0, busy = false;
    let queue = Promise.resolve();
    const enqueue = job => { queue = queue.then(job).catch(() => { healthyAt = -Infinity;reset = true; });return queue; };
    const ready = () => connected && client.isReady() && client.guilds.cache.has(env.GUILD_ID) && !client.guilds.cache.get(env.GUILD_ID).unavailable;
    function pause() {
        connected = false;healthyAt = -Infinity;reset = true;
        return enqueue(() => repositories.membership.pause(env.GUILD_ID, env.CLIENT_ID, id));
    }
    async function tick() {
        if (busy || blocked || !ready()) return;
        busy = true;
        try {
            await enqueue(async () => {
                if (blocked || !ready()) return;
                const start = now(), needsReset = reset || start - healthyAt >= 20000;
                healthyAt = -Infinity;
                const ok = await repositories.membership.watch(env.GUILD_ID, env.CLIENT_ID, id, needsReset);
                if (ok === true && ready()) { healthyAt = start; reset = false; }
                else reset = true;
            });
        } finally { busy = false; }
    }
    const resume = () => { connected = true;reset = true;healthyAt = -Infinity;void tick(); };
    // guildMemberRemove can be omitted for uncached members without Partials.GuildMember.
    // Read only IDs from the raw packet; never persist/log the remaining user payload.
    const departure = packet => {
        if (packet.t !== 'GUILD_MEMBER_REMOVE' || packet.d?.guild_id !== env.GUILD_ID) return;
        const discordId = packet.d?.user?.id;
        pending++;
        void enqueue(async () => {
            try {
                if (typeof discordId !== 'string' || !/^\d{17,20}$/.test(discordId) ||
                    await repositories.membership.departure(env.GUILD_ID,env.CLIENT_ID,discordId) !== true) throw new Error();
            } catch {
                // The shared barrier invalidates older consent after any event-write uncertainty.
                healthyAt = -Infinity;reset = true;
                await repositories.membership.pause(env.GUILD_ID,env.CLIENT_ID,id);
            } finally { pending--; }
        });
    };
    const listeners = [[Events.ShardDisconnect,pause],[Events.ShardReconnecting,pause],[Events.Invalidated,pause],
        [Events.ShardResume,resume],[Events.ClientReady,resume],[Events.ShardReady,resume],
        [Events.Raw,departure],
        [Events.GuildUnavailable,guild => { if(guild.id===env.GUILD_ID) void pause(); }],
        [Events.GuildAvailable,guild => { if(guild.id===env.GUILD_ID) resume(); }]];
    for (const [event,fn] of listeners) client.on(event,fn);
    const timer = schedule(() => { void tick(); },10000);
    timer.unref?.();
    return {
        id, start: tick, flush: () => queue,
        safe: () => !blocked && !pending && ready() && now()-healthyAt<20000,
        block: () => { blocked=true;void pause(); },
        close: () => { blocked=true;clearInterval(timer);for(const [event,fn] of listeners)client.off(event,fn);return pause(); }
    };
}
module.exports = { createMemberObserver };
