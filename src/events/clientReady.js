const { Events, ActivityType } = require('discord.js');

module.exports = {
    name: Events.ClientReady,
    once: true,

    async execute(client) {
        try { require('../guilds/runtime').start(client); }
        catch { console.error('GUILD_VERIFICATION_INITIALIZATION_FAILED'); }
        try { await require('../security/private-members').initialize(client); }
        catch { console.error('MEMBER_JOIN_INITIALIZATION_FAILED'); }
        console.log(`✅ ${client.user.tag} online`);

        client.user.setPresence({
            activities: [
                {
                    name: 'Community Games • discord.gg/mN78zKpWja',
                    type: ActivityType.Playing
                }
            ],
            status: 'online'
        });
    }
};
