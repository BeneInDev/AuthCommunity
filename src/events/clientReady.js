const { Events, ActivityType } = require('discord.js');

module.exports = {
    name: Events.ClientReady,
    once: true,

    execute(client) {
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
