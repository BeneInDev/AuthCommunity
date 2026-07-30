const { ActivityType, Events } = require('discord.js');

module.exports = {
    name: Events.ClientReady,
    once: true,
    execute(client) {
        console.log(`Logged in as ${client.user.tag}!`);
        console.log(`Bot ID: ${client.user.id}`);
        console.log(`Connected to ${client.guilds.cache.size} guilds`);

        client.user.setPresence({
            activities: [{ 
                name: 'Pure Solutions', 
                type: ActivityType.Streaming,
                url: 'https://twitch.tv/puresolutions'
            }],
            status: 'online',
        });
    },
};
