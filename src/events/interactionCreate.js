const { Events, MessageFlags } = require('discord.js');
const { administrativeIds, requireOwner } = require('../security/authorization');

module.exports = {
    name: Events.InteractionCreate,
    async execute(interaction, client) {
        if (process.env.OAUTH_MULTIGUILD_ENABLED && process.env.OAUTH_MULTIGUILD_ENABLED !== 'false') {
            const guildInteractions = require('../guilds/interactions');
            if (guildInteractions.handles(interaction)) {
                try { return await guildInteractions.handle(interaction, client); }
                catch { console.error('GUILD_INTERACTION_FAILED'); return; }
            }
        }
        if (interaction.isChatInputCommand()) {
            if (!await requireOwner(interaction)) return;

            const command = client.commands.get(interaction.commandName);
            if (!command) return;

            try {
                await command.execute(interaction, client);
            } catch (error) {
                console.error('COMMAND_FAILED');
                await interaction.reply({ 
                    content: 'Ocorreu um erro ao executar este comando!', 
                    flags: MessageFlags.Ephemeral
                });
            }
        } else if (interaction.isButton() || interaction.isStringSelectMenu() || interaction.isModalSubmit()) {
            if (administrativeIds.has(interaction.customId) && !await requireOwner(interaction)) return;
            const handler = client.commands.get('handler');
            if (handler && typeof handler.handleInteraction === 'function') {
                try {
                    await handler.handleInteraction(interaction, client);
                } catch {
                    console.error('INTERACTION_FAILED');
                }
            }
        }
    },
};
