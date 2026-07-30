const { Events, MessageFlags } = require('discord.js');

module.exports = {
    name: Events.InteractionCreate,
    async execute(interaction, client) {
        if (interaction.isChatInputCommand()) {
            if (interaction.user.id !== process.env.OWNER_ID) {
                return interaction.reply({ 
                    content: 'Apenas o dono do bot pode usar este comando.', 
                    flags: MessageFlags.Ephemeral
                });
            }

            const command = client.commands.get(interaction.commandName);
            if (!command) return;

            try {
                await command.execute(interaction, client);
            } catch (error) {
                console.error(error);
                await interaction.reply({ 
                    content: 'Ocorreu um erro ao executar este comando!', 
                    flags: MessageFlags.Ephemeral
                });
            }
        } else if (interaction.isButton() || interaction.isStringSelectMenu() || interaction.isModalSubmit()) {
            const handler = client.commands.get('handler');
            if (handler && typeof handler.handleInteraction === 'function') {
                await handler.handleInteraction(interaction, client);
            }
        }
    },
};
