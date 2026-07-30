const { ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');

module.exports = (desc, guild) => {
    const row = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('verify_button')
                .setLabel('Se Verificar')
                .setEmoji('1470918021278204128')
                .setStyle(ButtonStyle.Primary),
        );

    return { content: desc, components: [row] };
};
