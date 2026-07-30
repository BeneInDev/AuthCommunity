const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');

module.exports = (desc, guild) => {
    const embed = new EmbedBuilder()
        .setColor('#26272F')
        .setAuthor({ name: guild.name, iconURL: guild.iconURL() })
        .setThumbnail(guild.iconURL())
        .setDescription(desc);

    const row = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('verify_button')
                .setLabel('Se Verificar')
                .setEmoji('1470918021278204128')
                .setStyle(ButtonStyle.Primary),
        );

    return { embeds: [embed], components: [row] };
};
