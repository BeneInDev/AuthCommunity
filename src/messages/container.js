const {
    MessageFlags,
    TextDisplayBuilder,
    ThumbnailBuilder,
    SectionBuilder,
    SeparatorBuilder,
    SeparatorSpacingSize,
    ButtonBuilder,
    ButtonStyle,
    ActionRowBuilder,
    ContainerBuilder,
} = require('discord.js');

module.exports = async (interaction, desc) => {
    const guild = interaction.guild;

    const container = new ContainerBuilder()
        .addSectionComponents(
            new SectionBuilder()
                .setThumbnailAccessory(
                    new ThumbnailBuilder({
                        media: {
                            url:
                                guild.iconURL({ size: 256 }) ||
                                'https://cdn.discordapp.com/embed/avatars/0.png',
                        },
                    })
                )
                .addTextDisplayComponents(
                    new TextDisplayBuilder().setContent(`## ${guild.name}`),
                    new TextDisplayBuilder().setContent(desc),
                )
        )
        .addSeparatorComponents(
            new SeparatorBuilder()
                .setDivider(true)
                .setSpacing(SeparatorSpacingSize.Small)
        )
        .addTextDisplayComponents(
            new TextDisplayBuilder().setContent(
                '### -# Pra que serve a verificação?\n' +
                'Serve para que caso o servidor venha a cair, vocês sejam automaticamente puxados para o novo servidor.'
            )
        )
        .addActionRowComponents(
            new ActionRowBuilder().addComponents(
                new ButtonBuilder()
                    .setCustomId('verify_button')
                    .setLabel('Se Verificar')
                    .setEmoji('1470918021278204128')
                    .setStyle(ButtonStyle.Primary)
            )
        );

    await interaction.reply({
        flags: MessageFlags.IsComponentsV2,
        components: [container],
    });
};