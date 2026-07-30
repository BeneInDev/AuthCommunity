const { SlashCommandBuilder, MessageFlags, ChannelType } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('enviar')
        .setDescription('Envia a mensagem de verificação.')
        .addStringOption(option =>
            option.setName('desc')
                .setDescription('Descrição da mensagem')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('tipo')
                .setDescription('Tipo da mensagem')
                .setRequired(true)
                .addChoices(
                    { name: 'button', value: 'button' },
                    { name: 'content', value: 'content' },
                    { name: 'embed', value: 'embed' },
                    { name: 'container', value: 'container' },
                ))
        .addChannelOption(option =>
            option.setName('canal')
                .setDescription('Canal onde a mensagem será enviada')
                .addChannelTypes(ChannelType.GuildText)
                .setRequired(true)),

    async execute(interaction) {
        const desc = interaction.options.getString('desc');
        const tipo = interaction.options.getString('tipo');
        const canal = interaction.options.getChannel('canal');

        try {
            if (tipo === 'container') {
                await require('../messages/container')(interaction, desc);

                return;
            }
          
            const messageData = require(`../messages/${tipo}`)(desc, interaction.guild);
            await canal.send(messageData);

            await interaction.reply({
                content: `Mensagem de verificação enviada para ${canal}!`,
                flags: MessageFlags.Ephemeral,
            });

        } catch (error) {
            console.error('Error in /enviar:', error);

            if (!interaction.replied) {
                await interaction.reply({
                    content: 'Ocorreu um erro ao enviar a mensagem.',
                    flags: MessageFlags.Ephemeral,
                });
            }
        }
    },
};