const { SlashCommandBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, ActionRowBuilder } = require('discord.js');
const { users } = require('../database');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('puxar')
        .setDescription('Puxa membros verificados para um servidor.'),
    async execute(interaction, client) {
        const membersVerified = Object.keys(users.all()).length;

        const modal = new ModalBuilder()
            .setCustomId('puxar_modal')
            .setTitle('Puxar Membros');

        const amountInput = new TextInputBuilder()
            .setCustomId('amount')
            .setLabel('Quantidade')
            .setPlaceholder(`Disponíveis: ${membersVerified}`)
            .setStyle(TextInputStyle.Short)
            .setRequired(true);

        const targetGuildInput = new TextInputBuilder()
            .setCustomId('target_guild')
            .setLabel('Servidor Alvo (ID)')
            .setPlaceholder('Servidor onde os membros serão enviados')
            .setValue(interaction.guild.id)
            .setStyle(TextInputStyle.Short)
            .setRequired(true);

        const firstActionRow = new ActionRowBuilder().addComponents(amountInput);
        const secondActionRow = new ActionRowBuilder().addComponents(targetGuildInput);

        modal.addComponents(firstActionRow, secondActionRow);

        await interaction.showModal(modal);
    },
};
