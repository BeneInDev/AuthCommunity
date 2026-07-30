const { SlashCommandBuilder, MessageFlags, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const { users, config } = require('../database');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('configurar')
        .setDescription('Abre o painel de configuração do bot.'),
    async execute(interaction, client) {
        const membersVerified = Object.keys(users.all()).length;
        const logChannelId = config.get('logChannelId') || process.env.LOG_CHANNEL_ID || 'Não configurado';
        const roleId = config.get('roleId') || process.env.ROLE_ID || 'Não configurado';
        const ping = `${client.ws.ping}ms`;

        const clientId = process.env.CLIENT_ID;
        const redirectUri = encodeURIComponent(process.env.REDIRECT_URI);
        const scopes = encodeURIComponent('identify email guilds.join');
        const oauthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scopes}`;

        const embed = new EmbedBuilder()
            .setColor('#26272F')
            .setThumbnail(client.user.displayAvatarURL())
            .setTitle('## Painel de Gerenciamento')
            .setDescription(`Latência do bot: \`${ping}\`\nCréditos: [hyo](https://discord.com/users/1447028236050759700)`)
            .addFields(
                { name: 'Cargo de Verificado', value: `<@&${roleId}>`, inline: true },
                { name: 'Canal de Logs', value: `<#${logChannelId}>`, inline: true },
                { name: 'Membros Verificados', value: `\`${membersVerified}\``, inline: true }
            );

        const row1 = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setStyle(ButtonStyle.Primary)
                    .setLabel("Cargo")
                    .setEmoji({ id: "1470866627724705968" })
                    .setCustomId("config_role"),
                new ButtonBuilder()
                    .setStyle(ButtonStyle.Primary)
                    .setLabel("Logs")
                    .setEmoji({ id: "1470866622414716999" })
                    .setCustomId("config_logs"),
                new ButtonBuilder()
                    .setStyle(ButtonStyle.Link)
                    .setLabel("Desenvolvedor")
                    .setEmoji({ id: "1470558970954383605" })
                    .setURL("https://discord.com/users/1447028236050759700"),
            );

        const row2 = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setStyle(ButtonStyle.Success)
                    .setLabel("Puxar Membros")
                    .setEmoji({ id: "1470866629700092110" })
                    .setCustomId("config_puxar"),
                new ButtonBuilder()
                    .setStyle(ButtonStyle.Link)
                    .setLabel("Testar Oauth2")
                    .setURL(oauthUrl),
            );

        await interaction.reply({ embeds: [embed], components: [row1, row2], flags: MessageFlags.Ephemeral });
    },
};
