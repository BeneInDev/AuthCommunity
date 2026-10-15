const { MessageFlags } = require('discord.js');

const administrativeIds = new Set(['config_role', 'config_logs', 'config_puxar', 'modal_role', 'modal_logs', 'puxar_modal']);

async function requireOwner(interaction, ownerId = process.env.OWNER_ID) {
    if (ownerId && interaction.user?.id === ownerId) return true;
    await interaction.reply({ content: 'Apenas o dono do bot pode usar esta ação.', flags: MessageFlags.Ephemeral });
    return false;
}

module.exports = { administrativeIds, requireOwner };
