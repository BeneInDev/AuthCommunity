const axios = require('axios');
const { createVerifiedUsersRepository } = require('../database/verified-users');
const { EmbedBuilder } = require('discord.js');
const { createOAuthState } = require('./oauth-state');
const { externalRequestOptions } = require('../http-options');

module.exports = (app, client, dependencies = {}) => {
    const { users, config } = dependencies.database || require('../database');
    const http = dependencies.http || axios;
    const env = dependencies.env || process.env;
    if (env.OAUTH_PRIVATE_ENABLED && !['true', 'false'].includes(env.OAUTH_PRIVATE_ENABLED)) {
        throw new Error('OAUTH_CONFIGURATION_INVALID');
    }
    if (env.OAUTH_MULTIGUILD_ENABLED && env.OAUTH_MULTIGUILD_ENABLED !== 'false') {
        if (env.OAUTH_MULTIGUILD_ENABLED !== 'true' || env.OAUTH_PRIVATE_ENABLED !== 'true') throw new Error('OAUTH_CONFIGURATION_INVALID');
        require('./oauth-multiguild-routes').mountMultiguildOAuth(app, client, {
            env, http, repositories: dependencies.oauthRepositories, now: dependencies.now
        });
    } else if (env.OAUTH_PRIVATE_ENABLED === 'true') {
        require('./oauth-private-routes').mountPrivateOAuth(app, client, {
            env, http, repositories: dependencies.oauthRepositories, now: dependencies.now
        });
    }
    const verifiedUsers = dependencies.verifiedUsers || createVerifiedUsersRepository({ legacyUsers: users });
    const oauthState = dependencies.oauthState || createOAuthState();

    app.get('/oauth2/start', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.set('Referrer-Policy', 'no-referrer');
        try { res.redirect(oauthState.start(res)); }
        catch { console.error('OAUTH_START_FAILED'); res.redirect('/error'); }
    });

    app.get('/', (req, res) => {
    console.log(
        `Ping recebido em ${new Date().toLocaleString()}`
    );

    res.render('index.html');
});

    app.get('/oauth2/callback', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.set('Referrer-Policy', 'no-referrer');
        const { code } = req.query;

        try {
            if (!oauthState.consume(req, res) || typeof code !== 'string' || !code.trim()) return res.redirect('/error');
            const params = new URLSearchParams();
            params.append('client_id', process.env.CLIENT_ID);
            params.append('client_secret', process.env.CLIENT_SECRET);
            params.append('grant_type', 'authorization_code');
            params.append('code', code);
            params.append('redirect_uri', process.env.REDIRECT_URI);

            const tokenResponse = await http.post(
                'https://discord.com/api/oauth2/token',
                params,
                { ...externalRequestOptions(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
            );

            const { access_token, refresh_token, token_type } = tokenResponse.data;

            const userResponse = await http.get(
                'https://discord.com/api/users/@me',
                { ...externalRequestOptions(), headers: { Authorization: `${token_type} ${access_token}` } }
            );

            const userData = userResponse.data;

            let ip =
                req.headers['cf-connecting-ip'] ||
                req.headers['x-forwarded-for'] ||
                req.socket.remoteAddress;

            if (ip && ip.includes(',')) ip = ip.split(',')[0].trim();

            const userDevice = req.headers['user-agent'] || 'Unknown';

            await verifiedUsers.saveVerification({
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

            if (guildId && roleId) {
    try {
        const guild = client.guilds.cache.get(guildId);

        if (!guild) {
            console.log('Servidor não encontrado pelo bot.');
        } else {
            const member = await guild.members.fetch(userData.id);

            await member.roles.add(roleId);

            console.log(
                'ROLE ADD SUCCESS:',
                userData.id,
                roleId
            );
        }

    } catch (error) {
        console.log(
            'ROLE ADD ERROR:',
            'Falha ao atribuir cargo.'
        );
    }
}

            const createdAt = new Date(
                Number((BigInt(userData.id) >> 22n) + 1420070400000n)
            );

            const now = new Date();
            const accountDays = Math.floor(
                (now - createdAt) / (1000 * 60 * 60 * 24)
            );

            try {
                await sendLog(client, userData, config);
            } catch {
                console.error('VERIFICATION_LOG_FAILED');
            }

            const guild = client.guilds.cache.get(guildId);

            res.render('success.html', {
                userName: userData.username,
                userId: userData.id,
                userAvatar: userData.avatar
                    ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png`
                    : 'https://cdn.discordapp.com/embed/avatars/0.png',
                guildName: guild ? guild.name : 'Server',
                guildId: guildId || '0',
                guildUrl: `https://discord.com/channels/${guildId || '0'}`,
                guildIcon: guild && guild.icon
                    ? `https://cdn.discordapp.com/icons/${guildId}/${guild.icon}.png`
                    : 'https://cdn.discordapp.com/embed/avatars/0.png',
                accountDays
            });

        } catch {
            console.error('VERIFICATION_FAILED');
            res.redirect('/error');
        }
    });

    app.get('/error', (req, res) => {
        res.render('error.html', {
            error: 'Não foi possível concluir a verificação. Inicie uma nova verificação e tente novamente.'
        });
    });
};

async function sendLog(client, userData, config) {
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
            `**Idade da Conta:** \`${creationAccountDays}\` dias`
        )
        .setTimestamp();

    await webhook.send({ embeds: [embed] });
}
