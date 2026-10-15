const express = require('express');
const { escapeHtml } = require('./html');
const { createConsentState } = require('./oauth-consent-state');
const { oauthRepositoriesFromEnvironment } = require('../database/oauth-repositories');
const { createOAuthLifecycle } = require('../security/oauth-lifecycle');

function mountPrivateOAuth(app, client, { env = process.env, http, repositories, now } = {}) {
    const state = createConsentState({ env, now });
    const repo = repositories || oauthRepositoriesFromEnvironment(env);
    const lifecycle = createOAuthLifecycle({ repositories: repo, http, env, now });
    const headers = res => {
        res.set('Cache-Control', 'no-store');
        res.set('Referrer-Policy', 'no-referrer');
        res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    };
    const failure = res => res.status(400).send('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Verificação não concluída</title><p>Não foi possível concluir. Inicie uma nova verificação.</p><a href="/oauth2/start">Recomeçar</a></html>');
    app.get('/oauth2/start', (req, res) => {
        headers(res);
        try {
            if (Object.keys(req.query).some(key => key !== 'guild_id') ||
                (req.query.guild_id !== undefined && req.query.guild_id !== env.GUILD_ID)) throw new Error();
            const guild = client.guilds.cache.get(env.GUILD_ID);
            if (!guild || typeof guild.name !== 'string') throw new Error();
            const csrf = state.start(res);
            res.send(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Autorizar servidor</title>
                <h1>Autorizar ${escapeHtml(guild.name)}</h1><p>Servidor Discord: ${escapeHtml(env.GUILD_ID)}</p>
                <p>Esta autorização permite uma única tentativa de adicionar sua conta a este servidor durante ${state.days} dias.
                Não autoriza outros servidores. Se você sair, sua saída não autoriza reinclusão automática.</p>
                <p>Seus tokens serão armazenados criptografados para esta finalidade.</p>
                <form method="post" action="/oauth2/consent"><input type="hidden" name="state" value="${escapeHtml(csrf)}">
                <label><input type="checkbox" name="accepted" value="yes" required> Autorizo expressamente a entrada neste servidor.</label>
                <button type="submit">Autorizar e continuar no Discord</button></form><a href="/">Cancelar</a></html>`);
        } catch { failure(res); }
    });
    const parser = express.urlencoded({ extended: false, limit: '4kb', parameterLimit: 3 });
    app.post('/oauth2/consent', (req, res, next) => {
        headers(res);
        parser(req, res, error => error ? failure(res) : next());
    }, async (req, res) => {
        try {
            if (Object.keys(req.body || {}).some(key => !['state','accepted'].includes(key))) throw new Error();
            const flow = state.accept(req);
            const id = await repo.flows.create(flow);
            if (id !== flow.id) throw new Error();
            res.redirect(303, flow.url);
        } catch { failure(res); }
    });
    app.get('/oauth2/callback', async (req, res) => {
        headers(res);
        try {
            const flow = state.callback(req, res);
            await lifecycle.complete(flow, req.query.code);
            res.send('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Autorização registrada</title><p>Autorização e consentimento registrados. Isso não confirma entrada no servidor.</p></html>');
        } catch { failure(res); }
    });
    return lifecycle;
}
module.exports = { mountPrivateOAuth };
