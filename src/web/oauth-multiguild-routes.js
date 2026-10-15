const express=require('express');
const {escapeHtml}=require('./html');
const {createConsentState}=require('./oauth-consent-state');
const {createGuildLinks}=require('../guilds/links');
const {createOAuthLifecycle}=require('../security/oauth-lifecycle');
const {oauthRepositoriesFromEnvironment}=require('../database/oauth-repositories');
function mountMultiguildOAuth(app,client,{env=process.env,http,repositories,now}={}) {
    const repo=repositories||oauthRepositoriesFromEnvironment(env),state=createConsentState({env,now,multi:true}),links=createGuildLinks(env,now);
    const lifecycle=createOAuthLifecycle({repositories:repo,http,env,now});
    const headers=res=>{res.set('Cache-Control','no-store');res.set('Referrer-Policy','no-referrer');res.set('Content-Security-Policy',"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");};
    const fail=res=>res.status(400).send('Não foi possível concluir. Solicite um novo link no servidor Discord.');
    app.get('/oauth2/start',async(req,res)=>{
        headers(res);
        try {
            if(Object.keys(req.query).some(k=>k!=='ticket'))throw new Error();
            const binding=links.read(req.query.ticket),config=await repo.guilds.public(binding.guildId),guild=client.guilds.cache.get(binding.guildId);
            if(!config?.active||!guild)throw new Error();
            const csrf=state.start(res,{guildId:binding.guildId,originGuildId:binding.originGuildId,subjectId:binding.subjectId,configVersion:config.version});
            res.send(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Verificar conta</title>
                <h1>${escapeHtml(guild.name)}</h1><p>${escapeHtml(config.verification_message)}</p>
                <p>Origem e destino autorizado: ${escapeHtml(binding.guildId)}. Nenhum outro servidor será autorizado.</p>
                <p>Autorização para uma tentativa de entrada, válida por ${state.days} dias. Sair não autoriza reinclusão.</p>
                <form method="post" action="/oauth2/consent"><input type="hidden" name="state" value="${escapeHtml(csrf)}">
                <label><input type="checkbox" name="accepted" value="yes" required> Autorizo este servidor.</label>
                <button>Continuar no Discord</button></form></html>`);
        }catch{fail(res);}
    });
    const parser=express.urlencoded({extended:false,limit:'4kb',parameterLimit:3});
    app.post('/oauth2/consent',(req,res,next)=>{headers(res);parser(req,res,error=>error?fail(res):next());},async(req,res)=>{
        try {
            if(Object.keys(req.body||{}).some(k=>!['accepted','state'].includes(k)))throw new Error();
            const flow=state.accept(req);
            if(await repo.guilds.createFlow(flow)!==flow.id)throw new Error();
            res.redirect(303,flow.url);
        }catch{fail(res);}
    });
    app.get('/oauth2/callback',async(req,res)=>{
        headers(res);
        try {
            await lifecycle.complete(state.callback(req,res),req.query.code);
            res.send('Verificação e perfil registrados. O cargo será processado após confirmar sua presença no servidor; tarefas pendentes serão recuperadas automaticamente.');
        }catch{fail(res);}
    });
}
module.exports={mountMultiguildOAuth};
