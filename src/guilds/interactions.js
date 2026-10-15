const {ActionRowBuilder,ButtonBuilder,ButtonStyle,ModalBuilder,TextInputBuilder,TextInputStyle,MessageFlags}=require('discord.js');
const {externalRequestOptions}=require('../http-options');
const {createGuildLinks}=require('./links');
const runtime=require('./runtime');
const scope=interaction=>interaction.guildId||interaction.guild?.id;
function handles(interaction,env=process.env) {
    if(!env.OAUTH_MULTIGUILD_ENABLED||env.OAUTH_MULTIGUILD_ENABLED==='false')return false;
    return Boolean((interaction.isChatInputCommand()&&['configurar','enviar'].includes(interaction.commandName)) ||
        interaction.customId==='verify_button'||interaction.customId?.startsWith('guild_config:')||interaction.customId?.startsWith('guild_open:'));
}
async function handle(interaction,client,dependencies) {
    try {
        const {repositories:repo,http,env}=dependencies||runtime.get(client),guildId=scope(interaction),actorId=interaction.user.id;
        if(!/^\d{17,20}$/.test(guildId)||!interaction.guild)throw new Error();
        const reply=data=>interaction.deferred?interaction.editReply(data):interaction.reply({...data,flags:MessageFlags.Ephemeral});
        if(interaction.customId?.startsWith('guild_open:')) {
            const [,boundGuild,version]=interaction.customId.split(':');
            if(boundGuild!==guildId||!/^\d+$/.test(version))throw new Error();
            // Values are only form prefills. Every permission/value/version is rechecked on submit.
            const fields=interaction.message?.embeds?.[0]?.fields||[];
            const read=name=>{const value=name==='Mensagem'?interaction.message?.embeds?.[0]?.description:fields.find(f=>f.name===name)?.value;return value==='—'?'':value||'';};
            const modal=new ModalBuilder().setCustomId(`guild_config:${guildId}:${version}`).setTitle('Configurar este servidor');
            const input=(id,label,value,required=true)=>new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId(id).setLabel(label)
                .setStyle(id==='message'?TextInputStyle.Paragraph:TextInputStyle.Short).setRequired(required).setValue(value));
            modal.addComponents(input('role','ID do cargo',read('Cargo'),false),input('logs','ID do canal de logs',read('Canal'),false),
                input('message','Mensagem de verificação',read('Mensagem')),input('active','Ativo? sim ou não',read('Ativo')));
            if(fields.some(f=>f.name==='Administradores'))modal.addComponents(input('admins','IDs dos admins (separados por vírgula)',read('Administradores'),false));
            return interaction.showModal(modal);
        }
        if(interaction.deferReply)await interaction.deferReply({flags:MessageFlags.Ephemeral});
        if(interaction.customId==='verify_button') {
            const config=await repo.guilds.public(guildId);if(!config?.active)throw new Error();
            const url=createGuildLinks(env).issue(guildId,actorId);
            return reply({content:'Link pessoal válido por cinco minutos.',components:[new ActionRowBuilder().addComponents(new ButtonBuilder().setStyle(ButtonStyle.Link).setLabel('Verificar neste servidor').setURL(url))]});
        }
        const opts=()=>({...externalRequestOptions(),headers:{Authorization:`Bot ${env.TOKEN}`}});
        const guild=await http.get(`https://discord.com/api/v10/guilds/${guildId}`,opts());
        if(guild.data.id!==guildId||!/^\d{17,20}$/.test(guild.data.owner_id))throw new Error();
        await repo.guilds.syncOwner(guildId,guild.data.owner_id);
        const config=await repo.guilds.get(guildId,actorId);
        if(interaction.customId?.startsWith('guild_config:')) {
            const [,boundGuild,version]=interaction.customId.split(':');
            if(boundGuild!==guildId||String(config.version)!==version)throw new Error();
            const read=id=>interaction.fields.getTextInputValue(id).trim();
            const roleId=read('role')||null,logChannelId=read('logs')||null,message=read('message'),active=read('active');
            if(!['sim','não','nao'].includes(active))throw new Error();
            if(roleId){const roles=await http.get(`https://discord.com/api/v10/guilds/${guildId}/roles`,opts());
                if(!roles.data.some(r=>r.id===roleId&&!r.managed&&r.id!==guildId))throw new Error();}
            if(logChannelId){const channel=await http.get(`https://discord.com/api/v10/channels/${logChannelId}`,opts());
                if(channel.data.guild_id!==guildId||![0,5].includes(channel.data.type))throw new Error();}
            const adminIds=actorId===config.owner_id?read('admins').split(/[,\s]+/).filter(Boolean):null;
            await repo.guilds.save({guildId,actorId,version:config.version,roleId,logChannelId,message,active:active==='sim',adminIds});
            return reply({content:'Configuração deste servidor salva.'});
        }
        if(interaction.commandName==='configurar') {
            const fields=[{name:'Cargo',value:config.role_id||'—'},{name:'Canal',value:config.log_channel_id||'—'},
                {name:'Ativo',value:config.active?'sim':'não'}];
            if(actorId===config.owner_id)fields.push({name:'Administradores',value:config.admin_ids.join(',')||'—'});
            return reply({embeds:[{title:'Configuração deste servidor',description:config.verification_message,fields}],allowedMentions:{parse:[]},components:[new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`guild_open:${guildId}:${config.version}`).setLabel('Editar configuração').setStyle(ButtonStyle.Primary))]});
        }
        if(interaction.commandName==='enviar') {
            const channel=interaction.options.getChannel('canal');
            if(!config.active||channel?.guildId!==guildId)throw new Error();
            await channel.send({content:config.verification_message,allowedMentions:{parse:[]},components:[new ActionRowBuilder().addComponents(new ButtonBuilder()
                .setCustomId('verify_button').setLabel('Verificar neste servidor').setStyle(ButtonStyle.Primary))]});
            return reply({content:'Mensagem de verificação enviada neste servidor.'});
        }
        throw new Error();
    }catch{
        const reply={content:'Operação não autorizada ou indisponível para este servidor.',flags:MessageFlags.Ephemeral};
        if(interaction.deferred||interaction.replied)await interaction.editReply({content:reply.content});else await interaction.reply(reply);
    }
}
module.exports={handles,handle};
