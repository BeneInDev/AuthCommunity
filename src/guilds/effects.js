const {randomUUID}=require('node:crypto');
const {externalRequestOptions}=require('../http-options');
function createEffectsWorker({repositories,http,env=process.env}) {
    let busy=false;
    const options=()=>({...externalRequestOptions(),validateStatus:()=>true,headers:{Authorization:`Bot ${env.TOKEN}`}});
    async function tick() {
        if(busy)return;busy=true;
        try {
            for(let count=0;count<10;count++) {
                const leaseId=randomUUID(),job=await repositories.effects.claim(leaseId);
                if(!job)return;
                let status='pending',code='transport_unknown',messageId=null,delay=Math.min(3600,10*2**job.attempts);
                try {
                    const member=job.kind==='role' ? await http.get(`https://discord.com/api/v10/guilds/${job.guild_id}/members/${job.discord_id}`,options()) : {status:200,data:{}};
                    if(member.status===404){code='member_absent';delay=300;}
                    else if(member.status===200 && member.data?.pending){code='screening_pending';delay=300;}
                    else if(member.status===200) {
                        if(await repositories.effects.dispatch(job.id,leaseId)!==true)continue;
                        if(job.kind==='role') {
                            if(Array.isArray(member.data.roles)&&member.data.roles.includes(job.target_id)){status='done';code=null;}
                            else {
                                const response=await http.put(`https://discord.com/api/v10/guilds/${job.guild_id}/members/${job.discord_id}/roles/${job.target_id}`,null,options());
                                if(response.status===204){status='done';code=null;}
                                else if(response.status===429){delay=retryDelay(response);}
                                else if(response.status>=400&&response.status<500){status='failed';code='discord_rejected';}
                            }
                        } else {
                            const channel=await http.get(`https://discord.com/api/v10/channels/${job.target_id}`,options());
                            if(channel.status===200 && channel.data.guild_id===job.guild_id) {
                                const response=await http.post(`https://discord.com/api/v10/channels/${job.target_id}/messages`,{
                                    content:`Verificação concluída. Referência: ${job.nonce}`,nonce:job.nonce,enforce_nonce:true,allowed_mentions:{parse:[]}
                                },options());
                                if(response.status===200 && /^\d{17,20}$/.test(response.data?.id)){status='done';code=null;messageId=response.data.id;}
                                else if(response.status===429){delay=retryDelay(response);}
                                else if(response.status>=400&&response.status<500){status='failed';code='discord_rejected';}
                                else {delay=10;}
                            }else if(channel.status===429){delay=retryDelay(channel);}
                            else {status='failed';code='discord_rejected';}
                        }
                    }else if(member.status===429){delay=retryDelay(member);}
                    else if(member.status>=400&&member.status<500){status='failed';code='discord_rejected';}
                }catch{delay=10;}
                // Failed acknowledgement remains leased; another process recovers it after expiry.
                if(await repositories.effects.finish({id:job.id,leaseId,status,code,messageId,delay})!==true)return;
                if(code==='transport_unknown')return;
            }
        } finally {busy=false;}
    }
    return {tick};
}
function retryDelay(response) {
    const seconds=Number(response.data?.retry_after??response.headers?.['retry-after']);
    return Number.isFinite(seconds)&&seconds>0&&seconds<=86400?Math.ceil(seconds):86400;
}
module.exports={createEffectsWorker};
