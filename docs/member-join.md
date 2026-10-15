# Inclusão consentida de membros — terceira etapa local

Esta etapa de `/puxar` permanece inalterada. A implementação posterior de perfil/cargo/log
está descrita na [quarta etapa](multiguild-verification.md); a seção de análise ao final
registra o plano anterior àquela implementação.

O comportamento novo exige **ambas** as opções `OAUTH_PRIVATE_ENABLED=true` e
`OAUTH_MEMBER_JOIN_ENABLED=true`. A segunda é `false` por padrão. Não ativar na Render
sem homologação e autorização de publicação. Nenhuma inclusão real foi executada.

## Funcionamento

O modal `/puxar` deixa de contar usuários no JSON no modo privado. O handler continua
exigindo o proprietário e aceita de 1 a 100 candidatos para o servidor configurado em
`GUILD_ID`. O serviço não importa usuários, não cria consentimentos e não usa JSON como
fallback. Outros servidores são rejeitados, mesmo se informados no modal.

O Supabase seleciona consentimentos ativos e não expirados para o destino/aplicação,
com autorização ativa e escopo `guilds.join`. Access tokens expirados podem aparecer
nessa seleção apenas para renovação; jamais são utilizados para inclusão sem renovação
confirmada. O serviço reutiliza o mecanismo de renovação com reserva e versão da etapa 2.

Uma RPC reserva e consome o consentimento em transação. Em seguida o serviço consulta
se o membro já está presente, sem adicioná-lo novamente. Antes de um PUT, outra RPC
revalida autorização, expiração, saída, continuidade do Gateway e prazo da reserva,
emitindo uma única permissão de envio. Dois processos não podem usar o mesmo consentimento.
Não há repetição automática do PUT, inclusive quando o primeiro resultado é incerto.

O banco registra operação, estado, horário, código HTTP e categoria de falha de uma lista
fechada. Não recebe respostas brutas do Discord, tokens em texto puro ou mensagens de exceção.
As respostas do comando apresentam apenas contadores. A consulta inicial ou uma disputa
perdida antes da reserva não cria operação de inclusão; aparece como não processada.

## Saídas e continuidade

`guild_departures` registra saídas por servidor/aplicação/usuário; saídas e expulsões recebem
o mesmo bloqueio conservador. O observador usa `GUILD_MEMBER_REMOVE` via evento bruto do
Gateway: o evento de alto nível do discord.js pode omitir membros fora do cache. Apenas IDs
são extraídos; o restante do pacote não é persistido nem registrado em logs.

Uma saída invalida consentimentos ativos anteriores e bloqueia uma operação reservada que
ainda não recebeu permissão de envio. Somente um fluxo novo de autorização, iniciado depois
da saída registrada, pode voltar a habilitar uma inclusão. Um consentimento consumido nunca
é reativado pela renovação do token, pela saída ou pela execução repetida de `/puxar`.

`guild_join_safety` mantém um observador exclusivo com validade de 30 segundos, atualizado
a cada dez segundos. O processo bloqueia novas inclusões ao perder conexão, ao receber uma
saída ainda não persistida ou ao ficar 20 segundos sem confirmação de saúde. A decisão de
reserva/envio também consulta o banco; não depende apenas de um sinal em memória.

Na inicialização, reconexão, troca de observador ou perda de continuidade, inicia-se um novo
período de observação. Consentimentos cujos fluxos são anteriores a esse período tornam-se
inelegíveis, mesmo se a pessoa não tiver saído. Isso é intencional: uma consulta de presença
não prova que o usuário nunca saiu enquanto o bot estava offline. Os registros não são apagados.
Em múltiplas instâncias, só aquela que mantém a reserva do observador pode executar inclusões.

Essa política exige novas autorizações após reinícios/suspensões da Render Free. É uma
limitação operacional importante, que precisa ser aceita antes da ativação. O intent
GuildMembers, já solicitado pelo código atual, deve estar disponível no aplicativo Discord.

Não existe transação distribuída com o Discord: uma saída ocorrida depois da última validação,
mas antes de o Discord aplicar uma requisição já enviada, não pode ser cancelada atomicamente.
Não prometemos eliminar essa janela. O sistema impede repetição automática e bloqueia as
próximas operações assim que recebe o evento. Não remove membros como compensação.

## Respostas e recuperação

| Situação | Tratamento |
| --- | --- |
| Já presente | Consome a tentativa e registra `already_member`; não envia PUT |
| Membership Screening pendente | Registra `pending`; não atribui cargo nem contorna a triagem |
| PUT 201 | Registra `joined` ou `pending`, conforme resposta |
| PUT 204 | Registra `already_member` |
| HTTP 429 | Consome a tentativa, registra `rate_limited`, interrompe o lote e persiste o cooldown |
| Timeout ou resposta ambígua do PUT | Registra `uncertain`, interrompe o lote e não repete |
| Falha ao confirmar persistência do resultado | Não conta sucesso; interrompe e bloqueia o observador local |
| Falha de renovação | Bloqueia o serviço local, sem tentar repetidamente refresh_token possivelmente rotacionado |

O cooldown usa `retry_after` ou `Retry-After`, arredondado para cima; valor ausente/inválido
usa bloqueio conservador de sete dias. O destino é único por configuração, por isso o cooldown
compartilhado também impede novos lotes desse aplicativo/destino em outra instância.
Não há espera em loop nem fila de reenvio. Uma tentativa consumida exige novo consentimento,
inclusive após 429 ou falha definitiva. O limite de processamento de um lote é aproximadamente
dois minutos, além da chamada em andamento, e cada HTTP tem timeout de dez segundos.

Ainda não há interface de reconciliação ou scheduler. Operações `in_progress` com reserva
expirada devem ser tratadas como resultado desconhecido, nunca retomadas para novo PUT.
É necessário desenvolver recuperação administrativa segura para bloqueios locais e resultados
pendentes. Reiniciar para liberar um bloqueio implica novo período de observação e novas
autorizações; não é uma recomendação para reiniciar o serviço online agora.

## Migração e validação

Aplicar futuramente as migrações 001 a 004 em ordem, somente após autorização. A quarta
adiciona as duas tabelas privadas, sete RPCs restritas, campos de resultado e `pending`.
Ela retira de `service_role` a execução direta de `ac_oauth_claim_join`; essa função passa
a ser interna à reserva protegida. Não modifica `public.auth_users`.

Os testes usam PGlite em memória, HTTP simulado e Gateway simulado. Cobrem autorização,
destino, expiração, revogação, consentimento consumido, saída, continuidade, cooldown,
concorrência lógica, integração dos comandos e preservação do legado. Antes de publicar,
validar PostgREST, múltiplas conexões PostgreSQL e eventos reais em homologação autorizada,
com contas de teste consentidas. PGlite serializa consultas e não prova contenção entre
conexões independentes de um servidor PostgreSQL.

Referências: [inclusão de membros no Discord](https://github.com/discord/discord-api-docs/blob/main/developers/resources/guild.mdx)
e [rate limits](https://github.com/discord/discord-api-docs/blob/main/developers/topics/rate-limits.mdx).

## Perfil, cargo e logs do callback — análise, sem implementação

O callback privado continua gravando apenas autorização/consentimento nas tabelas privadas.
Para preservar os demais efeitos do callback legado em uma etapa futura:

1. **Perfil:** aproveitar a identidade retornada por `/users/@me` e passar somente ID, username
   e avatar a `createAuthUsersStore().saveVerifiedUser`. Não usar `saveVerification` do adaptador
   legado, porque ele também grava no JSON. Para atomicidade com autorização/consentimento,
   uma nova RPC revisada poderá incluir o upsert dos cinco campos já existentes de `auth_users`,
   sem mudar seu esquema. Essa escrita não foi implementada nesta etapa.
2. **Cargo:** executar somente depois da persistência confirmada e de confirmar que o usuário
   está no destino correto. Respeitar a triagem pendente e permissões/hierarquia do bot.
   Falha no cargo não deve desfazer tokens/consentimento nem indicar inclusão que não ocorreu.
   O serviço de inclusão desta etapa não envia `roles` no PUT.
3. **Logs:** extrair a rotina atual de webhook para um módulo compartilhado, mantendo a lista
   explícita de campos permitidos. Agendar apenas após o commit, preferencialmente por uma
   outbox persistente com identificador de evento e recuperação de falhas. Avaliar duplicação
   se a resposta de um webhook se perder; não prometer entrega exatamente uma vez.

Cargo e webhook são efeitos externos, portanto não participam da transação PostgreSQL.
Definir separadamente confirmação da verificação e estado desses efeitos. Não foram alterados
perfil, cargos, webhooks, timestamps ou esquema de `public.auth_users` nesta etapa.
