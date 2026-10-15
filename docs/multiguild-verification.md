# Verificação por servidor — etapa 4 local

## Ativação e escopo

`OAUTH_MULTIGUILD_ENABLED=false` é o padrão. A ativação exige `OAUTH_PRIVATE_ENABLED=true`
e as migrações 001–005 aplicadas em homologação autorizada. Nada é aplicado no startup.
Não houve acesso a dados reais, mudanças na Render ou publicação.

Com ambas as opções ativas, `/configurar`, `/enviar` e o botão de verificação usam a nova
configuração. A versão anterior permanece disponível quando a opção está desligada.
`/puxar`, seus handlers, permissões e o observador da etapa 3 não foram modificados:
continuam vinculados a `GUILD_ID` quando o modo de inclusão privado está ativo.
Suporte multisservidor aqui abrange configuração, verificação, perfil, cargo e logs;
não amplia automaticamente os destinos aceitos por `/puxar`.

As variáveis necessárias são `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `OAUTH_TOKEN_KEYS`,
`OAUTH_TOKEN_ACTIVE_KEY_ID`, `OAUTH_STATE_SECRET`, `CLIENT_ID`, `CLIENT_SECRET`, `TOKEN`,
`REDIRECT_URI` HTTPS e `OAUTH_CONSENT_DAYS` (30 por padrão). Nenhuma chave nova é necessária.
`GUILD_ID` não determina o destino no callback multisservidor, mas continua necessário
para funcionalidades antigas e para o `/puxar` da etapa anterior.

## Configuração e permissões

A migração 005 cria `private.guild_configurations` e `private.verification_effects`,
com RLS, acesso direto revogado e nove RPCs exclusivas do backend. Nenhum campo de
`public.auth_users` é criado, removido ou alterado. Os cinco campos existentes são
escritos pela transação de verificação.

Cada configuração contém guild_id, proprietário, lista de administradores delegados,
role_id, log_channel_id, mensagem, estado ativo e versão. Não há importação automática
do JSON nem consentimentos gerados a partir de usuários antigos.

O proprietário atual do servidor, consultado no Discord pelo backend, pode iniciar a
configuração. O registro começa inativo. Ele pode delegar até 20 IDs de usuários;
delegados podem configurar e publicar mensagens somente naquele servidor. Apenas o
proprietário pode mudar a lista de delegados. Ter o cargo Discord Administrator, por si só,
não concede acesso a esta configuração. O proprietário global do bot também não ganha
acesso implícito às configurações de outros servidores.

Antes de ler/salvar configurações, o backend atualiza o proprietário a partir da resposta
autenticada do Discord. Ao detectar transferência, limpa delegados e desativa a configuração.
As RPCs confiam na identidade atestada pelo backend: nunca disponibilizar o service secret
nem aceitar actor_id/owner_id de uma API pública sem autenticação equivalente.

`/configurar` responde com um painel efêmero e um botão para abrir o modal imediatamente.
Isso evita depender de chamadas remotas no prazo de três segundos para abrir o modal.
O formulário inclui cargo, canal, mensagem e ativação; o proprietário também vê os delegados.
Destino, permissões e versão são novamente conferidos no envio. Atualizações concorrentes
com versão antiga falham em vez de sobrescrever configurações recentes.

O cargo deve pertencer ao servidor e não pode ser gerenciado nem @everyone. O canal de logs
deve pertencer ao mesmo servidor e ser de texto/anúncios. O bot ainda precisa das permissões
Discord e de hierarquia suficiente para atribuir o cargo; erros definitivos viram tarefas falhas.

No modo novo, `/enviar` usa a mensagem armazenada e o canal selecionado do próprio servidor.
As opções antigas `desc` e `tipo` continuam no registro do comando para preservar compatibilidade,
mas não definem o conteúdo nesse modo. Menções automáticas são desativadas. O botão público
emite um link individual efêmero; não publica um link pessoal no canal.

## Origem, destino e persistência

O link assinado dura cinco minutos, vem do guildId da interação Discord e contém o ID do
usuário que clicou. O navegador não escolhe livremente o servidor. Origem e destino são
iguais nesta etapa: qualquer transferência entre servidores exige desenho e consentimento
específicos futuros, nunca configuração implícita.

O state tem domínio de assinatura próprio, validade de dez minutos, cookie seguro de navegador,
origem, destino, conta esperada e versão da configuração. Trocar query parameters não altera
esses vínculos. O callback confirma que a conta retornada pelo Discord é a mesma do link.
Um link compartilhado não verifica outra conta. Mudanças de configuração invalidam fluxos
anteriores, inclusive quando a mudança ocorre antes do commit.

Uma única transação grava autorização criptografada, consentimento, consumo do fluxo,
upsert do perfil e tarefas de cargo/log. Falha na escrita do perfil desfaz todas essas
gravações. A reserva inicial do callback permanece consumida para troca de código: iniciar
novo fluxo após falha, sem fallback JSON nem repetição cega. Os timestamps continuam sendo
enviados pelo backend SQL, respeitando qualquer trigger existente; não se exige igualdade exata.

O perfil guarda apenas discord_id, username, avatar, verified_at e updated_at. Tokens ficam
somente no envelope criptografado da autorização. IP e e-mail não são persistidos pelo fluxo.
A resposta confirma perfil/verificação persistidos e informa que cargo é um efeito posterior,
sem prometer que já foi atribuído ou que o membro já entrou no servidor.

## Recuperação de cargo e log

O worker inicia somente no modo multisservidor e consulta a fila a cada dez segundos enquanto
o bot está em execução. Todos os servidores usam a fila com guild_id explícito em cada tarefa.
Há uma tarefa única por fluxo/tipo, reservas de 60 segundos, comparação da reserva na conclusão,
`SKIP LOCKED`, até dez tentativas e backoff persistente. Reinícios não apagam a fila.
Configuração desativada ou com versão diferente cancela uma tarefa antes do envio externo.

Para **cargo**, o worker consulta o membro no servidor correto. Ausência ou Membership Screening
pendente agenda nova tentativa. Cargo já presente é sucesso sem nova atribuição; a inclusão de
cargo usa PUT idempotente. Nenhum membro é adicionado por esse worker.

Para **log**, o worker confere o servidor do canal e envia uma mensagem pelo bot, sem webhook.
O texto contém somente confirmação e uma referência opaca da tarefa, sem usuário, tokens,
IP ou e-mail. A verificação pode ser registrada mesmo que o membro ainda não esteja presente.
Não se inclui conteúdo livre de exceções nem respostas do provedor.

O log usa nonce persistente e `enforce_nonce`. A [documentação oficial do Discord](https://github.com/discord/discord-api-docs/blob/main/developers/resources/message.mdx)
limita essa deduplicação aos últimos minutos. O código permite recuperação automática somente
nos primeiros 120 segundos após marcar o primeiro envio. Depois disso, resultado ambíguo vira
`uncertain`, sem reenvio automático. Isso evita depender de deduplicação permanente inexistente,
mas não oferece garantia distribuída de entrega exatamente uma vez.

Timeout do Discord e perda da resposta do banco podem ocultar sucesso externo. A fila conserva
a reserva para recuperação; não confirma publicamente efeitos não persistidos. Uma chamada já
enviada não pode ser desfeita atomicamente por mudança de configuração ou revogação posterior.

## Antes da homologação

- Aprovar o modelo de proprietário/delegados, o texto mínimo dos logs e o comportamento de
  `/enviar` no modo novo. Configurações devem ser feitas por servidor; não há migração do JSON.
- Validar os tipos, defaults, triggers e privilégios reais de `auth_users`, sem alterar seu esquema.
- Validar as migrações e a fila com PostgreSQL/PostgREST de homologação e conexões independentes.
  PGlite exercita SQL real em memória, mas não substitui esse teste de concorrência.
- Verificar permissões/hierarquia do bot, canais e cargos com contas e servidores de teste autorizados.
- Definir retenção das tarefas, procedimento de inspeção/reconciliação de `failed`/`uncertain` e
  interface administrativa para essas operações. A recuperação automática existe; painel de
  reconciliação manual ainda não foi implementado.
- Avaliar a operação na Render Free: o worker para quando o serviço dorme; a fila retoma depois,
  mas não garante execução em tempo real e logs antigos ambíguos não serão reenviados.
- Decidir sobre os registros JSON existentes antes de qualquer reinício/deploy. Nenhuma ação
  desta etapa os recupera do serviço online ou autoriza sua perda.

Testes locais cobrem isolamento de configurações, proprietário/delegados, conflito de versões,
links/state/conta, callback Express, atualização do perfil, rollback, permissões SQL, tarefas
únicas, reservas concorrentes, recuperação após expiração, log ambíguo e efeitos simulados no Discord.
