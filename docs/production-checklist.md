# Checklist da primeira publicação

Revisão local: quarta etapa implementada. Não equivale a homologação no Discord ou Supabase real.
O proprietário aceitou a perda do JSON temporário e a necessidade de nova verificação.
Não importar registros antigos nem gerar consentimentos a partir deles. Nenhuma publicação foi executada.

## Escopo disponível

- Verificação multisservidor: origem e destino iguais, link pessoal assinado, consentimento explícito,
  perfil + autorização criptografada + consentimento + tarefas gravados na mesma transação.
- Cargo e logs são processados depois do commit, pela fila persistente. Configurar ambos em cada
  servidor; campos vazios não geram tarefas. Cargo exige membro presente e triagem concluída.
- Configurações isoladas: proprietário do servidor e delegados explícitos. Só o proprietário delega.
- `/puxar`: exclusivo de `OWNER_ID`, somente destino `GUILD_ID`, consentimento válido específico,
  uso único e sem fallback JSON. Não é um comando multisservidor nesta versão.
- Após saída ou perda de continuidade do Gateway, autorizações antigas não habilitam nova entrada.
  Reinício/suspensão pode exigir novo consentimento mesmo com tokens preservados no Supabase.
- Renovação usa reserva/versão; resultado ambíguo bloqueia reutilização do refresh token.
  Revogação bloqueia localmente antes de chamar o Discord; falha externa mantém estado pendente.
  Não existe interface pública de revogação nem rotina automática para retomar revogações pendentes.
- Não é necessário conteúdo prévio de config.json, message.json ou users.json no modo novo.
  Os adaptadores legados só abrem arquivos quando efetivamente acessados. O legado permanece disponível.

## Variáveis para o modo completo

| Variável | Configuração necessária |
| --- | --- |
| `TOKEN` | Token do bot, somente backend |
| `CLIENT_ID` | ID da mesma aplicação Discord |
| `CLIENT_SECRET` | Segredo OAuth2 da aplicação |
| `REDIRECT_URI` | URL HTTPS pública terminando em `/oauth2/callback`, idêntica à registrada no Discord |
| `OWNER_ID` | ID do operador autorizado a executar `/puxar` |
| `GUILD_ID` | Único destino permitido pelo `/puxar`; bot presente nesse servidor |
| `SUPABASE_URL` | URL HTTPS do projeto correto |
| `SUPABASE_SECRET_KEY` | Chave secreta backend desse projeto, com execução das RPCs como service_role |
| `OAUTH_STATE_SECRET` | Segredo aleatório independente, mínimo 32 caracteres, diferente de CLIENT_SECRET |
| `OAUTH_TOKEN_KEYS` | Objeto JSON de IDs de chave para chaves AES aleatórias de 32 bytes em base64url sem padding |
| `OAUTH_TOKEN_ACTIVE_KEY_ID` | ID existente no objeto acima; conservar chaves antigas necessárias para descriptografia |
| `OAUTH_PRIVATE_ENABLED` | `true` |
| `OAUTH_MULTIGUILD_ENABLED` | `true` |
| `OAUTH_MEMBER_JOIN_ENABLED` | `true` para `/puxar` privado; `false` mantém o comando legado, não o desativa |
| `OAUTH_CONSENT_DAYS` | `30`; intervalo aceito: 1 a 90 dias |
| `NODE_ENV` | `production` |
| `NODE_VERSION` | `22` para respeitar engines >=22 <23; conferir versão efetiva no build |
| `PORT` | Usar a variável fornecida pelo serviço; o código já a lê |

Não são necessárias ROLE_ID/LOG_CHANNEL_ID para o modo multisservidor: cadastrar cargo/canal no
`/configurar` de cada servidor. As flags continuam false por padrão no código/exemplo.
Guardar backups seguros das chaves AES fora do banco; perdê-las impede recuperar os tokens.
A Render prioriza NODE_VERSION sobre engines: [documentação oficial](https://render.com/docs/node-version).

## Migrações e pré-condições

Aplicar uma única vez, em ordem, com executor administrativo confiável e registro de versões:

1. `202610140001_private_oauth_tables.sql`
2. `202610140002_private_oauth_rpc.sql`
3. `202610140003_oauth_callback_lifecycle.sql`
4. `202610140004_member_join_service.sql`
5. `202610140005_guild_verification.sql`

Cada arquivo tem BEGIN/COMMIT. Não repetir migrações já aplicadas. O startup não executa SQL.
`public.auth_users` deve existir com os cinco campos previstos, discord_id textual com chave
única/primária para ON CONFLICT, e timestamps compatíveis. Conferir triggers e privilégios reais;
as migrações não alteram seu esquema. Não expor o schema private no PostgREST.
Os testes executam os cinco arquivos em PostgreSQL em memória, incluindo rollback e permissões.
Isso não valida o esquema real nem concorrência entre conexões independentes.

## Sequência mínima, somente após autorização de publicação

1. Homologar os cinco arquivos e RPCs num ambiente separado, com dados fictícios; negar acesso
   anon/authenticated, confirmar acesso backend e compatibilidade de auth_users.
2. Preparar aplicação Discord: callback HTTPS exato; bot nos servidores; intents GuildMembers
   e MessageContent disponíveis (ambos solicitados pelo código); Manage Roles, hierarquia acima
   do cargo configurado e acesso de leitura/envio aos canais usados.
3. Revisar o diff final e arquivos a publicar, excluindo .env, JSON de usuários, logs e arquivos
   locais indevidos. Coordenar o deploy automático da main: preparar migrações, variáveis e janela
   antes do push autorizado. Não supor que alterar variáveis mantém o serviço antigo em execução.
4. Com autorização e backup do banco, aplicar as migrações pendentes e preparar todas as variáveis
   acima. Build: `npm ci --omit=dev`; start: `node index.js`. Não há script npm start atualmente.
5. Publicar a revisão autorizada. Registrar os comandos com `node deploy-commands.js` se necessário,
   usando as mesmas credenciais da aplicação; não executar esse registro no build de cada deploy.
6. Em cada servidor, o proprietário usa `/configurar`, informa cargo/canal, mensagem e ativa a
   configuração. `/enviar` ainda pede desc/tipo, mas no modo novo usa a mensagem cadastrada.
7. Validar com contas autorizadas: OAuth2, perfil, cargo, log, negação entre servidores, renovação,
   revogação e `/puxar` no destino permitido. Não anunciar sucesso só porque a página HTTP abriu:
   confirmar também Gateway, fila e efeitos no Discord.
8. Em incidente, suspender acesso/serviço ou desativar configurações afetadas; não desligar flags
   como se isso desativasse funcionalidades: desligá-las reativa o legado. Não apagar banco/chaves.

## Pendências de homologação e operação

- PostgreSQL/PostgREST real, concorrência independente, permissões e hierarquia Discord.
- Recuperação após reinício, timeouts e respostas perdidas; cargos idempotentes, logs com nonce
  limitado no tempo. Logs ambíguos antigos ficam uncertain, sem reenvio automático.
- Procedimento restrito para revogação pendente, operações failed/uncertain e bloqueios do `/puxar`;
  não há painel administrativo de reconciliação nesta versão.
- Worker depende do processo estar ativo. Não garante prazo de entrega durante suspensão do serviço.
- Aceitar expressamente o destino único do `/puxar` e a nova autorização após quebra de continuidade;
  persistência de tokens não significa autorização perpétua para reincluir membros.

Detalhes: [verificação multisservidor](multiguild-verification.md),
[inclusão de membros](member-join.md), [criptografia e ciclo OAuth2](oauth-persistence.md).
