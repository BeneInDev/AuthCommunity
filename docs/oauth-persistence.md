# Persistência privada OAuth2 — etapa local

Para o modo multisservidor, perfil atômico e recuperação de cargo/log, consulte
[a quarta etapa](multiguild-verification.md). O restante deste documento descreve também
o modo privado de servidor único, preservado quando `OAUTH_MULTIGUILD_ENABLED=false`.

O callback pode utilizar esta estrutura somente com `OAUTH_PRIVATE_ENABLED=true`.
Por padrão, o fluxo existente continua ativo. `/puxar` usa estas tabelas somente com a opção
adicional `OAUTH_MEMBER_JOIN_ENABLED=true`; veja [a terceira etapa](member-join.md).
Não importa usuários nem concede consentimentos antigos.
As migrações não foram aplicadas ao Supabase. `public.auth_users` permanece intacta.

## Estrutura

- `202610140001_private_oauth_tables.sql`: quatro tabelas no schema `private`, restrições, índices e RLS.
- `202610140002_private_oauth_rpc.sql`: 13 funções transacionais, com `search_path` fixo, acessíveis somente a `service_role`.
- `202610140003_oauth_callback_lifecycle.sql`: cinco RPCs adicionais para callback atômico, reautorização e revogação recuperável.
- `202610140004_member_join_service.sql`: continuidade do Gateway, saídas e operações protegidas de inclusão.
- `oauth_authorizations`: identidade Discord/aplicação, envelope criptografado, expiração de acesso, escopos, versão e reserva de renovação.
- `guild_consents`: autorização explícita para um destino e versão de política, validade e revogação. Um consentimento ativo por autorização/destino.
- `oauth_flows`: hashes de sessão/state, destino, política, validade de dez minutos e consumo único.
- `member_join_operations`: reserva única por consentimento e resultado, inclusive `uncertain`.

As tabelas não concedem acesso direto a `anon`, `authenticated` ou `service_role`.
As funções ficam em `public` para descoberta via RPC; isso não concede execução pública.
O proprietário das funções deve ser uma identidade administrativa confiável, nunca um papel do navegador.
Não adicionar `private` aos schemas expostos pela API. Administradores do banco continuam sendo uma fronteira de confiança.

O backend usa comparação de versão e reservas de 60 segundos. Renovações ambíguas exigem nova autorização;
não há repetição automática com refresh_token possivelmente utilizado. As chamadas RPC têm timeout de dez
segundos e repetição automática desativada. Um timeout pode acontecer após o commit: não significa rollback.
O consumidor futuro deve reconciliar o resultado antes de tentar novamente.

A reserva de entrada consome o consentimento mesmo quando o resultado posterior falha ou é incerto.
Isso evita reentrada silenciosa. O banco não torna atômica uma chamada externa ao Discord.
Uma revogação concorrente não consegue cancelar uma requisição já enviada ao Discord.

## Criptografia e variáveis

Manter os segredos exclusivamente no backend, fora do banco, logs, Git e respostas HTTP:

| Variável | Uso |
| --- | --- |
| `SUPABASE_URL` | URL HTTPS do projeto |
| `SUPABASE_SECRET_KEY` | Chave secreta do backend com execução das RPCs como `service_role` |
| `OAUTH_TOKEN_KEYS` | Objeto JSON: identificadores de versão associados a chaves aleatórias de 32 bytes em base64url sem padding |
| `OAUTH_TOKEN_ACTIVE_KEY_ID` | Identificador da chave utilizada nas novas criptografias |
| `OAUTH_STATE_SECRET` | Segredo independente do fluxo OAuth2 existente; não reutilizar como chave dos tokens |
| `OAUTH_PRIVATE_ENABLED` | `false` por padrão; somente `true` ativa as novas rotas |
| `OAUTH_CONSENT_DAYS` | 30 por padrão; inteiro entre 1 e 90 |
| `OAUTH_MEMBER_JOIN_ENABLED` | `false` por padrão; requer OAuth privado ativo e migração 004 |

As demais variáveis atuais do bot e Discord permanecem necessárias. Com a opção desabilitada,
não se instanciam os repositórios novos. O modo privado exige `OAUTH_STATE_SECRET` independente,
`CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, `GUILD_ID` e as chaves do Supabase e de criptografia.
Não colocar valores reais em exemplos. Gerar as chaves com um gerador criptográfico em ambiente
administrativo seguro, transferindo diretamente para o gerenciador de segredos.

AES-256-GCM usa nonce aleatório de 96 bits e tag de 128 bits. O AAD vincula versão de formato,
identificador da chave, UUID da autorização, Discord ID e aplicação Discord. Trocar um envelope entre
identidades falha na autenticação. O índice de chave/nonce rejeita duplicações entre envelopes atuais;
a unicidade global dos nonces aleatórios é probabilística, não um contador persistente.
O payload aceita somente access_token e refresh_token; este último pode ser nulo.
Somente o método explícito de descriptografia retorna tokens em memória. Buffers temporários são
limpos, mas strings e cópias internas do runtime JavaScript não oferecem apagamento garantido.

Rotação: distribuir a chave nova junto das antigas para todas as instâncias, mudar a versão ativa,
recriptografar com comparação de versão, verificar conclusão e só então retirar a chave antiga.
Conservar backups protegidos das chaves enquanto existirem backups de dados que dependam delas.
Perder as chaves inviabiliza recuperar tokens; comprometer backend e chaves permite descriptografá-los.

## Integração futura e decisões pendentes

Antes de ativar esta arquitetura, implementar e revisar:

1. Revisar a interface de consentimento implementada e a política de retenção/limpeza. O destino
   atual é exclusivamente `GUILD_ID`; incluir outros destinos exige uma lista autorizada e nova revisão.
2. A validade inicial é de 30 dias, com uma tentativa por consentimento. Validar o texto de política
   `guild-join-v1` antes da ativação; não reusar a versão se mudar o significado do consentimento.
3. O callback novo grava somente nas tabelas privadas. Não atualiza `auth_users`, não escreve JSON,
   não atribui cargo e não publica webhook. Revisar esses efeitos de produto antes de substituir o fluxo atual.
4. Os serviços internos implementam renovação e revogação no Discord, mas não há endpoint público
   para gerenciamento. Criar uma interface autenticada de revogação e uma rotina de recuperação
   de operações pendentes antes de ativar em produção. Não usar `revokeLocally` como substituto da revogação externa.
5. Homologar o `/puxar` opt-in da terceira etapa. Paginação além de lotes de 100,
   recuperação de reservas expiradas e reconciliação administrativa ainda não estão integradas.
6. Responsáveis pela custódia, backup e rotação das chaves; procedimento de incidente.

## Implantação futura, somente após autorização

1. Decidir a preservação dos registros atuais antes de reiniciar ou publicar na Render. Este código
   não extrai o JSON do serviço online. Deploy/reinício pode perder o armazenamento efêmero.
2. Revisar migrações em um projeto descartável de homologação com dados fictícios. Verificar
   permissões reais do PostgREST, papel da chave secreta e chamadas concorrentes em conexões distintas.
3. Com backup e autorização, aplicar os quatro arquivos em ordem por um executor administrativo
   com controle de versões. Cada arquivo contém sua própria transação; registrar a versão aplicada.
   Não executar novamente arquivos já aplicados; corrigir por nova migração revisada.
   As migrações não fazem parte do startup do bot.
4. Configurar os segredos pelo mecanismo seguro de implantação, após aprovação. Nunca expor
   a chave secreta ou chaves AES no cliente. Validar RPCs com dados fictícios e confirmar negação para anon/authenticated.
5. Concluir os consumidores e a gestão de autorizações, testar recuperação de falhas e só então publicar.
   Não desligar o armazenamento legado até confirmar a estratégia de transição.
6. Em caso de falha, desativar a integração futura; não apagar tabelas nem chaves como rollback.
   Não há migração destrutiva de reversão incluída.

## Validação local

`npm test` executa testes de criptografia, adulteração, AAD, rotação, sanitização de erros,
repositórios e SQL em PostgreSQL em memória via PGlite (dependência somente de desenvolvimento).
Os testes usam identidades fictícias e chaves efêmeras e não carregam `.env`.
Cobrem permissões, restrições, rollback, consentimento, expiração e operações com versões/reservas
desatualizadas. Não substituem teste de múltiplas conexões nem a configuração real do Supabase/PostgREST.
Executar também `npm audit --omit=dev` e `git diff --check` antes de solicitar publicação.

## Fluxo opt-in implementado na segunda etapa

`GET /oauth2/start` apresenta nome e ID do servidor conhecido pelo bot. O formulário tem checkbox
desmarcado e um state assinado, vinculado ao cookie HttpOnly/Secure/SameSite e ao destino.
`POST /oauth2/consent` exige a origem exata de `REDIRECT_URI`, assinatura, cookie, validade e aceite
explícito. A origem não é inferida de Host ou headers do proxy. O banco guarda hashes, não cookies
ou state em texto puro. A confirmação cria um fluxo antes de redirecionar ao Discord.

O callback rejeita parâmetros de destino, valida outra fase da assinatura e reserva o fluxo no banco
antes de trocar o código. Assim, duas instâncias não trocam o mesmo código. Só então consulta a identidade
no Discord e grava tokens criptografados, expiração, escopos efetivamente concedidos e consentimento
em uma única transação. Reautorização usa comparação de versão e não ressuscita consentimentos consumidos.
Não há sucesso sem confirmação da RPC. O fluxo pede apenas `identify guilds.join`; não pede e-mail nem guarda IP.

O state dura dez minutos. A autorização expira conforme `expires_in` do Discord, independentemente
dos 30 dias de consentimento. Se faltarem os escopos necessários ou refresh_token, o fluxo falha.
Mudanças de destino, chave de assinatura ou duração de consentimento invalidam fluxos em andamento.

Renovação usa uma reserva exclusiva e grava os tokens novos antes de retornar. Falha ambígua bloqueia
o uso, sem repetição automática do refresh_token. Uma reserva cujo resultado se perdeu pode exigir
reconciliação administrativa; não existe scheduler nesta etapa.

Revogação primeiro marca `revocation_pending`, bloqueia renovação/entrada/reautorização e revoga os
consentimentos ativos. O ciphertext fica recuperável até o Discord confirmar a revogação. Só então
é apagado, com comparação de versão. Falha externa mantém o bloqueio; nova tentativa pode ser feita
pelo backend após a reserva de 60 segundos. O serviço não revela tokens nem detalhes de erros.
Esses métodos são internos: quem os chamar deve autenticar e autorizar o titular, nunca confiar
em um UUID recebido diretamente de uma requisição pública.

Não há atomicidade entre Discord e PostgreSQL: uma resposta perdida pode esconder um commit concluído.
O callback responde com falha genérica nessa situação, sem fallback nem repetição cega. A emissão do token
no Discord pode ter ocorrido mesmo que a persistência falhe; o usuário pode revogar o aplicativo no Discord.
Não executar revogação automática nessa falha, pois ela pode invalidar uma autorização concorrente válida.

O callback não adiciona membros. A terceira etapa oferece um `/puxar` separado, opt-in, com
invalidação por saída e por perda de continuidade dos eventos. Uma saída jamais constitui
consentimento novo. O comando legado continua disponível quando a nova opção está desabilitada;
ele não oferece as garantias da arquitetura privada. Manter ambas as opções desativadas em
produção até concluir homologação e receber autorização. Não usar registros legados como fallback.

Referência do protocolo: [documentação OAuth2 oficial do Discord](https://github.com/discord/discord-api-docs/blob/main/developers/topics/oauth2.mdx).
