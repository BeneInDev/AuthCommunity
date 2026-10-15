# Correções locais de segurança

## OAuth2 e proxy

Os botões geram links para `/oauth2/start` na origem de `REDIRECT_URI`.
Essa rota cria uma sessão temporária de navegador em cookie HttpOnly, SameSite=Lax,
sem Domain, com validade de dez minutos. Em HTTPS o cookie usa Secure e o prefixo
`__Host-`. O state contém nonce e expiração, assinados por HMAC-SHA256 e vinculados
à sessão e à URL de callback. O callback valida a assinatura em tempo constante
e apaga o cookie antes da troca do código. Não há tokens OAuth no cookie/state.

A assinatura usa `OAUTH_STATE_SECRET` opcional ou, na ausência dele, `CLIENT_SECRET`,
com separação de domínio criptográfico. O segredo precisa de pelo menos 32 caracteres
e deve ser igual em todas as instâncias. Não é gerado novamente a cada processo.
Nenhuma configuração da Render foi alterada. `REDIRECT_URI` deve representar a URL
pública HTTPS: Secure não depende de `req.secure` ou de headers encaminhados pelo
proxy. O único HTTP permitido é localhost/loopback fora de NODE_ENV=production.

A solução não precisa de armazenamento de sessões em memória ou de uma nova tabela.
Uma nova tentativa substitui a sessão anterior naquele navegador; em abas concorrentes,
somente a tentativa mais recente terá o cookie correspondente. Cookies precisam estar
habilitados. Ao expirar ou falhar, iniciar novamente pelo botão de verificação.
Cookies já capturados não podem ser revogados globalmente sem armazenamento compartilhado;
a expiração limita sua validade e o Discord controla o uso único do código OAuth.

Links antigos que apontam diretamente para a autorização do Discord sem passar por
`/oauth2/start` não serão aceitos. Botões existentes com customId `verify_button`
continuam funcionando e passam a gerar o novo link. Links já emitidos, incluindo o
botão de teste de painéis antigos, precisam ser gerados novamente após a publicação.

## Permissões, HTML e requisições

- Slash commands e botões/modais administrativos verificam OWNER_ID; ausência de
  configuração nega acesso. A verificação pública permanece disponível para todos.
- O renderer faz escape de texto e atributos HTML com aspas. URLs de imagens são
  limitadas a HTTPS em cdn.discordapp.com; links de servidor, a discord.com/channels
  com ID numérico. A interpolação dentro de JavaScript foi removida do template.
- Axios usa timeout e AbortSignal de dez segundos; redirecionamentos HTTP externos
  não são seguidos, evitando encaminhar credenciais para destinos inesperados.
- Discord REST usa timeout de dez segundos e zero repetições de falhas HTTP/rede.
  O tratamento de rate limits do SDK continua ativo; o timeout limita cada requisição,
  não o tempo total na fila de rate limit nem a execução inteira de `/puxar`.
- Supabase mantém AbortSignal de dez segundos e desabilita repetição automática.
  Um timeout pode ocorrer depois de o servidor gravar: não há confirmação de sucesso
  sem resposta válida; uma nova autorização faz upsert pelo mesmo ID.

## Persistência e timestamps

Supabase é confirmado antes do JSON. Falha em qualquer etapa impede a página de
sucesso. Falhas do JSON são convertidas para LEGACY_USERS_SAVE_FAILED, sem expor o
erro original. Não há rollback destrutivo do Supabase: as gravações não são atômicas.
Os tokens e demais campos legados permanecem no JSON para preservar os comandos.
O Supabase recebe somente os cinco campos autorizados.

A lógica de timestamps não foi alterada. A aplicação ainda envia a mesma data em
verified_at e updated_at; o banco pode recalcular updated_at. Defaults e triggers
continuam pendentes de documentação, e nenhuma alteração SQL foi executada.

## Dependências e compatibilidade

Atualizações diretas: Axios 1.20.0, discord.js 14.27.0, body-parser 2.3.0.
O lockfile também atualiza dependências transitivas vulneráveis.
proxy-from-env 2.1.0 usa URL padrão em vez do parser legado. Mantém suporte a
HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY e precedência das variantes minúsculas.
A implementação instalada não consulta npm_config_proxy/npm_config_https_proxy:
ambientes que dependiam apenas dessas variáveis precisam revisar sua configuração
antes de publicar. Os destinos Discord usados pelo código são URLs HTTPS fixas.
Nenhum proxy foi configurado ou desabilitado globalmente pela aplicação.

Os testes usam credenciais fictícias, transporte simulado ou servidores HTTP locais.
Não conectam um bot nem consultam usuários reais. A auditoria local retornou zero
vulnerabilidades após a atualização; isso não substitui validação de configuração
e testes de integração em um ambiente autorizado antes de publicar.
