# Persistência dos usuários verificados

O callback OAuth2 usa `src/database/verified-users.js` como fronteira de persistência.
Ele aguarda a confirmação do Supabase e depois mantém a gravação existente no wio.db.
Somente após ambas as gravações o fluxo atribui o cargo, envia o log e exibe sucesso.
Os comandos continuam lendo o JSON. Não há migração histórica, recuperação automática
do JSON pelo Supabase nem transferência automática de membros.

## Configuração para uma futura ativação autorizada

- `SUPABASE_URL`: URL HTTPS do projeto Supabase.
- `SUPABASE_SECRET_KEY`: chave secreta de servidor, com permissão para inserir,
  atualizar e consultar `public.auth_users`. Nunca usar no navegador ou no Git.
- As variáveis atuais do Discord continuam necessárias e não foram alteradas.
- `.env.example` contém apenas nomes e valores vazios. O `.env` real é ignorado pelo Git.

A tabela existente deve ter `discord_id` como chave primária ou UNIQUE para permitir
`upsert`, preferencialmente do tipo `text` para preservar o ID exato. IDs sempre são
enviados como strings, nunca como números JavaScript. `username` e `avatar` devem
aceitar texto, com `avatar` permitindo NULL; as datas devem aceitar timestamps ISO UTC
(preferencialmente `timestamptz`). Outros campos obrigatórios, se existirem, precisam
ter defaults. Nenhuma alteração de schema ou política RLS foi executada.

A aplicação envia exclusivamente `discord_id`, `username`, `avatar`, `verified_at`
e `updated_at`. As duas datas representam a última verificação concluída no Supabase,
atualizadas em cada nova verificação. O avatar preserva o hash retornado pelo Discord.
A confirmação consulta somente `discord_id`; resposta vazia, erro ou ID diferente
impedem o sucesso. A requisição possui timeout de 10 segundos.

## Compatibilidade com a Render

O SDK instalado (`@supabase/supabase-js` 2.117.3) exige Node.js >=22. O projeto declara
`>=22.0.0 <23` em `package.json`; os testes locais usam Node.js 22.23.2.
A Render suporta `engines.node`, mas `NODE_VERSION`, `.node-version` e `.nvmrc`
têm precedência, nessa ordem. Não há arquivos locais de override neste projeto.
Não foi possível confirmar a variável ou a versão efetivamente usada pelo serviço
existente. Verificar o Node nos logs de build antes de um futuro deploy autorizado.

Documentação: https://render.com/docs/node-version

## Falhas e limitações

- Sem configuração válida ou confirmação do Supabase, não há gravação nova no JSON,
  atribuição de cargo, log de sucesso ou página de sucesso.
- As gravações Supabase/JSON não são uma transação única. Se o JSON falhar após a
  gravação remota, o registro remoto permanece, mas a página mostra falha. Uma nova
  autorização OAuth repete o upsert sem criar outro registro para o mesmo ID.
- Um timeout pode ocorrer após o banco ter gravado; por isso a aplicação não confirma
  sucesso sem receber a resposta. Não existe fila de repetição em segundo plano.
- Falhas de cargo continuam não fatais, conforme o comportamento anterior. Falhas
  do webhook são registradas com mensagem fixa e não invalidam a persistência.
- Logs da aplicação não incluem tokens, e-mails, IPs, user-agent ou erros brutos dos
  provedores. A página de erro ignora mensagens arbitrárias na query string.
- O JSON mantém temporariamente tokens OAuth, e-mail, IP e dispositivo, no formato
  legado. Esse armazenamento não se torna persistente por causa desta integração.
  Os comandos dependentes dele e suas contagens ainda precisam de migração futura.
- A chave secreta tem privilégios elevados e deve ficar exclusivamente no servidor.
  Políticas RLS, permissões e constraints reais do banco ainda precisam de validação.
- A sanitização cobre o código da aplicação; configurações de logs externos da
  plataforma não foram inspecionadas ou modificadas.

## Verificação local

Execute `npm test` (`npm.cmd test` no PowerShell com scripts bloqueados).
Os testes usam o SDK real com transporte HTTP simulado e armazenamento em memória.
Eles não inicializam o bot, não gravam no JSON real, não acessam o Supabase real
e não adicionam membros a servidores. Cobrem payload, upsert, timeout, configuração,
falhas dos provedores, confirmação de sucesso e ausência de dados sensíveis nos logs.

Para migrar os comandos depois, ampliar o repositório com operações explícitas de
consulta e adaptar os consumidores separadamente. `auth_users` contém apenas perfil
e datas; não substitui o armazenamento de credenciais necessário ao comando legado.
