# Lockd — Fase 1 concluída, Fase 2 aguardando liberação

Atualização: 24/10/2026. Repositório: `~/Claude/locked`. Sem commit, push, dependência nova, instalação ou alteração de configurações. Não foi aberto o app pessoal, nem lido/alterado o cofre real, Keychain ou credenciais. Todos os testes criptográficos usaram chaves falsas e LOCKD_HOME temporário.

## Resultado real

Comando executado serialmente: `LOCKD_HOME=<temporário> swift test --package-path Lockd --jobs 2` (equivalente a `cd Lockd && swift test --jobs 2`). Saída final:

```text
Test Suite 'All tests' passed at 2026-10-24 10:29:55.490.
 Executed 43 tests, with 0 failures (0 unexpected) in 1.536 (1.543) seconds
```

Zero testes ignorados. Nove casos novos além da revisão anterior: três de sessão e seis de argv, confirmação de curinga, executável confiável, sandbox, consentimento e audit. Os quatro testes de caracterização tratados nesta fase foram invertidos: presets/hosts, Git, leitura file:// e .env por padrão. Os cinco casos remanescentes de caracterização continuam evidenciando problemas abertos de redactor, JSON, ciphertext e wire; o resultado verde não declara esses problemas corrigidos.

`swift build --package-path Lockd -c release --jobs 2`: exit 0, `Build complete! (35.58s)`. Compilou app e CLI, sem assinar ou executar o app. Isso também verifica que o inicializador de sessão simulada, somente DEBUG, não é necessário ao build de produção. Permanecem warnings de código preexistente, sem falha de compilação. `git diff --check`: passou.

## O que mudou

- **Vault.swift**: relógio injetável interno DEBUG com sessão simulada separada do LOCKD_HOME legado; presença de sessão antes de cache; expiração limpa contexto/cache; geração de sessão evita reutilizar aprovações e resultados atravessando lock/unlock. `fresh: true` usa LAContext novo sem janela configurada de reutilização biométrica.
- **Policy.swift**: todos os presets sem curingas e sem CLIs que executam código; somente curl onde aplicável. AWS fica sem comandos/hosts padrão até configuração exata. allowEnv nil=false, incluindo itens existentes sem opt-in explícito. Executável e ancestrais reais devem pertencer a root, não ser graváveis por grupo/outros ou efetivamente pelo usuário; isso recusa Homebrew/binários locais graváveis.
- **CurlArguments.swift** (novo): linguagem fechada, opções longas com `=`, curtas agrupadas e argumentos anexos; recusa config/proxy/arquivos/cookies/output/redirects/opções desconhecidas. HTTPS em porta 443, sem userinfo, uma URL. Força `-q` primeiro, `--proto =https`, `--max-redirs 0` e globoff. `--write-out` também recusado, pois pode escrever arquivos. Referências @arquivo são recusadas, e @ literal dentro de JSON/email inline continua permitido. CR/LF de headers verificado por bytes, inclusive o Character CRLF do Swift.
- **Broker.swift**: somente curl validado nesta fase, inclusive para regra personalizada; substituição em configuração gerada internamente por stdin, nunca em argv; revalidação depois de substituir protege contra @arquivo/CRLF introduzidos pelo valor. Valores também podem estar no ambiente do curl, como previsto, sem promessa de isolamento contra o mesmo UID. Caminho resolvido no audit. Novo destino/conjunto de chaves .env pede autenticação nova mesmo durante sessão; repetição na mesma sessão reaproveita consentimento. Lock/restart/novo desbloqueio observado revoga esse conjunto. Resposta e audit incluem o aviso de leitura por qualquer processo do usuário.
- **Sandbox.swift**: realpath para cwd/proteções/temporários, incluindo ancestral existente de caminho ainda ausente; pastas SSH/AWS/GnuPG/GitHub/npm/netrc/kube/docker/Keychains e locais conhecidos de gerenciadores de senhas negados. Escrita só no cwd, /tmp e temporário privado da chamada; exceção explícita para /dev/null. Sem cwd, usa o temporário da chamada em vez do home. Não é isolamento completo da pasta pessoal.
- **Models.swift / Access.swift**: confirmação explícita de curingas, aviso solicitado e evento policy_wildcard. Curingas personalizados antigos sem marcador ficam inativos; reintrodução exige confirmação. Marcador ainda adulterável por edição do JSON: S03 continua aberto até assinatura de regras. Interruptor .env/hosting desligado por padrão e texto explica a exposição. Supabase pede host exato do projeto. Mudanças locais apenas no bloco de acesso; redesenho e Activity preservados.
- **Audit.swift**: campo opcional resolvedProgram, compatível com logs antigos.
- **lockdctl/main.swift**: descrição MCP de .env e instruções honestas; explica curl validado e stdin.
- **BrokerTests.swift / SecurityReviewTests.swift / PhaseOneTests.swift (novo) / VaultSessionTests.swift (novo)**: inversões e provas positivas/negativas, sem chaves reais. Provas diretas de sandbox evitam um falso positivo causado somente pela recusa no parser.
- **SECURITY-REVIEW.md / STATUS.md**: tabela com Status e limites residuais.

`Library.swift`, `Folders.swift`, `Theme.swift` e os commits do proprietário não foram revertidos nem modificados. Os scripts/documentos de release anteriores continuam sem commit; não foram refeitos. O arquivo do prompt do proprietário não foi alterado.

## Estado dos achados

S05 corrigido no controle de sessão/cache. S01/S02/S06/S07/S08/S09 parcialmente mitigados: permanecem processo filho, leitura por mesmo UID quando .env é habilitado, hosts exatos multitenant, regras editáveis e limites de sandbox/redactor. S03/S04/S10/S17 seguem abertos para a arquitetura autorizada da Fase 2. S11–S16 permanecem conforme a tabela completa; fora do escopo desta fase.

Não há assinatura de regras, formato v3/AAD, migração do cofre, derivação/verificação da pública a partir do blob, lockd_http ou cliente HTTP seguro implementados nesta fase. O mecanismo de Secure Enclave existente foi preservado.

## Não verificado

- Touch ID real, fallback por senha, criação do SE com tela bloqueada e confirmação visual de presença nova por destino. Testes usam handlers simulados; código novo chama autenticação fresca no caminho de produção, mas isso não foi validado interativamente.
- Cliques na confirmação de curinga e apresentação/layout dos novos textos no app; SwiftUI compilou. Audit da confirmação está implementado, mas o fluxo visual não foi acionado no app real.
- `ps -ww` / `lsof` durante chamada lenta deste build. O argv executado pelo caminho Broker está constante por construção/teste; a prova de observação fica para Fase 2.
- Gatekeeper, assinatura/notarização, execução do app instalado, FSEvents, notificações, CGEvent e SMAppService nesta fase. Nenhum novo DMG foi produzido.
- Escape por Mach, hardlinks, aliases APFS/Data, cobertura de todos os gerenciadores de senhas, memória/IPC do mesmo UID, DoS completo e TOCTOU do .env. A denylist de pastas sensíveis não cobre todo arquivo secreto possível.
- Nova auditoria humana independente. Os testes verdes remanescentes de caracterização não fecham os achados da próxima fase.

## Próxima decisão

Parado ao fim da Fase 1, conforme instrução. Aguardar **“libera a Fase 2”**. Não é necessário certificado Apple para avançar no código da Fase 2; conta Apple e validação interativa continuam pendentes para distribuição real.
