# Lockd — Fase 2 implementada

24/10/2026. Código em `~/Claude/locked/Lockd`. Sem commit/push, sem dependência nova, sem instalar/abrir o app pessoal e sem acesso ao cofre real, Keychain, credenciais ou `~/.claude/settings.json`. Fase 1 preservada em `history/STATUS-FASE-1.md`.

## Resultado real

Testes serializados com `LOCKD_HOME` temporário:

```text
Test Suite 'All tests' passed at 2026-10-24 13:37:04.293.
 Executed 57 tests, with 0 failures (0 unexpected) in 4.467 (4.477) seconds
```

Comando: `swift test --package-path Lockd --jobs 2` (equivalente a entrar em Lockd e executar `swift test --jobs 2`). Zero ignorados. Foram adicionados 14 testes da Fase 2; provas anteriores de JSON/ciphertext/segredo curto foram invertidas. O caso de redactor com espaçamento/UTF-16 e o limite do wire continuam caracterizando achados abertos, não correções.

Build produção: `swift build --package-path Lockd -c release --jobs 2` terminou com exit 0, `Build complete! (26.89s)`. Warnings preexistentes de Audit/Toast permanecem; sem erro de compilação. O CLI release foi executado com LOCKD_HOME descartável: `lockd_http` apareceu e `lockd_run` ficou oculto, sem lançar o app. `git diff --check` passou.

O teste de HTTPS externo usou apenas chave falsa, em api.anthropic.com, confirmou resposta via túnel fixado e TLS padrão. Os outros ataques HTTP usam servidor local falso, com exceção DEBUG explícita. Não houve chamada real autenticada à Vercel.

## Arquivos da Fase 2

- **Novos LockdCore/SecureHTTPClient.swift e HTTPPlan.swift:** HTTP interno com URLSession efêmera/delegate; HTTPS público em porta 443, DNS público e upstream fixado ao endereço aprovado por proxy CONNECT local. Headers reservados/controle recusados; nenhum redirect seguido. Corpo inline/string/JSON, substituição somente em valores de headers/query/body, limites de 256 KB/1 MB, timeout, binário omitido e resposta mascarada/marcada como não confiável. JSON recebe Content-Type apropriado por padrão.
- **Broker.swift:** operação `http`, presença nova por combinação chave/host/regra assinada na sessão; verificações de método/prefixo. Modelos com placeholders no audit, sem valores substituídos. `run` recusa por padrão, mesmo se uma chamada antiga tentar contornar o catálogo MCP.
- **Novo LockdCore/BrokerSettings.swift:** preferência avançada desligada por padrão. Testes usam estado de software, sem alterar UserDefaults reais.
- **Novo LockdCore/RuleSigner.swift; Policy.swift e Models.swift:** assinatura P-256 separada do SE com privateKeyUsage+userPresence; payload canônico inclui identidade/metadados, hash do cipher, regras, versão e restrições HTTP. Verificação pela pública derivada do blob, sem assinatura nova. Manifesto assinado e maior contador em memória. Sem assinatura válida, nenhuma regra ativa.
- **Store.swift:** autorização local explícita em lote, conferência do snapshot antes/depois do prompt e persistência; não há endpoint MCP que assine regras. Migração de v2 na autenticação/leitura, ou na aprovação do lote. Estado não assinado permanece não autorizado. Carregamento/adicionamento de item sem assinatura ou com assinatura inválida registra recusa no audit.
- **Vault.swift:** novos ciphers v3 com AAD = UUID+versão e HKDF separado; cache também ligado ao UUID. Leitura v2 compatível, sem criar v2 novo em produção. Pública derivada do blob e comparada à cópia pública; inconsistente recusa cifrar. Blob ausente com dados/cópia pública existente ou itens ilegíveis não regenera silenciosamente a chave. Somente testes DEBUG têm gerador de fixture v2.
- **FilterProxy.swift:** modo de upstream fixado a IP aprovado e encerramento dos túneis ao terminar a chamada. Modo antigo permanece para programas avançados.
- **EnvFile.swift:** VercelPush usa o mesmo cliente HTTP seguro; produção sem development envia sensitive; combinações com development usam encrypted. Override de URL de fixture só em DEBUG. write_env mantém as restrições e o limite de TOCTOU já documentados.
- **Redactor.swift:** segredos curtos também filtrados, com tabelas de tamanhos distintas; audit HTTP preserva placeholders mesmo se o nome coincidir com uma fatia do segredo. Isso não resolve toda transformação arbitrária.
- **lockdctl/main.swift:** ferramenta MCP lockd_http, CLI `http` lendo modelo limitado de stdin; catálogo de programas depende da capacidade informada pelo Broker e falha fechado quando ele está indisponível. Descrições honestas.
- **Access.swift:** edição/assinatura com autenticação nova, métodos/prefixos opcionais, estado inválido claro. Reset vira sugestão até assinar.
- **Novo Lockd/SecuritySettings.swift:** toggle avançado com aviso, revisão explícita do lote e estado da chave/recuperação.
- **Library.swift:** apenas inserção do bloco de segurança, mensagem visível se salvar falha e correção da alegação absoluta. Sem reversão de layout/pasta/árvore/atividade. **Folders.swift e Theme.swift não alterados.**
- **Lockd/main.swift:** selftest ajustado à API v3; o selftest real não foi executado.
- **Testes:** novo PhaseTwoTests.swift; ajustes em BrokerTests/DetectorTests/PhaseOneTests/SecurityReviewTests/VaultSessionTests para autorizar regras falsas e exigir as novas recusas.
- **README.md, docs/SECURITY-REVIEW.md, STATUS.md, UNINSTALL.md, beta/README.md e history/**: contrato atual, tabela de Status e histórico.

Arquivos de release da entrega anterior e seus untracked continuam sem commit. Package.swift não recebeu dependência. O DMG/app de dry-run ainda em `Lockd/dist` é da Fase 1; **não corresponde ao novo código e não deve ser publicado como Fase 2**. Nenhum novo DMG foi gerado.

## O que foi verificado

- Host sem política/assinatura, edição de JSON, swap de cipher/UUID e acesso v3 sem ID recusados.
- Migração de fixture v2 para v3, preservação do valor falso e assinatura válida do estado aprovado.
- Rollback de item isolado e de manifesto antigo durante a sessão recusados.
- Proxy/HTTPS real com chave falsa; redirect não segue nem encaminha Authorization para outro destino.
- IPs privados/literais, DNS de localhost, CRLF/header Host, corpo grande, resposta truncada, binário e timeout.
- Segredo chega ao servidor falso e seu eco não volta em texto ao cliente; audit retém placeholders sem o valor falso.
- Primeira chave/host pede handler fresco; repetições na mesma sessão reutilizam, outro host/bloqueio revogam.
- Durante chamada lenta: chave falsa ausente em ps -ww do processo de teste e nos caminhos/descritores de lsof desse processo. Não é teste de RAM ou de todo o sistema.
- MCP esconde run por padrão e responde ao estado desligado/ligado do Broker; comportamento desligado confirmado também no binário release.

## Não verificado e limites importantes

**Não verificado:** Touch ID real (incluindo quantidade de prompts), assinatura/verificação da chave real do Secure Enclave sem novo prompt, Mac bloqueado, migração de um cofre real/legado no SE, layout/cliques da UI, Gatekeeper/notarização e conta real Vercel. Chaves de teste são de software; não equivalem a uma prova de SE.

A assinatura local detecta adulteração de itens com a identidade confiável atual; **não cria uma âncora externa**. Restaurar todo o estado antigo após reinício ou substituir também a identidade de chave e o manifesto não tem garantia de detecção. Esse limite permanece em S03/S17. O contador em memória só cobre a sessão atual. Não adicionamos Keychain/servidor/serviço externo para alegar o contrário.

Também permanecem: encodings arbitrários, hosts exatos multitenant/escopos de conta, processos avançados, inspeção de memória/IPC, DoS/framing do socket, TOCTOU de .env e logs externos. A tabela em SECURITY-REVIEW.md discrimina os escopos. Não há parecer de auditoria humana independente nem backup portátil implementado.

## Próximo passo do proprietário

1. Validar em **conta macOS/Mac de teste com dados falsos** o fluxo real de Touch ID: revisão/assinatura de lote, verificação sem prompt, primeiro HTTP chave/host, bloqueio/expiração e mensagem de perda/divergência da chave. Não usar LOCKD_HOME para afirmar teste real do SE: ele ativa software.
2. Revisar os limites de âncora de confiança e o relatório antes de considerar beta com segredos reais. Uma revisão humana independente continua recomendada para este conjunto de mudanças.
3. Só depois seguir os passos Apple de RELEASE.md para Developer ID/notarização; eles não foram executados. A escolha do backup portátil continua pendente em BACKUP-OPTIONS.md.

Não é necessária outra autorização para esta Fase 2: o código solicitado foi entregue. Não há instalação/publicação, migração do cofre pessoal ou execução de conta Apple nesta entrega.
