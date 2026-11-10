# Lockd

**A local, encrypted key vault for the Mac that lets AI coding agents use your API keys without ever seeing them.**
Keys are sealed to the Secure Enclave and opened with Touch ID. Agents (Claude Code, and any MCP client) call tools such as `lockd_http`, `lockd_supabase_sql` or `lockd_vercel_env`; Lockd fills the key in inside the app, limits each key to exact hosts, and returns the answer with the key masked.

> **Status: beta, not independently audited.** Apple Silicon, macOS 14+. No portable backup yet: losing your Mac or the vault files can make secrets unrecoverable. Start with keys you can rotate. See [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) for known limits. The detailed documentation below is in Portuguese (PT-BR).

Cofre cifrado vinculado ao Mac, com autenticação local, ferramentas e destinos limitados para agentes de desenvolvimento.

O Lockd organiza assets por projeto e guarda segredos textuais com ECIES P-256/AES-GCM usando o Secure Enclave. O acesso usa Touch ID ou senha do Mac, com sessão limitada. Arquivos organizados como assets/credenciais não recebem automaticamente a criptografia dos segredos textuais.

## Caminho recomendado: HTTP dentro do app

`lockd_http` faz a chamada dentro do Lockd, sem executar programa filho e sem colocar valores substituídos em argv/ambiente de subprocessos. Usa regras assinadas, hosts exatos e restrições opcionais de método/prefixo de caminho. Exemplo de modelo MCP:

```json
{
  "method": "GET",
  "url": "https://api.anthropic.com/v1/models",
  "headers": {"x-api-key": "{{ANTHROPIC_API_KEY}}", "anthropic-version": "2023-06-01"},
  "names": ["ANTHROPIC_API_KEY"],
  "timeout": 20
}
```

O nome da chave deve existir no projeto selecionado. Somente valores de headers/query/body aceitam substituição; host e caminho não aceitam placeholders. JSON é serializado depois da substituição, para preservar aspas e caracteres especiais. A CLI também aceita um modelo por stdin: `lockdctl http < request-template.json`.

A primeira combinação chave/host na sessão requer autenticação nova. O cliente aceita HTTPS público em porta 443; valida todos os IPs resolvidos e fixa o upstream a um deles, preservando o hostname da URL para o TLS normal. Nenhum redirect é seguido, nem no mesmo host. Não usa cookies, cache, credenciais persistentes ou subprocessos.

Limites: corpo de requisição até 256 KB depois de substituir; resposta até 1 MB com aviso de truncamento; timeout até 120 segundos. Binários/UTF-8 inválido/NUL não são devolvidos em texto, apenas tipo e tamanho retido. O conteúdo de um servidor é entrada não confiável; mascaramento reduz exposição acidental e não elimina toda codificação ou inferência possível.

## Aprovar regras existentes e migração

Chaves novas e itens com assinatura ausente/inválida ficam sem acesso pelo agente. Em Settings → **Review and approve existing rules…**, confira nomes, projetos, hosts, métodos, caminhos e a opção .env antes de aprovar o lote com Touch ID. A aprovação não é uma ferramenta MCP. Para editar uma chave: abra o bloco de acesso e use **Sign rules with Touch ID**. Alterar nome/projeto ou outro campo autenticado revoga a assinatura até nova revisão.

Presets são sugestões para a revisão; não autorizam acesso automaticamente. Supabase precisa do host exato do projeto para a API desse projeto. Wildcards personalizados exigem aviso/consentimento e só podem ser usados no modo de programas; `lockd_http` exige host exato.

Novos segredos usam v3 com AAD = versão + UUID estável. v2 continua legível e é regravado em v3 na próxima autenticação/leitura ou na aprovação do lote. **Não volte a um app antigo que só lê v2 depois de migrar.** Preserve os arquivos originais antes de qualquer migração manual; a equipe/agente não fez cópia nem alteração do seu cofre real.

## Programas e arquivos .env

`lockd_run` fica oculto no MCP e recusado no Broker por padrão. Settings → **Permitir programas (avançado)** mostra aviso antes de habilitar. Mesmo habilitado, só curl com opções limitadas e executável verificado é aceito. O sandbox restringe rede e algumas pastas/escritas; não isola integralmente o usuário. Valores vão por stdin/ambiente, não por argv substituído.

`.env`/hosting ficam desligados por padrão por chave. Um destino novo pede autenticação nova. Um .env habilitado torna os valores legíveis por qualquer processo do usuário, incluindo o agente; 0600 não separa processos do mesmo UID. A integração Vercel usa o mesmo cliente HTTP interno. Para produção sem development, envia `type: sensitive`; compatibilidade real com a conta Vercel ainda não verificada.

## Limites de confiança e recuperação

Assinaturas detectam alteração isolada de itens/políticas/ciphertext. O manifesto assinado e o contador em memória detectam rollback durante a sessão. Restaurar todo o estado de confiança antigo após reiniciar, ou substituir também a identidade de chave e o manifesto, exige uma âncora externa para detecção confiável. Não há essa âncora aqui. O app não protege contra toda ação de um processo arbitrário do mesmo usuário, injeção no app, memória, serviços do sistema ou um Mac comprometido.

A pública de cifragem é derivada do blob do SE; divergência da cópia em arquivo interrompe cifragem. Perda do blob com dados existentes não gera outra chave silenciosamente. Apagar/trocar o Mac pode perder segredos sem backup portátil anterior. Backup portátil **não implementado**: veja [opções](docs/BACKUP-OPTIONS.md).

## Desenvolvimento e validação

SwiftPM, sem dependência externa nova. Mac Apple Silicon, macOS 14+. Execute testes serialmente com `LOCKD_HOME` temporário e `swift test --jobs 2`; esse modo usa chaves de software e não comprova Secure Enclave/Touch ID. As exceções de rede local dos testes só existem no inicializador DEBUG, não no produto release.

[Status e validações](docs/STATUS.md) · [revisão e achados remanescentes](docs/SECURITY-REVIEW.md) · [release](docs/RELEASE.md) · [desinstalação](docs/UNINSTALL.md).

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
