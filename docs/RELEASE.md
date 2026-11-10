# Release do Lockd

Pipeline preparado para Apple Silicon, macOS 14+. Nenhum entitlement: o app não habilita App Sandbox nem exceções ao hardened runtime (JIT, memória executável, bibliotecas sem assinatura ou get-task-allow). O sandbox dos comandos é o perfil criado em `Sandbox.swift`, separado do App Sandbox. Não adicionar `network.client`, `network.server` ou `keychain-access-groups` por tentativa: não são necessários ao app não sandboxed atual. Permissões TCC e autorização do usuário continuam necessárias.

## Versão e saída

`Lockd/scripts/VERSION` é a fonte padrão única; `LOCKD_VERSION` pode sobrescrever na execução. A versão alimenta `CFBundleShortVersionString`, nomes e manifesto JSON. `CFBundleVersion` é derivado como `(MAJOR + 1).MINOR.PATCH`: `0.1.0` resulta em build `1.1.0`, respeitando o primeiro componente positivo exigido pela Apple. Formato `MAJOR.MINOR.PATCH`, até `9998.99.99`, sem zeros à esquerda. Avance PATCH para cada build distribuído; não reutilize versão para binários diferentes. A migração inicial altera o build antigo `1` para `1.1.0`; considere isso ao adotar um atualizador futuro. Não há contador de build independente.

Em `Lockd/dist/`: `Lockd.app`, `Lockd-VERSAO-arm64[-dry-run].dmg`, `.dmg.sha256` e `.version.json`. Dry-run tem nome próprio e `notarized: false`; nunca o anuncie como release. O diretório temporário e ZIP são apagados ao terminar; preservam-se os relatórios pequenos de notarização. Execuções usam o mesmo app em dist: rode uma por vez.

## Antes de executar

Faça revisão de segurança e confirme o espaço disponível. O pipeline não roda os testes nem inicia o app, não instala em `/Applications`, não altera ajustes e não consulta identidades. Assinar usa a chave de assinatura existente; notarização real usa exclusivamente o perfil escolhido. Não executa `--selftest-se` nem acessa o cofre.

```bash
cd ~/Claude/locked/Lockd
TEST_HOME="$(mktemp -d "${TMPDIR:-/tmp}/lockd-release-tests.XXXXXX")"
LOCKD_HOME="$TEST_HOME" swift test
# Os testes atuais criam outras pastas lockd-b-* e lockd-test-* temporárias.
# Não remova esses padrões globalmente; remova apenas pastas da sua execução.
rm -rf "$TEST_HOME"
```

Os testes atuais contêm uma chamada de rede com chave falsa para `api.anthropic.com`; conexão e resposta externa podem afetar o teste. Eles usam chave de software com LOCKD_HOME; não comprovam Secure Enclave ou Touch ID. Alguns testes legados criam um diretório de projeto descartável no home e o removem no teardown.

## Dry-run (sem conta de notarização)

```bash
cd ~/Claude/locked/Lockd
LOCKD_SIGN_IDENTITY='Apple Development: Gustavo Henrique Correia Ferreira (44LNP6HYTB)' \
  scripts/release.sh --dry-run
```

Usa o certificado existente, build release arm64, assina CLI, executável principal e bundle com `--options runtime --timestamp`, monta DMG comprimido com atalho `/Applications` e assina o DMG. A consulta de timestamp pode precisar de internet. Não envia nada para notarização, não faz staple; executa `codesign`, Gatekeeper e inspeção de ticket. Rejeição do Gatekeeper e falta de ticket são esperadas nesse modo, aparecem no terminal e não interrompem. Qualquer erro de build, assinatura ou criação do DMG interrompe. Dry-run não valida distribuição pública, Touch ID nem funcionalidades interativas.

## Passos exclusivos do titular Apple

1. Xcode → Settings → Accounts (ou Apple Accounts) → conta/equipe `YOUR_TEAM_ID` → Manage Certificates → `+` → **Developer ID Application**. Se indisponível, use [Certificates no portal Apple](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/). **Apple Distribution não serve** para este fluxo.
2. Você pode confirmar localmente com `security find-identity -v -p codesigning`; não é necessário compartilhar a saída inteira.
3. Crie e guarde uma credencial de notarização. Você executa; não forneça a senha ao agente. O comando pede a senha específica de app interativamente:

```bash
xcrun notarytool store-credentials 'lockd-notary' \
  --apple-id 'SEU_APPLE_ID' --team-id YOUR_TEAM_ID
```

Uma chave de API App Store Connect também é alternativa suportada pelo notarytool; veja `xcrun notarytool store-credentials --help` para os campos. Não grave senha em script, histórico ou documentação.

## Release real (executar somente após preparar a conta)

```bash
cd ~/Claude/locked/Lockd
LOCKD_SIGN_IDENTITY='Developer ID Application: SEU NOME (YOUR_TEAM_ID)' \
LOCKD_NOTARY_PROFILE='lockd-notary' LOCKD_VERSION='0.1.1' \
  scripts/release.sh
```

O pipeline faz duas submissões `notarytool submit --wait`: ZIP temporário do app e DMG final. Primeiro anexa e valida o ticket no app; depois empacota esse app com ticket no DMG, submete e anexa o ticket ao DMG. Assim ambos preservam tickets para verificação offline. Exige status JSON `Accepted`, verifica assinatura estrita do app/DMG e Gatekeeper dos dois. Só então escreve checksum e manifesto. Não publique um artefato parcial de uma execução que falhou. O CLI está coberto pela assinatura/notarização do bundle e não recebe ticket separado.

Confirme o checksum sem mover o arquivo:

```bash
shasum -a 256 -c dist/Lockd-0.1.1-arm64.dmg.sha256
```

## Rejeição e diagnóstico

As respostas ficam em `dist/Lockd-VERSAO-arm64-app-notary.json` e `-dmg-notary.json`. Leia `id` e `status`; mesmo exit code zero não significa aceitação. Com o UUID da submissão:

```bash
xcrun notarytool log UUID_DA_SUBMISSAO \
  --keychain-profile lockd-notary dist/notary-log.json
xcrun notarytool info UUID_DA_SUBMISSAO --keychain-profile lockd-notary
```

Leia `issues`, `path`, `message` e arquitetura. Corrija o binário apontado, assine novamente de dentro para fora, gere novo pacote e repita o pipeline. Não contorne Gatekeeper nem remova quarentena para declarar sucesso. Falta de runtime/timestamp, certificado inadequado ou `get-task-allow` são motivos a investigar; erro de rede/autenticação requer corrigir conta/conectividade. Mesmo com `Accepted`, revise warnings no log. Não inclua senhas ou conteúdo do cofre em pedidos de suporte.

## Validação funcional necessária

Ausência de entitlements adicionais é a escolha inicial; inspeção do código não comprova execução. Execute esta matriz manualmente em Mac de teste, com dados falsos, após assinatura final. A autorização para testes daqui não autoriza alterar permissões do Mac pessoal ou abrir o cofre real.

| Função | Verificação | Estado nesta entrega |
|---|---|---|
| Secure Enclave / Touch ID | Criar cofre descartável real, bloquear/desbloquear, confirmar presença e fallback | **não verificado**; relato prévio do titular não substitui teste deste build |
| sandbox-exec | Executar chaves falsas no broker e negar leitura/rede proibidas | Testes automatizados; resultado da execução deve acompanhar entrega |
| FilterProxy / Network.framework | Host permitido, bloqueado e conexão direta negada | Testes com chave falsa; não equivalem a auditoria completa de rede |
| Socket Unix | Cliente do bundle conecta; permissões 0600 e erros de ocupação | **não verificado** no app assinado |
| FSEvents / Downloads / Desktop | Permitir/negar e criar arquivo fictício | **não verificado** |
| Acessibilidade / CGEvent | Autorizar, buscar e colar texto falso no app da frente | **não verificado** |
| Notificações | Permitir/negar e agendar alerta fictício | **não verificado** |
| SMAppService | Habilitar, verificar após login, desabilitar | **não verificado** |
| Gatekeeper / tickets | Baixar em outro Mac limpo, montar DMG e abrir também offline | **não verificado**, depende de conta Apple e release final |

Não use `LOCKD_HOME` para afirmar teste real de Secure Enclave: essa variável troca a criptografia por chave de software. O CLI não deve ser usado para imprimir valores. Os testes não demonstram ausência de todas as formas de exfiltração; leia `SECURITY-REVIEW.md` antes de definir alegações públicas.

Referências oficiais: [CFBundleVersion](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CoreFoundationKeys.html), [notarização](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [empacotamento](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution), [hardened runtime](https://help.apple.com/xcode/mac/current/en.lproj/devf87a2ac8f.html).
