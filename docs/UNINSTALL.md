# Desinstalação manual

Instruções preparadas a partir do código, sem executar remoção e sem acessar dados reais. Não há desinstalador integrado verificado.

1. No Lockd, desligue abrir no login, se disponível. O código usa `SMAppService.mainApp.unregister()`; também confira Ajustes do Sistema → Geral → Itens de Início e Extensões e desative Lockd. A ausência de item na lista não prova que o app foi apagado.
2. Encerre Lockd pelo menu e feche comandos que estejam usando o broker.
3. No Finder, mova `/Applications/Lockd.app` para a Lixeira. Isso preserva os dados abaixo. Se quiser reinstalar mantendo o cofre, pare aqui.
4. Antes de apagar dados, decida quais assets/credenciais devem ser preservados. `~/Lockd` contém **arquivos movidos** de Downloads/Desktop, não apenas cópias ou cache. Mova os arquivos necessários de volta a um destino seguro, manualmente. Apagar metadados perde a associação com os caminhos originais.
5. Para remoção definitiva, use Finder → Ir → Ir para a Pasta e confira `~/Library/Application Support/Lockd`. Essa pasta contém `items.json`, `projects.json`, `audit.jsonl`, `lockd.sock`, `se-key.blob`, `se-key.pub`, `rules-se-key.blob` e `rules-manifest.json`. Só depois de aceitar a perda, mova a pasta para a Lixeira. `se-key.blob` é a representação opaca vinculada ao Secure Enclave: apagá-la perde o caminho de recuperação dos segredos cifrados. Não existe exportação portátil implementada. Não remova apenas os arquivos de chave pensando que os demais são restauráveis em outro Mac.
6. Opcionalmente remova `~/Lockd` após preservar os arquivos necessários. Preferências usam `UserDefaults.standard`, com bundle ID `app.lockd.mac`; se existir, o arquivo esperado é `~/Library/Preferences/app.lockd.mac.plist`. Com o app fechado, pode removê-lo pelo Finder. Não remova preferências de outros apps.
7. Em Ajustes do Sistema, revogue permissões de Lockd em Acessibilidade, Arquivos e Pastas e Notificações onde a interface permitir. Não execute resets globais de permissões.

O código atual não cria uma entrada nominal de senha no Keychain para o cofre; não use `security delete-*`, nem apague itens por busca de nome. Apagar o blob não é uma certificação de apagamento físico da chave no hardware. Esvaziar a Lixeira também não garante sobrescrita física em SSD/APFS ou remoção de snapshots/backups.

O CLI é empacotado em `Lockd.app/Contents/MacOS/lockdctl`; nenhum instalador de link global foi identificado no script de build. Se você criou atalhos, integrações MCP ou links manualmente, remova apenas os que reconhecer. Estas instruções não alteram `~/.claude/settings.json`. Artefatos de desenvolvimento `Lockd/dist` e `.build` ficam no repositório e não são dados do usuário; não é necessário apagá-los para desinstalar o app.

Fontes locais: `Sources/LockdCore/Models.swift` (`LockdPaths`), `Vault.swift`, `Files.swift` (`Ingestor`), `Sources/Lockd/Services.swift` (`LoginItem`, preferências) e `scripts/build_app.sh`.
