# Backup portátil — decisão antes de implementar

Status: **não implementado; requer decisão do responsável**. Não foi acessado cofre real nem Keychain. Copiar `items.json` e `se-key.blob` não cria uma migração para outro Mac: o blob é vinculado ao aparelho. Sem recuperação portátil validada, perder o Mac ou esse blob pode significar perder os segredos.

## Limite das APIs solicitadas

No SDK local, a interface pública de CryptoKit expõe HKDF, mas não Argon2/scrypt. O header público de CommonCrypto documenta somente PBKDF2 em `CCKeyDerivationPBKDF`. Portanto **Argon2/scrypt via CryptoKit ou CommonCrypto, sem código adicional, não é uma opção disponível verificada**. HKDF não deve ser usado sozinho para transformar uma senha humana em chave de backup. Fontes: [CryptoKit](https://developer.apple.com/documentation/cryptokit), [HKDF](https://developer.apple.com/documentation/cryptokit/hkdf), [header oficial de CommonCrypto](https://github.com/apple-oss-distributions/CommonCrypto/blob/main/include/CommonKeyDerivation.h). Conferido também no SDK local de Command Line Tools, `CommonKeyDerivation.h` e `CryptoKit.swiftinterface` (2026-10-23); nenhuma API de KDF foi compilada ou medida nesta etapa.

| Alternativa | Custo técnico estimado, não orçamento | Limite e decisão |
| --- | --- | --- |
| PBKDF2-HMAC-SHA256 (CommonCrypto) + AES-256-GCM (CryptoKit) | 3–5 dias de implementação e testes; mais revisão independente e validação manual em dois Macs | Sem pacote externo; PBKDF2 não impõe o custo de memória de Argon2/scrypt. Exige aprovar desvio do requisito original e uma senha forte. |
| Argon2id com implementação de referência incorporada e fixada | 5–10 dias para integrar, verificar licença, vetores, limites de memória e empacotamento; mais revisão independente | É código externo mesmo sem gerenciador de dependências. Precisa aprovação e manutenção de atualizações; tamanho e tempo devem ser medidos. |
| scrypt com implementação de referência incorporada e fixada | 5–10 dias, com obrigações equivalentes | Também exige código extra, vetores e limites de custo; não resolve o requisito de usar apenas APIs Apple. |
| Adiar backup e limitar beta a dados fictícios descartáveis | Sem implementação agora; adiciona restrição ao teste de uso real | Não resolve migração nem recuperação. Deve constar do convite e da interface antes de aceitar segredos importantes. |

Estimativas pressupõem um único desenvolvedor familiarizado com Swift e incluem UI básica, formato e importação transacional; não prometem prazo de auditoria. Argon2 e scrypt são funções com custo deliberado de memória: [RFC 9106](https://www.rfc-editor.org/info/rfc9106/), [RFC 7914](https://www.rfc-editor.org/info/rfc7914/). Nenhum benchmark ou tamanho adicional foi medido.

**Recomendação para decisão:** se manter zero dependências é obrigatório, aprovar explicitamente PBKDF2 + AES-GCM, com revisão antes de dados reais. Se a resistência a ataques offline com senha humana for prioridade superior, aprovar uma implementação madura de Argon2id. Não escrever um Argon2/scrypt próprio para evitar chamar isso de dependência. Até a decisão e os testes, manter beta com dados fictícios.

## Contrato proposto para qualquer implementação

- Exportar somente após autenticação explícita nova, mostrando que o arquivo será recuperável com a senha em outro Mac. Não exportar a chave privada do Secure Enclave. Decifrar itens em memória e recifrar o pacote com a chave derivada da senha, sem temporário em texto aberto.
- Formato versionado, salt aleatório por exportação, nonce aleatório e tag AES-GCM. Autenticar versão e parâmetros de KDF como AAD; impor limites de tamanho, iterações e memória antes de processar arquivo hostil. Persistir os parâmetros para compatibilidade e migração futura. Definir codificação UTF-8 e tratamento de senha de forma estável.
- Para PBKDF2, medir custo em Macs suportados, fixar piso conservador e teto de importação; não confundir a calibração de latência com validação de força da senha. Não há número de iterações aprovado nesta proposta.
- No Mac novo, validar inteiramente o arquivo antes de alterar dados; apresentar conflitos e recifrar cada segredo para a chave local. Fazer importação transacional com rollback. Não ampliar silenciosamente regras importadas: pedir revisão das políticas. Assets e arquivos de credenciais devem ter escopo explícito; exportar metadados não equivale a copiar seus arquivos.
- Testar apenas com chaves falsas e `LOCKD_HOME` temporário: ida/volta, senha errada, corrupção, truncamento, versão desconhecida, parâmetros enormes, duplicatas, cancelamento, falha de disco e rollback. Restauração entre dois Macs, autenticação e ausência de temporários são **não verificados** até teste manual.
- Senha perdida não terá recuperação por e-mail. O arquivo permite tentativas offline: senha fraca continua sendo risco. Remover referências de memória ao terminar é necessário, mas Swift não garante apagar todas as cópias de `String` da RAM.

Aprovação solicitada antes de código: escolher PBKDF2 sem dependência, Argon2id com código adicional ou adiar. Esta documentação não autoriza implementação nem declara a tarefa C concluída.
