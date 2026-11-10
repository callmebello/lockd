# Segurança — atualização da Fase 2, 24/10/2026

A Fase 2 foi autorizada e implementada; isto não é uma auditoria humana independente nem uma certificação. A revisão anterior está preservada em `history/SECURITY-REVIEW-FASE-1.md`. Os testes usam dados falsos e software com LOCKD_HOME, sem ler/alterar cofre real, Keychain ou credenciais.

## Modelo de ameaça e promessa sustentável

Atacante: agente comprometido por prompt injection, com Bash, leitura/escrita dos arquivos do usuário e acesso ao socket, sem root e sem poder aprovar conscientemente a presença do usuário. Não assumimos isolamento entre processos do mesmo UID. O fluxo recomendado é HTTP dentro do app: não passa valores substituídos por argv/ambiente de processo filho, aplica política assinada e filtra respostas. Arquivos .env explicitamente habilitados continuam legíveis ao agente.

O app pode sustentar: cofre cifrado vinculado ao Mac; autenticação local de sessão/operações; limitação de ferramentas/destinos; redução de exposição acidental por mascaramento. Não pode sustentar inviolabilidade, proteção contra toda exfiltração, ausência universal de segredos em memória/logs, nem que nenhum processo do usuário consegue obter valores.

## Achados atualizados

“Corrigido no HTTP” delimita o caminho recomendado; não transforma programas avançados ou o Mac inteiro em ambientes isolados.

| ID | Severidade | Status | Evidência e limite restante |
|---|---|---|---|
| S01 | Alta | Corrigido no HTTP; parcial no avançado | lockd_http não executa programa filho. Programas ficam ocultos no MCP e recusados no Broker por padrão; teste de catálogo verifica desligado/ligado. Avançado ainda executa curl limitado. |
| S02 | Alta | Parcial | Default nil=false, políticas assinadas e aprovação nova por destino/chaves. .env habilitado continua legível ao mesmo UID; TOCTOU de S14 permanece. |
| S03 | Alta | Parcial, limite de âncora | Assinatura P-256 separada do SE sobre UUID/nome/projeto/serviço/hash do cipher/regras/versão. JSON alterado revoga acesso, com aviso e audit. Manifesto assinado + contador em memória recusam replay na sessão. Sem âncora externa, rollback conjunto após reinício e substituição de toda a identidade confiável continuam sem garantia de detecção. |
| S04 | Alta | Parcial | Eco exato/base64/hex e segredos curtos tratados; resposta binária/NUL/UTF-8 inválido omitida. Espaçamento e transformações arbitrárias ainda não são uma fronteira segura. Entrada do servidor é marcada como não confiável. |
| S05 | Alta | Corrigido no controle de sessão | Mantidas as provas da Fase 1: verifica sessão antes do cache e após decifrar, expiração limpa cache/contexto; lockNow e geração revogam reutilização. Touch ID/SE real ainda não verificados. |
| S06 | Alta | Parcial | Presets sem wildcard; HTTP exige host exato mesmo com wildcard confirmado. Métodos/prefixos opcionais assinados. Host exato multitenant ou API que permite escrever em recursos de terceiros ainda exige escopo de conta/recurso. |
| S07 | Alta | Corrigido no HTTP; parcial no avançado | HTTP não cria processo filho. Chave falsa ausente no ps -ww do processo de teste e no lsof durante chamada lenta. Avançado usa config por stdin e ambiente; isso não é garantia contra inspeção de memória/IPC do mesmo UID. |
| S08 | Alta | Corrigido no HTTP; parcial no avançado | HTTP aceita body inline/JSON, sem cwd/upload/arquivos arbitrários. Avançado preserva denylist de pastas e limites de escrita da Fase 1; leitura geral, hardlinks e serviços Mach não foram integralmente isolados. |
| S09 | Alta | Corrigido no HTTP; parcial no avançado | HTTP não resolve executáveis. Curl avançado exige raiz/ancestrais root-owned e sem escrita efetiva; hash pinning não implementado. |
| S10 | Média | Corrigido em v3; legado em migração | AAD ligado ao UUID+versão e HKDF separado por versão; troca de cipher/UUID falha inclusive se houver cache. v2 migra na próxima autenticação/leitura ou aprovação de lote. Não se pode recuperar a identidade histórica de um v2 trocado antes da migração. |
| S11 | Média | Aberto no socket; HTTP limitado | Corpos 256 KB/1 MB, timeout, headers validados. Framing/rate limit/concorrência e leitura de logs no protocolo antigo ainda não corrigidos. |
| S12 | Média | Aberto | Mesmo UID não autentica a identidade de um cliente. Política e presença limitam operações; ocupação/unlink do socket e DoS continuam como antes. |
| S13 | Média | Corrigido no caminho HTTP implementado; parcial global | URLSession efêmera, TLS normal, Host/proxy/framing headers reservados, nenhum redirect seguido. Todos os IPs DNS devem ser públicos; upstream fixado a IP aprovado via CONNECT local, sem segunda resolução do destino. Teste HTTPS real com chave falsa confirma uso do túnel e TLS. Proxy de programas avançados continua sendo túnel genérico. |
| S14 | Média | Aberto | Opt-in/presença e assinatura não eliminam race de ancestral symlink em EnvFile. Escrita por FD/no-follow ainda pendente. |
| S15 | Média | Parcial | Vercel usa cliente seguro, token com política assinada e método/caminho, presença por chave/host. Produção sem development usa sensitive. Token amplo, configuração de projeto/time e autorização de recursos externos continuam exigindo cuidado; conta/API real não verificadas. |
| S16 | Média | Parcial | Audit HTTP preserva placeholders e mascara literais conhecidos; modelo limitado a 8 mil caracteres. Outros metadados, crash reports, logs externos, rotação e garantia universal de ausência de valores continuam abertos. |
| S17 | Média | Parcial | Pública derivada do blob e comparada ao arquivo público; divergência para cifragem. Blob ausente com dados/cópia pública existente não gera nova chave. Testes de software cobrem divergência/perda. Substituição conjunta da identidade de chave/estado confiável e comportamento real do SE ainda limitam a garantia. |

## Assinatura, migração e rollback

A aprovação é uma ação local da UI; não existe operação de assinatura/migração no MCP/socket. A folha de revisão mostra as regras atuais antes de um prompt para o lote. O app verifica que o estado não mudou entre revisão, autenticação e persistência. Alterar campos autenticados invalida a assinatura; propostas de presets não são regras ativas.

Cada entrada assinada inclui hash SHA-256 do ciphertext, versão e regras canônicas com JSON de chaves ordenadas. O manifesto assinado guarda contador e hash de cada entrada. Um item antigo isolado não corresponde ao manifesto atual. O maior contador observado é mantido em memória: restaurar também um manifesto mais antigo na mesma sessão falha.

**Limite importante:** o contador em arquivo não é fonte de verdade externa. Restaurar todo o estado antigo após reiniciar pode ser aceito. Além disso, derivar a pública de um blob confirma a identidade daquele blob, não que ele seja o blob histórico legítimo. Um adversário que substitua toda a identidade de chaves e o manifesto fica fora da garantia dessa assinatura local. Não há proteção comprovada contra esse cenário, alteração/injeção no binário ou administração do Mac. Resolver exige uma âncora confiável fora dos arquivos que esse mesmo usuário pode substituir; não foi acrescentado Keychain, servidor ou dependência para fingir que isso está resolvido.

A migração v2→v3 é deliberada e não tem downgrade automático. Apps antigos que só leem v2 não abrem v3. Ela não assina silenciosamente regras antigas: se o item era sem assinatura, converter o cipher não autoriza o agente. Aprovar o lote assina somente o estado exibido/revisado. Se houver falha entre manifesto e itens, o comportamento é revogar regras, não liberar acesso; revisão/reparo local pode ser necessário. Backup portátil continua não implementado.

## Rede e limites dos testes

Nenhum redirect é seguido, inclusive no mesmo host: cabeçalhos sensíveis não são reenviados. O cliente não usa cache/cookies/credenciais persistentes. A exceção de HTTP/IP loopback para fixtures só pode ser construída no código DEBUG com LOCKD_HOME; não existe flag de ambiente para ativá-la no release. Vercel test-base também fica dentro de DEBUG.

A resolução verifica todas as respostas e o proxy abre TCP para endereço numérico aprovado. O TLS da URL original fica com URLSession, sem aceitar certificado inválido. DNS tem espera limitada; chamada pode falhar por rede externa. O teste de API usa exclusivamente chave falsa. Não é prova formal de CFNetwork, DNS ou TLS.

57 testes passaram, sem ignorados, nesta execução. Incluem servidor local falso, host sem política, regras ausentes/adulteradas, redirects sem encaminhamento, IPs privados/literais, CRLF, requisição grande, resposta truncada, binário omitido, timeout, eco de segredo, limites de método/caminho, presença por combinação, AAD/cache, migração e perda de chave. O teste de ps inspeciona somente o processo de teste; lsof lista seus descritores. Nenhum desses dois comprova ausência de segredo na RAM, em outros canais ou em crash reports.

Continuam não verificados: Touch ID real, chave de assinatura real do SE e sua verificação sem prompt, Mac bloqueado, instalação/Gatekeeper/notarização, integração com conta real Vercel, layout/cliques da UI e uma revisão humana independente. Não se abriu o app instalado nem se migrou o cofre real.

## Comunicação pública

Pode dizer: “Cofre cifrado vinculado ao Mac, com autenticação local”; “O Broker limita ferramentas e destinos e mascara padrões comuns”; “HTTP roda dentro do app com regras assinadas”; “.env habilitado torna valores legíveis aos processos do usuário”. Qualifique sessão, estado de verificação e limites acima.

Não dizer: “Claude nunca vê suas chaves”, “nenhum processo do usuário lê segredos”, “sandbox impede toda exfiltração”, “zero segredos em logs/argv em qualquer situação”, “inviolável”, “à prova de IA” ou “segurança militar”.
