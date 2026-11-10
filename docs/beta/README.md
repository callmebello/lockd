# Beta fechado — material preparado, beta ainda não liberado

Este material não conclui a tarefa C. Onboarding, diagnóstico, erros, backup e teste manual de permissões continuam pendentes. Distribuir somente depois das correções de segurança aprovadas e de um artefato assinado e notarizado validado. O responsável envia os convites; nada foi enviado por automação.

## Convite PT

Estou testando o Lockd com cerca de 10 devs. É um app de barra de menu para Mac Apple Silicon (macOS 14+) que organiza assets por projeto e oferece chamadas HTTP internas com regras de acesso assinadas. Topa instalar em 5 minutos e conversar depois de uma semana? É beta: comece com dados fictícios, sem credenciais de produção. Ainda não há backup portátil; perder o Mac ou os arquivos do cofre pode tornar os segredos irrecuperáveis. Quero saber se ele cabe no seu trabalho toda semana. Envio o download e as instruções quando o build estiver liberado.

## Invitation EN

I'm testing Lockd with about 10 developers. It's a menu bar app for Apple Silicon Macs (macOS 14+) that organizes project assets and lets commands use API keys through access rules. Would you try a five-minute setup and talk after a week? This is a beta: start with dummy data, without production credentials. Portable backup is not available yet; losing your Mac or vault files can make secrets unrecoverable. I want to learn whether you'd use it every week. I'll send the download and instructions once the build is cleared.

## Instalação — roteiro de 5 minutos

O responsável deve preencher **[URL do build]**, **[versão]**, **[SHA-256]** e **[canal privado de feedback]** antes do envio. Este roteiro não é evidência de teste em um Mac limpo.

1. **0–1 min:** confirme Apple Silicon e macOS 14+. Baixe o DMG por [URL do build], confira a versão e o SHA-256 informados pelo responsável. Se houver alerta de assinatura ou notarização, pare e reporte; não desative o Gatekeeper.
2. **1–2 min:** abra o DMG, arraste Lockd para Applications e abra `/Applications/Lockd.app`. Procure o ícone na barra de menu.
3. **2–3 min:** para testar colagem, permita Acessibilidade em Ajustes do Sistema → Privacidade e Segurança → Acessibilidade. Para observar pastas, confira Arquivos e Pastas → Lockd → Downloads/Desktop. Configure notificações em Ajustes do Sistema → Notificações → Lockd. Negar uma permissão deve ser registrado, não resolvido concedendo Acesso Total ao Disco. A apresentação e a recuperação dessas permissões ainda exigem validação manual.
4. **3–4 min:** copie uma chave fictícia, como `sk_test_LOCKD_DEMO_0123456789abcdef`, e confirme a captura na biblioteca. Teste busca `⌥⌘L` e colagem somente em um editor vazio. Se a captura automática não ocorrer, registre a falha. Não use a chave fictícia em um serviço real.
5. **4–5 min:** tente abrir um segredo e observe a autenticação. O código permite Touch ID **ou senha do Mac** e mantém sessão por até 30 minutos. Registre cancelamento, bloqueio ou erro sem enviar o valor. Não configure integração com Claude nem altere configurações globais neste roteiro. Envie versão, macOS e descrição do resultado pelo canal privado indicado.

O Secure Enclave protege o uso da chave privada no aparelho; não impede toda ação de programas do mesmo usuário, nem torna toda saída de comandos segura. Downloads/Desktop podem conter arquivos que o organizador move para `~/Lockd`; use arquivos descartáveis neste teste.

## Entrevista — após uma semana

1. Em que tarefa concreta você tentou usar o Lockd? O que fazia antes?
2. Qual chave você colou por último fora daqui? Diga apenas o serviço/contexto, nunca o valor.
3. Você usaria toda semana? Sim, não ou incerto — por quê? Qual tarefa recorrente sustentaria isso?
4. Quanto tempo levou até o primeiro resultado útil? Onde travou?
5. O que você entendeu que Touch ID/senha e as regras de comandos/hosts protegem? O que ficou confuso?
6. Alguma permissão, solicitação de autenticação ou erro interrompeu seu trabalho? Qual foi a consequência?
7. O que precisaria mudar para confiar no app no trabalho? Como a ausência de backup portátil afetou sua decisão?
8. Se o Lockd desaparecesse amanhã, você sentiria falta? Que alternativa usaria e o que deixaria de fazer?

## Registro e decisão

Use `respostas.csv`: uma linha por participante, identificador pseudônimo, sem chaves, nomes de clientes, arquivos privados ou e-mails. Notas de entrevista são enviadas voluntariamente; isso não é telemetria no app. Combine com cada participante quem terá acesso e até quando manter as notas antes de coletá-las.

Meta: aproximadamente 10 devs com uma semana de oportunidade real de uso. Convite não aceito não equivale a resposta. Marque abandono e ausência de resposta; reporte o denominador e não troque participantes para melhorar o resultado.

Critério definido pelo fundador: **se menos de aproximadamente 3 de 10 disserem que usariam toda semana, revisar a ideia**. Operacionalização para 10 entrevistas válidas: 0–2 respostas `sim` → revisar; 3 ou mais → sinal mínimo atingido, sem comprovar segurança, retenção ou demanda comercial. `incerto` não conta como `sim`. Se houver menos de 10 entrevistas, informe `sim / entrevistas válidas` e complete a coleta antes de declarar o critério atingido. Registre também a tarefa recorrente citada, para distinguir intenção de uso observado.
