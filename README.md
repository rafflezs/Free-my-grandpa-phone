# APK Security Analysis Toolkit

Conjunto de scripts para análise de segurança e remoção de aplicativos Android via ADB.

---

## Sumário

1. [Requisitos](#requisitos)
2. [Visão Geral](#visão-geral)
3. [Script de Análise](#script-de-análise-batch_analysissh)
4. [Script de Limpeza](#script-de-limpeza-interactive_cleanupsh)
5. [Fluxo de Trabalho Recomendado](#fluxo-de-trabalho-recomendado)
6. [Referência de Comandos](#referência-de-comandos)
7. [Estrutura de Arquivos](#estrutura-de-arquivos)
8. [Resolução de Problemas](#resolução-de-problemas)

---

## Requisitos

| Componente | Instalação |
|------------|------------|
| ADB | `sudo apt install android-tools-adb` |
| Python 3.8+ | Geralmente pré-instalado |
| androguard | `pip install androguard` |
| apkleaks | `pip install apkleaks` |

O dispositivo Android deve estar conectado via USB com depuração USB ativada.

---

## Visão Geral

O toolkit consiste em dois scripts complementares:

- **batch_analysis.sh**: Analisa pacotes instalados no dispositivo, identificando permissões perigosas e possíveis vazamentos de dados.
- **interactive_cleanup.sh**: Permite revisar os resultados e decidir interativamente quais aplicativos desabilitar ou remover.

O fluxo de trabalho é sequencial: primeiro analisa-se o dispositivo, depois revisa-se os resultados.

---

## Script de Análise (batch_analysis.sh)

### Descrição

Extrai e analisa APKs do dispositivo Android conectado. A análise inclui:

- Verificação de permissões perigosas (34 categorias)
- Detecção de credenciais e URLs expostos via apkleaks
- Classificação de risco (CRITICAL, HIGH, MEDIUM)

### Modos de Operação

| Modo | Descrição | Uso de Disco | Paralelismo | Cleanup |
|------|-----------|--------------|-------------|--------|
| `--stream` | Analisa um APK por vez, apagando após análise | Mínimo (~100MB) | Não* | Automático |
| `--stream-all` | Inclui pacotes de sistema | Mínimo | Não* | Automático |
| `--stream-system` | Apenas pacotes de sistema | Mínimo | Não* | Automático |
| `--pull [dir]` | Baixa todos os APKs antes de analisar | Alto (vários GB) | Opcional | Pergunta |
| `<diretório>` | Analisa APKs de um diretório local | Variável | Opcional | Pergunta |

> **Nota sobre paralelismo**: O modo `--stream` não suporta paralelismo porque o ADB permite apenas uma conexão de transferência por vez. Para análise paralela, use `--pull` que baixa tudo primeiro.

> **Nota sobre [dir]**: O parâmetro é **opcional**. Se omitido, usa `./device_apks` como padrão.

### Comparação de Modos

```
┌─────────────────┬────────────┬──────────────┬─────────────┬─────────────┬──────────────┐
│ Modo            │ Disco      │ Download     │ Análise     │ Cleanup     │ Ideal para   │
├─────────────────┼────────────┼──────────────┼─────────────┼─────────────┼──────────────┤
│ --stream        │ ~100MB     │ 1 por vez    │ Sequencial  │ Automático   │ Laptops      │
│ --pull          │ 5-50GB     │ Todos antes  │ Sequencial  │ Pergunta    │ Desktops     │
│ --pull +parallel│ 5-50GB     │ Todos antes  │ Paralela    │ Pergunta    │ Servidores   │
│ SKIP_SECRETS    │ Qualquer   │ Depende      │ 10x rápido  │ Depende     │ Scan rápido  │
└─────────────────┴────────────┴──────────────┴─────────────┴─────────────┴──────────────┘
```

### Sintaxe

```bash
./batch_analysis.sh [MODO] [OPÇÕES]
```

### Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `SKIP_SECRETS` | `false` | Se `true`, pula análise de secrets (mais rápido) |
| `SECRETS_TIMEOUT` | `120` | Timeout em segundos para análise de secrets |
| `ENABLE_PARALLEL` | `false` | Se `true`, habilita processamento paralelo |
| `PARALLEL_JOBS` | `auto` | Número de jobs paralelos (padrão: nproc/2) || `CLEANUP_AFTER_ANALYSIS` | `ask` | Limpeza de APKs: `ask`, `yes`, ou `no` |
### Exemplos de Uso

Análise completa de apps de terceiros:
```bash
./batch_analysis.sh --stream
```

Análise rápida, apenas permissões:
```bash
SKIP_SECRETS=true ./batch_analysis.sh --stream
```

Análise noturna com timeout reduzido:
```bash
SECRETS_TIMEOUT=90 ./batch_analysis.sh --stream
```

Download de APKs para diretório padrão (`./device_apks`):
```bash
./batch_analysis.sh --pull
```

Download de APKs para diretório específico:
```bash
./batch_analysis.sh --pull ./meus_apks
```

Análise paralela com download automático (fluxo completo):
```bash
ENABLE_PARALLEL=true PARALLEL_JOBS=4 ./batch_analysis.sh --pull
```

Análise com cleanup automático (sem prompt):
```bash
CLEANUP_AFTER_ANALYSIS=yes ./batch_analysis.sh --pull
```

Manter APKs após análise (sem prompt):
```bash
CLEANUP_AFTER_ANALYSIS=no ENABLE_PARALLEL=true ./batch_analysis.sh --pull
```

Análise de APKs já baixados:
```bash
./batch_analysis.sh ./pasta_com_apks
```

### Saída

Os resultados são organizados em `./analysis_results/`:

```
analysis_results/
├── SUMMARY_REPORT.md        # Relatório consolidado
├── recommended_removal.txt  # Pacotes CRITICAL/HIGH para remoção prioritária
├── UNDO_COMMANDS.sh         # Script de reversão (gerado pelo cleanup)
├── analysis_*.log           # Logs de execução
├── permissions/             # Subdiretório de permissões
│   └── *_permissions.txt    # Permissões perigosas por pacote
└── secrets/                 # Subdiretório de secrets
    ├── *_secrets.json       # Dados brutos do apkleaks
    └── *_secrets.txt        # Secrets formatados
```

---

## Script de Limpeza (interactive_cleanup.sh)

### Descrição

Interface interativa para revisar os resultados da análise e tomar ações sobre cada pacote suspeito. Todas as ações são registradas e podem ser revertidas.

### Comandos Disponíveis

| Comando | Descrição |
|---------|-----------|
| `review` | Revisa todos os pacotes suspeitos (padrão) |
| `recommended` | Revisa apenas pacotes CRITICAL/HIGH (prioridade) |
| `list` | Lista pacotes suspeitos sem tomar ação |
| `package <nome>` | Revisa um pacote específico |
| `restore` | Reverte todas as alterações anteriores |

### Ações por Pacote

Durante a revisão interativa, as seguintes ações estão disponíveis:

| Tecla | Ação | Reversível | Descrição |
|-------|------|------------|-----------|
| `d` | Disable | Sim | Desabilita o app, mantém dados |
| `u` | Uninstall | Sim* | Remove para o usuário atual |
| `f` | Force | Não | Remoção completa (risco para apps de sistema) |
| `s` | Skip | - | Ignora o pacote |
| `i` | Info | - | Exibe informações detalhadas |
| `q` | Quit | - | Encerra a revisão |

*Reversível via `restore` ou factory reset.

### Sintaxe

```bash
./interactive_cleanup.sh [COMANDO] [PACOTE]
```

### Exemplos de Uso

Revisar todos os pacotes suspeitos:
```bash
./interactive_cleanup.sh
```

Revisar apenas pacotes de alta prioridade (CRITICAL/HIGH):
```bash
./interactive_cleanup.sh recommended
```

Listar pacotes sem interação:
```bash
./interactive_cleanup.sh list
```

Revisar pacote específico:
```bash
./interactive_cleanup.sh package com.exemplo.app
```

Restaurar alterações:
```bash
./interactive_cleanup.sh restore
```

---

## Fluxo de Trabalho Recomendado

### 1. Preparação

Conecte o dispositivo via USB e verifique a conexão:

```bash
adb devices
```

A saída deve mostrar o dispositivo com status `device`.

### 2. Análise

Execute a análise. Para uso noturno, recomenda-se:

```bash
SECRETS_TIMEOUT=90 ./batch_analysis.sh --stream 2>&1 | tee analysis.log
```

O comando `tee` salva a saída em arquivo para revisão posterior.

### 3. Revisão dos Resultados

Após a conclusão da análise, consulte o relatório:

```bash
cat ./analysis_results/SUMMARY_REPORT.md
```

### 4. Limpeza Interativa

Inicie a revisão interativa:

```bash
./interactive_cleanup.sh
```

Para cada pacote, o script exibirá:

- Permissões perigosas detectadas
- Secrets ou URLs suspeitos
- Localização do APK (sistema ou usuário)

Escolha a ação apropriada para cada pacote.

### 5. Verificação

Após a limpeza, reinicie o dispositivo e verifique se tudo funciona corretamente.

### 6. Reversão (se necessário)

Caso algum app essencial tenha sido removido:

```bash
./interactive_cleanup.sh restore
```

Ou execute comandos individuais:

```bash
adb shell cmd package install-existing com.exemplo.app
adb shell pm enable com.exemplo.app
```

---

## Referência de Comandos

### Comandos ADB Úteis

| Comando | Descrição |
|---------|-----------|
| `adb shell pm list packages -3` | Lista apps de terceiros |
| `adb shell pm list packages -s` | Lista apps de sistema |
| `adb shell pm list packages -d` | Lista apps desabilitados |
| `adb shell pm disable-user --user 0 <pkg>` | Desabilita app |
| `adb shell pm enable <pkg>` | Habilita app |
| `adb shell pm uninstall -k --user 0 <pkg>` | Remove app (mantém dados) |
| `adb shell cmd package install-existing <pkg>` | Restaura app removido |

### Permissões Monitoradas

O script detecta as seguintes categorias de permissões:

| Categoria | Exemplos |
|-----------|----------|
| Acessibilidade | `BIND_ACCESSIBILITY_SERVICE`, `BIND_DEVICE_ADMIN` |
| Comunicação | `READ_SMS`, `SEND_SMS`, `READ_CALL_LOG` |
| Mídia | `CAMERA`, `RECORD_AUDIO` |
| Localização | `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION` |
| Armazenamento | `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` |
| Sistema | `INSTALL_PACKAGES`, `WRITE_SETTINGS`, `DUMP` |

---

## Estrutura de Arquivos

```
apks_to_analyze/
├── batch_analysis.sh        # Script de análise
├── interactive_cleanup.sh   # Script de limpeza interativa
├── README.md                # Esta documentação
└── analysis_results/        # Diretório de resultados
    ├── SUMMARY_REPORT.md    # Relatório consolidado
    ├── recommended_removal.txt  # Pacotes CRITICAL/HIGH para remoção
    ├── UNDO_COMMANDS.sh     # Script de reversão gerado
    ├── analysis_*.log       # Logs de execução
    ├── permissions/         # Permissões perigosas
    │   └── *_permissions.txt
    └── secrets/             # Secrets e URLs expostos
        ├── *_secrets.json
        └── *_secrets.txt
```

---

## Resolução de Problemas

### Análise travando em "Secrets"

A ferramenta apkleaks pode demorar em APKs grandes. Soluções:

1. Reduzir timeout: `SECRETS_TIMEOUT=60 ./batch_analysis.sh --stream`
2. Pular análise de secrets: `SKIP_SECRETS=true ./batch_analysis.sh --stream`

### Muitos pacotes para revisar

Use o comando `recommended` para focar nos pacotes de alto risco:

```bash
./interactive_cleanup.sh recommended
```

Isso revisa apenas pacotes marcados como CRITICAL ou HIGH no arquivo `recommended_removal.txt`.

### Disco cheio após --pull

O modo `--pull` pode usar vários GB. Soluções:

1. Use cleanup automático: `CLEANUP_AFTER_ANALYSIS=yes ./batch_analysis.sh --pull`
2. Durante o prompt, escolha `s` para manter apenas APKs suspeitos
3. Use `--stream` para uso mínimo de disco

### Paralelismo não funciona

Requisitos para análise paralela:

1. APKs em diretório local (não funciona com `--stream`)
2. Variável habilitada: `ENABLE_PARALLEL=true`
3. GNU parallel instalado (opcional, usa xargs como fallback)

Verificar instalação do parallel:
```bash
which parallel && echo "OK" || echo "Instale: sudo apt install parallel"
```

### Dispositivo não detectado

1. Verifique se depuração USB está ativada
2. Revogue autorizações USB e reconecte
3. Verifique cabo e porta USB

### App essencial removido

Execute a restauração:

```bash
./interactive_cleanup.sh restore
```

Ou restaure individualmente:

```bash
adb shell cmd package install-existing <pacote>
```

### Falha ao remover app de sistema

Apps de sistema protegidos só podem ser desabilitados, não removidos. Use a opção `d` (disable) ao invés de `u` (uninstall).

---

## Considerações de Segurança

- **Não remova apps de sistema sem entender sua função**. Alguns são essenciais para o funcionamento do dispositivo.
- **Permissões não indicam necessariamente malícia**. Apps legítimos como WhatsApp requerem muitas permissões para funcionar.
- **Sempre mantenha backup** antes de remover apps.
- **O script nunca remove apps automaticamente**. Toda remoção requer confirmação manual.
