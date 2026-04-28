# Protótipo SIEM/SOAR — Gestão de Incidentes de Cibersegurança

Leonor Pereira – 104810
Luís Salazar – 104507
Malam Sanhá – 125754

## Arquitetura

```
┌─────────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Simulador Ransomware│────▶│  Logstash       │────▶│  Elasticsearch  │
│  (Fonte de Dados)   │ TCP │  (Ingestão)     │     │  (SIEM Engine)  │
│  simulador_ransom.. │5044 │  logstash.conf  │     │  :9200          │
└─────────────────────┘     └─────────────────┘     └────────┬────────┘
                                                               │
┌─────────────────────┐     ┌─────────────────┐              │
│  SOAR Playbook       │────▶│  Logstash       │──────────────┘
│  soar_playbook.py    │ TCP │  :5044          │
│  (Resposta Autom.)   │     └─────────────────┘
└─────────────────────┘              │
                                     ▼
                             ┌─────────────────┐
                             │  Kibana          │
                             │  (Dashboards)    │
                             │  :5601           │
                             └─────────────────┘
```

## Início Rápido

### Pré-requisitos
- Docker e Docker Compose
- Python 3.8+ com `cryptography>=42.0.0`

### Passo 1: Arrancar a infraestrutura ELK

```bash
cd prototype/
docker compose up -d
# Aguardar ~30 segundos para o Elasticsearch ficar pronto
docker compose logs -f  # (Ctrl+C para sair)
```

Verificar que está tudo a funcionar:
```bash
curl http://localhost:9200/_cluster/health
# Deve retornar status: "green" ou "yellow"
```

### Passo 2: Instalar dependências Python

```bash
pip install cryptography
```

### Passo 3: Executar o simulador de ransomware

```bash
python3 simulador_ransomware.py
```

Isto vai:
1. Criar um ficheiro com dados sintéticos (IBAN, credenciais)
2. Cifrar o ficheiro com AES-128-CBC (Fernet: PKCS7 + HMAC-SHA256)
3. Remover o original
4. Enviar logs estruturados para o Logstash → Elasticsearch

### Passo 4: Executar o playbook SOAR

**Modo 1 — Sem chave de backup (simula cenário real sem air-gap):**
```bash
python3 soar_playbook.py
```
→ A recuperação vai FALHAR (chave incompatível), demonstrando a necessidade de backups air-gapped.

**Modo 2 — Com chave de backup air-gapped (recuperação bem-sucedida):**
```bash
python3 soar_playbook.py --with-backup-key
```
→ A recuperação é BEM-SUCEDIDA, demonstrando a importância da política de backups 3-2-1.

### Passo 5: Visualizar no Kibana

Abrir: http://localhost:5601

1. Ir a **Management → Stack Management → Index Patterns**
2. Criar um index pattern: `incident-logs-*`
3. Ir a **Discover** e selecionar o index pattern
4. Os eventos do ransomware e do SOAR devem aparecer

### Passo 6: Medir métricas (para o paper)

```bash
python3 test_metrics.py
```

Isto executa o fluxo completo e reporta:
- **MTTD** (tempo de deteção no SIEM)
- **Tempo de contenção** (execução do playbook SOAR)
- **Resultado da recuperação** (com/sem chave de backup)
- **Documentos indexados** no Elasticsearch

## Ficheiros

| Ficheiro | Descrição |
|----------|-----------|
| `docker-compose.yml` | Infraestrutura ELK (Elasticsearch + Logstash + Kibana) |
| `logstash.conf` | Pipeline de ingestão com filtros de severidade |
| `simulador_ransomware.py` | Simulador de ransomware com cifragem AES-Fernet real |
| `soar_playbook.py` | Playbook SOAR de 3 fases (quarentena + firewall + recuperação) |
| `test_metrics.py` | Script de teste end-to-end para medição de métricas |
| `pyproject.toml` | Dependências do projeto |

## Fluxo Completo (Demo)

```bash
# Terminal 1: Arrancar ELK
docker compose up -d && sleep 30

# Terminal 2: Simular ataque
python3 simulador_ransomware.py

# Terminal 2: Resposta SOAR (sem backup)
python3 soar_playbook.py

# Terminal 2: Re-simular e responder COM backup
python3 simulador_ransomware.py
python3 soar_playbook.py --with-backup-key

# Terminal 3: Kibana
# Abrir http://localhost:5601
```

## Limpeza

```bash
docker compose down -v          # Parar e remover volumes
rm -rf quarentena_soar/         # Remover diretório de quarentena
rm -f .ransomware_key.bin       # Remover chave
rm -f dados_recuperados.txt     # Remover ficheiro recuperado
```
