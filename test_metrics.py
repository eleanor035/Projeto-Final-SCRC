import subprocess
import sys
import time
import json
import urllib.request
import urllib.error

ELASTICSEARCH_URL = "http://localhost:9200"
INDEX_PATTERN = "incident-logs-*"
WAIT_INTERVAL = 0.5  # segundos entre cada verificação
MAX_WAIT = 30  # segundos máximos de espera


def wait_for_elasticsearch():
    """Aguarda até que o Elasticsearch esteja acessível."""
    print("[*] A aguardar Elasticsearch...")
    for i in range(30):
        try:
            req = urllib.request.Request(f"{ELASTICSEARCH_URL}/_cluster/health")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                if data.get("status") in ("green", "yellow"):
                    print(f"[✓] Elasticsearch pronto (status: {data['status']})")
                    return True
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(2)
    print("[✗] Elasticsearch não ficou disponível a tempo.")
    return False


def wait_for_log(event_type, max_wait=MAX_WAIT):
    """
    Espera até que um evento com o dado event_type apareça no Elasticsearch.
    Retorna o tempo de espera em segundos.
    """
    start = time.time()
    query = json.dumps({
        "query": {
            "match": {
                "event_type": event_type
            }
        },
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }).encode()

    while time.time() - start < max_wait:
        try:
            req = urllib.request.Request(
                f"{ELASTICSEARCH_URL}/{INDEX_PATTERN}/_search",
                data=query,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                hits = data.get("hits", {}).get("total", {}).get("value", 0)
                if hits > 0:
                    return round(time.time() - start, 3)
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(WAIT_INTERVAL)

    return None  # Timeout


def run_command(cmd, description):
    """Executa um comando e retorna o tempo de execução."""
    print(f"\n[*] {description}...")
    start = time.time()
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    elapsed = round(time.time() - start, 3)

    # Mostrar output do comando
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            print(f"    {line}")
    if result.stderr:
        for line in result.stderr.strip().split('\n')[:5]:
            print(f"    [stderr] {line}")

    return elapsed, result.returncode


def count_elasticsearch_docs():
    """Conta o número total de documentos no índice."""
    try:
        req = urllib.request.Request(f"{ELASTICSEARCH_URL}/{INDEX_PATTERN}/_count")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("count", 0)
    except:
        return 0


def main():
    print("=" * 65)
    print("  TESTE END-TO-END — PROTÓTIPO SIEM/SOAR")
    print("  Medição de métricas para o paper")
    print("=" * 65)

    # Step 0: Verificar Elasticsearch
    if not wait_for_elasticsearch():
        print("\n[✗] Abortando: Elasticsearch não disponível.")
        print("    Certifique-se de executar: docker compose up -d")
        sys.exit(1)

    initial_docs = count_elasticsearch_docs()
    print(f"[*] Documentos iniciais no Elasticsearch: {initial_docs}")

    # ========================================
    # TEST 1: MTTD (Mean Time to Detect)
    # ========================================
    print("\n" + "-" * 65)
    print("  TESTE 1: MTTD (Mean Time to Detect)")
    print("  Mede: tempo desde o ransomware até o log no SIEM")
    print("-" * 65)

    # Executar simulador
    sim_time, sim_rc = run_command(
        [sys.executable, "simulador_ransomware.py"],
        "A executar simulador de ransomware"
    )

    if sim_rc != 0:
        print("[✗] Simulador falhou!")
        sys.exit(1)

    # Medir MTTD: tempo até o log Ransomware_Execution aparecer
    print("\n[*] A medir MTTD (tempo até deteção no SIEM)...")
    mttd = wait_for_log("Ransomware_Execution")

    if mttd is not None:
        print(f"[✓] MTTD medido: {mttd} segundos")
    else:
        print(f"[!] MTTD: timeout após {MAX_WAIT}s (log pode ter sido indexado mais tarde)")

    # ========================================
    # TEST 2: SOAR Containment Time
    # ========================================
    print("\n" + "-" * 65)
    print("  TESTE 2: Tempo de Contenção (SOAR Playbook)")
    print("  Mede: tempo de execução completa do playbook")
    print("-" * 65)

    # Executar SOAR playbook (sem chave de backup → falha intencional)
    soar_time, soar_rc = run_command(
        [sys.executable, "soar_playbook.py"],
        "A executar playbook SOAR (sem backup de chave)"
    )

    print(f"\n[*] Tempo de contenção (playbook completo): {soar_time} segundos")

    # Medir tempo até SOAR_Response_Action aparecer
    soar_detect = wait_for_log("SOAR_Response_Action")
    if soar_detect is not None:
        print(f"[✓] SOAR action detetada no SIEM em {soar_detect}s")

    # ========================================
    # TEST 3: Recovery com chave de backup
    # ========================================
    print("\n" + "-" * 65)
    print("  TESTE 3: Recuperação com chave air-gapped")
    print("  Mede: recuperação bem-sucedida com chave de backup")
    print("-" * 65)

    # Recolocar o ficheiro cifrado na quarentena (o SOAR moveu-o)
    # Re-executar simulador para gerar novo ficheiro cifrado + chave
    run_command(
        [sys.executable, "simulador_ransomware.py"],
        "A re-executar simulador para teste de recuperação"
    )

    # Executar SOAR com a flag de chave de backup
    soar_recov_time, soar_recov_rc = run_command(
        [sys.executable, "soar_playbook.py", "--with-backup-key"],
        "A executar playbook SOAR (COM chave de backup)"
    )

    # Verificar se o ficheiro foi recuperado
    recovered = os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dados_recuperados.txt"))
    if recovered:
        print("[✓] Recuperação bem-sucedida com chave air-gapped!")
    else:
        print("[!] Recuperação falhou (verificar logs)")

    # ========================================
    # RESULTADOS FINAIS
    # ========================================
    final_docs = count_elasticsearch_docs()
    new_docs = final_docs - initial_docs

    print("\n" + "=" * 65)
    print("  RESULTADOS DAS MÉTRICAS")
    print("=" * 65)
    print(f"""
  ┌──────────────────────────────────┬──────────────────┐
  │ Métrica                          │ Valor Medido     │
  ├──────────────────────────────────┼──────────────────┤
  │ MTTD (Deteção no SIEM)           │ {mttd if mttd else 'N/A':>14}  │
  │ Tempo de Contenção (SOAR)        │ {soar_time:>12.3f}s    │
  │ Recuperação (c/ backup)          │ {'SUCESSO' if recovered else 'FALHADA':>14}  │
  │ Documentos no Elasticsearch      │ {new_docs:>12} docs  │
  └──────────────────────────────────┴──────────────────┘
""")

    print("Para visualizar no Kibana: http://localhost:5601")
    print("Índice: incident-logs-*\n")


if __name__ == "__main__":
    import os
    main()