import socket
import json
import time
import os
import shutil
from cryptography.fernet import Fernet

LOGSTASH_HOST = 'localhost'
LOGSTASH_PORT = 5044
TARGET_FILE = "dados_sensíveis_departamento_financeiro.txt.encrypted"
QUARANTINE_DIR = "quarentena_soar/"
KEY_FILE = ".ransomware_key.bin"  # Chave guardada pelo simulador
C2_IP = "45.33.32.156"

# Modos de execução:
#   Sem argumentos: simula falha de chave (sem backup air-gapped)
#   --with-backup-key: usa a chave real do simulador (recuperação bem-sucedida)
USE_REAL_KEY = "--with-backup-key" in os.sys.argv

def send_log(log_data):
    """Envia um log estruturado em JSON para o Logstash via TCP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((LOGSTASH_HOST, LOGSTASH_PORT))
            s.sendall((json.dumps(log_data) + '\n').encode('utf-8'))
    except Exception as e:
        print(f"[!] Erro ao enviar log: {e}")


def trigger_soar_playbook():
    playbook_start = time.time()

    print("\n" + "=" * 60)
    print("  PLAYBOOK SOAR (AÇÕES AUTOMATIZADAS DE RESPOSTA)")
    print("=" * 60)

    # ========================================
    # AÇÃO 1: ISOLAMENTO (File System Quarantine)
    # ========================================
    print(f"\n[SOAR] Ação 1/3: A isolar ficheiro (File System Quarantine)...")

    if os.path.exists(TARGET_FILE):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(TARGET_FILE))
        shutil.move(TARGET_FILE, quarantine_path)

        log1 = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event_type": "SOAR_Response_Action",
            "action_taken": "File_Quarantine",
            "action_sequence": 1,
            "details": f"Ficheiro movido para {QUARANTINE_DIR}",
            "quarantine_path": quarantine_path,
            "status": "SUCCESS",
            "severity": "info",
            "playbook": "ransomware_response"
        }
        send_log(log1)
        print(f"[SOAR] ✓ SUCESSO: Ficheiro isolado em {quarantine_path}")
    else:
        print(f"[SOAR] ✗ AVISO: Ficheiro não encontrado para quarentena.")

    # ========================================
    # AÇÃO 2: BLOQUEIO C2 (Firewall / DNS Block)
    # ========================================
    print(f"\n[SOAR] Ação 2/3: A bloquear comunicação C2 (Firewall)...")

    blocked = False
    try:
        # Tentar iptables SEM sudo (não pede password interativa)
        result = os.system(f"iptables -A OUTPUT -d {C2_IP} -j DROP 2>/dev/null")
        if result == 0:
            block_method = "iptables OUTPUT DROP"
            blocked = True
        else:
            # Fallback: /etc/hosts (bloqueio DNS)
            hosts_entry = f"0.0.0.0 c2-malicious-server.invalid {C2_IP}\n"
            with open("/etc/hosts", "a") as hosts_file:
                hosts_file.write(hosts_entry)
            block_method = "/etc/hosts DNS redirect"
            blocked = True
    except PermissionError:
        # Sem permissões de root, usar /etc/hosts
        try:
            hosts_entry = f"0.0.0.0 c2-malicious-server.invalid {C2_IP}\n"
            with open("/etc/hosts", "a") as hosts_file:
                hosts_file.write(hosts_entry)
            block_method = "/etc/hosts DNS redirect (no root)"
            blocked = True
        except Exception as e:
            block_method = f"FALHA: {e}"
    except Exception as e:
        block_method = f"FALHA: {e}"

    log2 = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event_type": "SOAR_Response_Action",
        "action_taken": "Firewall_C2_Block",
        "action_sequence": 2,
        "blocked_ip": C2_IP,
        "block_method": block_method,
        "status": "SUCCESS" if blocked else "FAILED",
        "severity": "info",
        "playbook": "ransomware_response"
    }
    send_log(log2)
    if blocked:
        print(f"[SOAR] ✓ SUCESSO: IP {C2_IP} bloqueado via {block_method}")
    else:
        print(f"[SOAR] ✗ FALHA ao bloquear IP {C2_IP}")

    # ========================================
    # AÇÃO 3: RECUPERAÇÃO (Decryption from Backup Key)
    # ========================================
    print(f"\n[SOAR] Ação 3/3: A recuperar dados (Decryption)...")

    quarantined_file = os.path.join(QUARANTINE_DIR, os.path.basename(TARGET_FILE))

    if os.path.exists(quarantined_file):
        # Carregar chave de backup (air-gapped KMS)
        if USE_REAL_KEY and os.path.exists(KEY_FILE):
            # Modo com chave de backup: recuperação bem-sucedida
            with open(KEY_FILE, "rb") as kf:
                recovery_key = kf.read()
            recovery_method = "air-gapped_KMS_backup"
            print(f"[SOAR] Chave de backup carregada do KMS air-gapped: {recovery_key[:20].decode()}...")
        else:
            # Modo sem backup: chave diferente (falha intencional)
            recovery_key = Fernet.generate_key()
            recovery_method = "generated_placeholder (NO_BACKUP)"

        cipher_suite = Fernet(recovery_key)

        with open(quarantined_file, "rb") as f:
            encrypted_data = f.read()

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            recovered_file = "dados_recuperados.txt"
            with open(recovered_file, "wb") as f:
                f.write(decrypted_data)

            log3 = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event_type": "SOAR_Response_Action",
                "action_taken": "Data_Recovery",
                "action_sequence": 3,
                "recovery_method": recovery_method,
                "recovered_file": recovered_file,
                "status": "SUCCESS",
                "severity": "info",
                "playbook": "ransomware_response"
            }
            send_log(log3)
            print(f"[SOAR] ✓ SUCESSO: Ficheiro decifrado -> {recovered_file}")
            print(f"[SOAR] Conteúdo recuperado: {decrypted_data.decode('utf-8')[:60]}...")

        except Exception:
            log3 = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event_type": "SOAR_Response_Action",
                "action_taken": "Data_Recovery",
                "action_sequence": 3,
                "recovery_method": recovery_method,
                "status": "FAILED_KEY_MISMATCH",
                "severity": "critical",
                "details": "Chave de decifragem incompatível. Necessário aceder ao backup air-gapped.",
                "recommendation": "Usar política de backups 3-2-1 com air-gap (Sec. VI.D)",
                "playbook": "ransomware_response"
            }
            send_log(log3)
            print(f"[SOAR] ✗ FALHA CRÍTICA: Chave de decifragem incompatível.")
            print(f"[SOAR] => Necessário usar backup air-gapped da chave (política 3-2-1)")
    else:
        print(f"[SOAR] ✗ Ficheiro não encontrado em quarentena para recuperação.")

    # ========================================
    # RESUMO DO PLAYBOOK
    # ========================================
    playbook_time = time.time() - playbook_start

    summary_log = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event_type": "SOAR_Playbook_Summary",
        "playbook": "ransomware_response",
        "total_actions": 3,
        "execution_time_seconds": round(playbook_time, 3),
        "status": "COMPLETED",
        "severity": "info"
    }
    send_log(summary_log)

    print(f"\n{'=' * 60}")
    print(f"  PLAYBOOK CONCLUÍDO em {playbook_time:.3f}s")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    trigger_soar_playbook()
