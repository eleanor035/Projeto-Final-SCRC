import socket
import json
import time
import os
from cryptography.fernet import Fernet

LOGSTASH_HOST = 'localhost'
LOGSTASH_PORT = 5044
TARGET_FILE = "dados_sensíveis_departamento_financeiro.txt"
KEY_FILE = ".ransomware_key.bin"

def send_log(log_data):
    """Envia um log estruturado em JSON para o Logstash via TCP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((LOGSTASH_HOST, LOGSTASH_PORT))
            s.sendall((json.dumps(log_data) + '\n').encode('utf-8'))
    except Exception as e:
        print(f"[!] Erro ao enviar log: {e}")


def simulate_ransomware():
    print("=" * 60)
    print("  SIMULADOR DE RANSOMWARE (CIFRAGEM REAL AES)")
    print("=" * 60)

    # 1. Gerar chave de cifragem real (Simulação: o C2 envia a chave)
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    print(f"\n[*] Chave AES gerada: {key.decode()[:30]}...")

    # Guardar a chave num ficheiro (simula backup do KMS para o SOAR usar)
    with open(KEY_FILE, "wb") as kf:
        kf.write(key)
    print(f"[*] Chave guardada em {KEY_FILE} (para recuperação pelo SOAR)")

    # 2. Criar ficheiro alvo com dados sintéticos
    fake_data = "IBAN: PT50123456789012345678901 | Password Admin: Sup3rS3cr3t!"
    with open(TARGET_FILE, "w") as f:
        f.write(fake_data)
    print(f"[*] Ficheiro alvo criado: {TARGET_FILE}")

    # Registar timestamp de início para medição de MTTD
    start_time = time.time()

    # 3. CIFRAGEM REAL DO FICHEIRO
    time.sleep(1)
    with open(TARGET_FILE, "rb") as f:
        file_data = f.read()

    encrypted_data = cipher_suite.encrypt(file_data)

    encrypted_filename = TARGET_FILE + ".encrypted"
    with open(encrypted_filename, "wb") as f:
        f.write(encrypted_data)

    # Remover o original (comportamento real do ransomware)
    try:
        os.remove(TARGET_FILE)
        print(f"[!] Ficheiro original removido.")
    except FileNotFoundError:
        print(f"[!] AVISO: Ficheiro original já não existia.")

    print(f"[!] FICHEIRO CIFRADO COM SUCESSO -> {encrypted_filename}")
    encryption_time = time.time() - start_time
    print(f"[*] Tempo de cifragem: {encryption_time:.3f}s")

    # 4. Enviar log para o SIEM (camada de fontes de dados -> ingestão)
    log = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event_type": "Ransomware_Execution",
        "algorithm_used": "AES-128-CBC (Fernet/PKCS7+HMAC-SHA256)",
        "key_exchange": "Hybrid (simulated RSA-2048 + AES-128)",
        "target_file": encrypted_filename,
        "status": "SUCCESS",
        "severity": "critical",
        "encryption_time_seconds": round(encryption_time, 3),
        "mitre_attack": "T1486 (Data Encrypted for Impact)"
    }
    send_log(log)
    print("[*] Log de cifragem enviado para o SIEM (Logstash -> Elasticsearch).")

    # 5. Simular comunicação C2 (log adicional)
    c2_log = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event_type": "C2_Communication",
        "destination_ip": "45.33.32.156",
        "destination_port": 443,
        "protocol": "HTTPS/TLS",
        "status": "BLOCKED",
        "severity": "high",
        "mitre_attack": "T1071 (Application Layer Protocol)"
    }
    send_log(c2_log)
    print("[*] Log de comunicação C2 enviado para o SIEM.")
    print("\n" + "=" * 60)
    print("  SIMULAÇÃO CONCLUÍDA - Aguardar resposta SOAR")
    print("=" * 60)


if __name__ == "__main__":
    simulate_ransomware()
