import sys
import time
import socket
import pandas as pd
from pathlib import Path

# Configuração de Caminhos
DIRETORIO_ATUAL = Path(__file__).resolve().parent
DIRETORIO_RAIZ = DIRETORIO_ATUAL.parent

if str(DIRETORIO_RAIZ) not in sys.path:
    sys.path.append(str(DIRETORIO_RAIZ))

try:
    from caminhos import DIRETORES
except ImportError:
    DIRETORES = {
        "estudo_caso": DIRETORIO_RAIZ / "dados" / "estudo_caso"
    }

# Mapeamento dos rótulos do CIC-IDS2017 para payloads HTTP simulados que acionam regras do Wazuh
PAYLOADS_SIMULADOS = {
    'BENIGN': 'GET /index.php?page=home HTTP/1.1" 200 1024',
    'WEB ATTACK ï¿½ BRUTE FORCE': 'POST /login.php HTTP/1.1" 401 512',
    'WEB ATTACK - BRUTE FORCE': 'POST /login.php HTTP/1.1" 401 512',
    'WEB ATTACK ï¿½ XSS': 'GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 2048',
    'WEB ATTACK - XSS': 'GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 2048',
    'WEB ATTACK ï¿½ SQL INJECTION': "GET /product.php?id=1' OR '1'='1 HTTP/1.1\" 500 4096",
    'WEB ATTACK - SQL INJECTION': "GET /product.php?id=1' OR '1'='1 HTTP/1.1\" 500 4096"
}

def disparar_logs_estudo_caso(host_logstash="127.0.0.1", porta_syslog=5000, max_linhas=5000):
    """
    Lê o dataset de Estudo de Caso e injeta os logs correspondentes via Socket Syslog/Logstash
    para processamento em tempo real no Wazuh.
    """
    pasta_dados = DIRETORES.get("estudo_caso", DIRETORIO_RAIZ / "dados" / "estudo_caso")
    arquivos_csv = list(pasta_dados.glob("*.csv"))

    if not arquivos_csv:
        print(f"[X] Nenhum CSV encontrado em {pasta_dados}")
        return

    caminho_csv = arquivos_csv[0]
    print(f"[*] Lendo dataset para disparo de requisições: {caminho_csv.name}...")

    df = pd.read_csv(caminho_csv, encoding='cp1252', low_memory=False)
    df.columns = df.columns.str.strip()

    coluna_label = [c for c in df.columns if c.lower() == 'label'][0]
    
    # Amostragem para disparo controlado
    df_amostra = df.head(max_linhas).copy()

    print(f"[*] Iniciando envio de {len(df_amostra):,} logs para o Logstash/Wazuh ({host_logstash}:{porta_syslog})...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    sucesso = 0
    for idx, row in df_amostra.iterrows():
        label_raw = str(row[coluna_label]).strip().upper()
        
        # Seleciona o payload HTTP ideal para a regra do Wazuh
        payload = PAYLOADS_SIMULADOS.get(label_raw, 'GET /index.php HTTP/1.1" 200 512')
        
        # Formato de Log de Acesso HTTP Nginx
        log_entry = f'192.168.1.100 - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{payload}'
        
        try:
            sock.sendto(log_entry.encode('utf-8'), (host_logstash, porta_syslog))
            sucesso += 1
            if sucesso % 1000 == 0:
                print(f" -> {sucesso:,} logs injetados no Wazuh...")
                time.sleep(0.1) # Pausa pequena para evitar transbordamento de buffer
        except Exception as e:
            print(f"[!] Erro ao enviar log: {e}")
            break

    sock.close()
    print(f"\n[✓] Injeção de logs finalizada! Total enviado: {sucesso:,} requisições.")

if __name__ == "__main__":
    disparar_logs_estudo_caso()