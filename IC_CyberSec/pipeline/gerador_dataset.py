"""
================================================================================
GERADOR DE DATASET v3.0 - Proporção Realista (Estudo de Caso CSIC)
================================================================================
Meta: ~15.000 logs totais.
Proporção: ~62% Normal (9.300) | ~38% Anomalia (5.700)
Melhorias: Diversificação de ataques (SQLi, XSS, Path Traversal nativos) e 
intensificação do Nmap/SQLMap para reduzir a dependência exclusiva de Força Bruta.
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
# CONFIGURAÇÕES (Matemática CSIC 2010)
# ==========================================
CONFIG = {
    "alvo": "http://localhost:80",
    "total_normal": 9300,        # ~62% do tráfego
    "total_forca_bruta": 2000,   # Volume fixo de anomalias
    "total_ataques_web": 2000,   # SQLi, XSS, LFI nativos para garantir volume
    "timeout_requisicao": 3,
    "log_execucao": f"execucao_gerador_v3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
}

IPS_SIMULADOS_NORMAIS = [f"192.168.1.{i}" for i in range(10, 99)]
IPS_SIMULADOS_ATACANTES = ["10.0.0.1", "10.0.0.2", "172.16.0.99", "185.220.101.5"]

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

# Payloads clássicos para simular ataques manuais
PAYLOADS_WEB = [
    "' OR 1=1 --", 
    "\" OR \"a\"=\"a", 
    "<script>alert(1)</script>", 
    "../../../etc/passwd", 
    "../../../../windows/system32/cmd.exe",
    "union select null, null, null",
    "admin' #"
]

SENHAS_BRUTA = ["admin", "123456", "password", "admin123", "root", "test", "guest", "qwerty"]
EMAILS_BRUTA = ["admin@juice-sh.op", "test@test.com", "user@example.com"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(CONFIG["log_execucao"], encoding="utf-8"), logging.StreamHandler()])
log = logging.getLogger(__name__)


def verificar_dependencias():
    tem_nmap = shutil.which("nmap") is not None
    tem_docker = shutil.which("docker") is not None
    return tem_nmap, tem_docker


def gerar_trafego_normal():
    log.info(f"Gerando {CONFIG['total_normal']} requisições normais (~62%)...")
    sucesso, falhas = 0, 0
    for i in range(CONFIG["total_normal"]):
        headers = {"X-Forwarded-For": random.choice(IPS_SIMULADOS_NORMAIS), "User-Agent": random.choice(USER_AGENTS)}
        try:
            requests.get(f"{CONFIG['alvo']}{random.choice(ENDPOINTS_NORMAIS)}", headers=headers, timeout=CONFIG["timeout_requisicao"])
            sucesso += 1
            if sucesso % 2000 == 0: log.info(f"  -> Progresso: {sucesso}/{CONFIG['total_normal']} acessos normais...")
        except: falhas += 1
    log.info(f"✔ Tráfego normal finalizado. Sucesso: {sucesso} | Falhas: {falhas}")


def gerar_forca_bruta_http():
    log.info(f"Gerando {CONFIG['total_forca_bruta']} tentativas de força bruta HTTP...")
    ip_atacante = random.choice(IPS_SIMULADOS_ATACANTES)
    sucesso = 0
    for i in range(CONFIG["total_forca_bruta"]):
        payload = {"email": random.choice(EMAILS_BRUTA), "password": random.choice(SENHAS_BRUTA)}
        headers = {"X-Forwarded-For": ip_atacante, "Content-Type": "application/json", "User-Agent": random.choice(USER_AGENTS)}
        try:
            requests.post(f"{CONFIG['alvo']}/rest/user/login", json=payload, headers=headers, timeout=CONFIG["timeout_requisicao"])
            sucesso += 1
        except: pass
        time.sleep(0.01)
    log.info(f"✔ Força bruta finalizada ({sucesso} envios).")


def gerar_ataques_web_diretos():
    log.info(f"Gerando {CONFIG['total_ataques_web']} ataques Web (SQLi, XSS, LFI) nativos...")
    ip_atacante = random.choice(IPS_SIMULADOS_ATACANTES)
    sucesso = 0
    for i in range(CONFIG["total_ataques_web"]):
        headers = {"X-Forwarded-For": ip_atacante, "User-Agent": random.choice(USER_AGENTS)}
        endpoint = random.choice(["/api/Products/search?q=", "/rest/user/login?email=", "/#/search?q="])
        payload = random.choice(PAYLOADS_WEB)
        try:
            # Enviamos o payload direto na URL para o Nginx registrar
            requests.get(f"{CONFIG['alvo']}{endpoint}{payload}", headers=headers, timeout=CONFIG["timeout_requisicao"])
            sucesso += 1
        except: pass
        time.sleep(0.01)
    log.info(f"✔ Ataques Web nativos finalizados ({sucesso} envios).")


def disparar_nmap():
    log.info("Disparando varredura Nmap agressiva (Múltiplos scripts)...")
    try:
        # Aumento extremo na agressividade do Nmap para gerar milhares de logs
        subprocess.run(["nmap", "-p", "80", "--script", "http-enum,http-sql-injection,http-xssed,http-csrf,http-methods", "--min-rate", "500", "-T4", "localhost"], capture_output=True, timeout=180)
        log.info("✔ Nmap finalizado.")
    except Exception as e: log.error(f"Erro Nmap: {e}")


def disparar_sqlmap():
    log.info("Disparando SQLMap via Docker (Crawling mais profundo)...")
    try:
        # Level 3, Risk 3 e Crawl ativado para ele varrer o site todo
        subprocess.run(["docker", "run", "--rm", "secsi/sqlmap", "-u", "http://host.docker.internal/", "--crawl=2", "--level=3", "--risk=3", "--batch", "--timeout=180", "--threads=2"], capture_output=True, timeout=200)
        log.info("✔ SQLMap finalizado.")
    except Exception as e: log.error(f"Erro SQLMap: {e}")


if __name__ == "__main__":
    inicio = datetime.now()
    print("=" * 60)
    print("🏭  GERADOR DE DATASET v3.0 — ~15.000 Logs (62% Normal | 38% Anomalia)")
    print("=" * 60)
    
    tem_nmap, tem_docker = verificar_dependencias()
    
    threads = []
    if tem_nmap: threads.append(threading.Thread(target=disparar_nmap))
    if tem_docker: threads.append(threading.Thread(target=disparar_sqlmap))
    threads.append(threading.Thread(target=gerar_forca_bruta_http))
    threads.append(threading.Thread(target=gerar_ataques_web_diretos))
    
    for t in threads: t.start()
    gerar_trafego_normal()
    for t in threads: t.join()

    duracao = (datetime.now() - inicio).seconds
    log.info(f"✅  Dataset gerado com sucesso em {duracao}s! Aguarde 30s para o Logstash indexar.")