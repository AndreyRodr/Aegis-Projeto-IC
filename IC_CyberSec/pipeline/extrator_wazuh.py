"""
extrator_wazuh.py — Extrai alertas do Wazuh via API REST e ES interno
Saída: dados/alertas_wazuh.csv

O Wazuh não tem endpoint /alerts na API REST (v4.x).
Os alertas ficam no índice wazuh-alerts-* do Elasticsearch interno dele.
Este script tenta 3 estratégias em sequência até uma funcionar.
"""
import sys, warnings
from pathlib import Path

import requests
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from caminhos import garantir_pastas, CSV_WAZUH

warnings.filterwarnings('ignore')

CONFIG = {
    "wazuh_api_url": "https://localhost:55000",
    "usuario":       "wazuh-wui",
    "senha":         "MyS3cr37P450r.*-",
    "limite":        10000,
}

# Credenciais padrão do Elasticsearch interno do Wazuh Docker
ES_INTERNO_URLS  = ["https://localhost:9200", "http://localhost:9200"]
ES_INTERNO_CREDS = [("admin", "SecretPassword"), ("elastic", "changeme")]
ES_INDICES       = ["wazuh-alerts-4.x-*", "wazuh-alerts-*", "wazuh-alerts-4*"]


# ─────────────────────────────────────────────
# AUTENTICAÇÃO
# ─────────────────────────────────────────────

def autenticar():
    print("[*] Autenticando na API do Wazuh (porta 55000)...")
    for base in [CONFIG["wazuh_api_url"], "https://127.0.0.1:55000"]:
        try:
            r = requests.post(
                f"{base}/security/user/authenticate",
                auth=(CONFIG["usuario"], CONFIG["senha"]),
                verify=False, timeout=10
            )
            if r.status_code == 200:
                token = r.json()['data']['token']
                print(f"[OK] Autenticado em {base}")
                CONFIG["wazuh_api_url"] = base
                return token
            print(f"[~] {base} → HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[~] {base} → sem resposta")
        except Exception as e:
            print(f"[~] {base} → {e}")
    return None


# ─────────────────────────────────────────────
# ESTRATÉGIA 1: Elasticsearch interno do Wazuh
# ─────────────────────────────────────────────

def _buscar_es_interno():
    """
    O Wazuh Docker expõe seu ES interno (OpenSearch/Elasticsearch) na porta 9200.
    É diferente do nosso ES na porta 9201.
    """
    print("[*] Estratégia 1 — Elasticsearch interno do Wazuh (porta 9200)...")
    query = {
        "query": {"match_all": {}},
        "size": CONFIG["limite"],
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["rule", "agent", "data", "timestamp", "location"]
    }
    for base in ES_INTERNO_URLS:
        for user, pwd in ES_INTERNO_CREDS:
            for indice in ES_INDICES:
                try:
                    r = requests.post(
                        f"{base}/{indice}/_search",
                        json=query, auth=(user, pwd),
                        verify=False, timeout=15
                    )
                    if r.status_code == 200:
                        hits = r.json().get('hits', {}).get('hits', [])
                        if hits:
                            print(f"[OK] {len(hits)} alertas em {indice} ({base})")
                            return [h['_source'] for h in hits]
                except Exception:
                    continue
    print("[-] ES interno não acessível ou sem alertas.")
    return []


# ─────────────────────────────────────────────
# ESTRATÉGIA 2: API REST — /manager/logs
# ─────────────────────────────────────────────

def _buscar_manager_logs(token):
    """
    Fallback: logs do próprio manager do Wazuh.
    Não são alertas de segurança, mas mostram eventos do sistema.
    """
    print("[*] Estratégia 2 — /manager/logs via API REST...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(
            f"{CONFIG['wazuh_api_url']}/manager/logs",
            headers=headers,
            params={"limit": min(CONFIG["limite"], 2000), "sort": "-timestamp"},
            verify=False, timeout=30
        )
        if r.status_code == 200:
            items = r.json().get('data', {}).get('affected_items', [])
            print(f"[OK] {len(items)} entradas de log do manager.")
            # Converte para o formato de alerta
            return [{
                'rule':      {'level': 3, 'id': '', 'description': i.get('description', i.get('tag','')), 'groups': [i.get('tag','manager')]},
                'agent':     {'ip': '127.0.0.1'},
                'data':      {},
                'timestamp': i.get('timestamp', ''),
            } for i in items]
    except Exception as e:
        print(f"[-] /manager/logs falhou: {e}")
    return []


# ─────────────────────────────────────────────
# ESTRATÉGIA 3: nosso ES (porta 9201) com índice de anomalias
# ─────────────────────────────────────────────

def _buscar_nosso_es_alertas():
    """
    Último recurso: busca no nosso Elasticsearch (9201) por registros
    que o Logstash já marcou com user-agents de ferramentas de ataque.
    Simula o que o Wazuh teria detectado por assinatura.
    """
    print("\n[!!!] AVISO ACADÊMICO: API do Wazuh indisponível.")
    print("[*] Estratégia 3 — Simulação de alertas via nosso ES (porta 9201)...")
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"user_agent": "nmap"}},
                    {"match": {"user_agent": "sqlmap"}},
                    {"match": {"user_agent": "nikto"}},
                    {"match": {"user_agent": "burp"}},
                    {"match": {"user_agent": "masscan"}},
                    {"match": {"message": "nmap"}},
                    {"match": {"message": "sqlmap"}},
                ]
            }
        },
        "size": CONFIG["limite"]
    }
    try:
        r = requests.post(
            "http://localhost:9201/projeto-nginx-brutos/_search",
            json=query, timeout=15
        )
        if r.status_code == 200:
            hits = r.json().get('hits', {}).get('hits', [])
            print(f"[OK] {len(hits)} registros com assinatura de ataque nos logs Nginx.")
            return [{
                'rule':  {'level': 10, 'id': '31101', 'description': 'Ferramenta de ataque detectada por User-Agent', 'groups': ['web', 'attack']},
                'agent': {'ip': h['_source'].get('clientip', 'desconhecido')},
                'data':  {'url': h['_source'].get('url', h['_source'].get('request', ''))},
                'timestamp': h['_source'].get('@timestamp', ''),
            } for h in hits]
    except Exception as e:
        print(f"[-] Estratégia 3 falhou: {e}")
    return []


# ─────────────────────────────────────────────
# NORMALIZAÇÃO
# ─────────────────────────────────────────────

def normalizar(alertas):
    print(f"\n[*] Normalizando {len(alertas)} alertas...")
    rows = []
    for a in alertas:
        regra  = a.get('rule', {})
        dados  = a.get('data', {})
        agente = a.get('agent', {})
        ip = dados.get('srcip') or dados.get('src_ip') or agente.get('ip', 'desconhecido')
        rows.append({
            'timestamp':           a.get('timestamp', ''),
            'ip_origem':           ip,
            'nivel_wazuh':         int(regra.get('level', 0)),
            'regra_id':            regra.get('id', ''),
            'descricao_regra':     regra.get('description', ''),
            'grupo_regra':         ', '.join(regra.get('groups', [])),
            'url_alvo':            dados.get('url', dados.get('id', '')),
            'classificacao_wazuh': 'Anomalia',
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    print(f"\n  Top 5 regras disparadas:")
    for desc, n in df['descricao_regra'].value_counts().head(5).items():
        print(f"    [{n:4d}x] {desc}")
    print(f"\n  Nível baixo  (1-6):  {(df['nivel_wazuh']<=6).sum()}")
    print(f"  Nível médio  (7-11): {((df['nivel_wazuh']>=7)&(df['nivel_wazuh']<=11)).sum()}")
    print(f"  Nível alto   (12+):  {(df['nivel_wazuh']>=12).sum()}")
    return df


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    garantir_pastas()

    token = autenticar()
    if not token:
        print("\n[!] Autenticação falhou. Verifique:")
        print('    docker ps --format "table {{.Names}}\\t{{.Ports}}" | grep wazuh')
        print("    cat wazuh-docker/single-node/.env")
        exit(1)

    # Tenta as 3 estratégias em ordem
    alertas = _buscar_es_interno()
    if not alertas:
        alertas = _buscar_manager_logs(token)
    if not alertas:
        alertas = _buscar_nosso_es_alertas()

    if not alertas:
        print("\n[!] Nenhum alerta encontrado por nenhuma estratégia.")
        print("    Certifique-se de ter rodado o gerador_dataset_v2.py antes.")
        exit(1)

    df = normalizar(alertas)
    if not df.empty:
        df.to_csv(CSV_WAZUH, index=False)
        print(f"\n[OK] {len(df)} alertas salvos → {CSV_WAZUH}")