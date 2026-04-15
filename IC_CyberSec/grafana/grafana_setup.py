"""
================================================================================
GRAFANA SETUP v2.0 - Projeto de IC (Versão de Apresentação)
================================================================================
Autor: Andrey Rodrigues Moreira

DESCRIÇÃO:
  Provisiona o Dashboard de SOC (Security Operations Center) focado na 
  Inteligência Artificial, com métricas reais de validação.
================================================================================
"""

import requests
import json
import warnings

warnings.filterwarnings('ignore')

CONFIG = {
    "grafana_url": "http://localhost:3001",
    "usuario": "admin",
    "senha": "admin",
    # URL do Elasticsearch como o Grafana enxerga dentro da rede Docker
    "es_url_interno": "http://elasticsearch:9200", 
}

SESSION = requests.Session()
SESSION.auth = (CONFIG["usuario"], CONFIG["senha"])
SESSION.headers.update({"Content-Type": "application/json"})
BASE = CONFIG["grafana_url"]


def verificar_grafana():
    try:
        r = SESSION.get(f"{BASE}/api/health", timeout=5)
        if r.status_code == 200:
            print("[✔] Grafana acessível e pronto.")
            return True
    except Exception:
        pass
    print("[✘] Grafana não responde em", BASE)
    print("    Verifique: docker-compose ps | grep grafana")
    return False


def criar_datasource():
    print("[*] Configurando datasource Elasticsearch...")
    payload = {
        "name": "Elasticsearch-IC",
        "type": "elasticsearch",
        "url": CONFIG["es_url_interno"],
        "access": "proxy",
        "isDefault": True,
        "jsonData": {
            "esVersion": "8.0.0",
            "timeField": "@timestamp",
            "interval": "Daily"
        }
    }
    
    r = SESSION.get(f"{BASE}/api/datasources/name/Elasticsearch-IC")
    if r.status_code == 200:
        return r.json()['uid']
    
    r = SESSION.post(f"{BASE}/api/datasources", json=payload)
    if r.status_code in [200, 201]:
        return r.json()['datasource']['uid']
    return "elasticsearch-ic"


def criar_dashboard_soc(ds_uid):
    print("[*] Criando Dashboard SOC (Security Operations Center)...")

    dashboard = {
        "title": "SOC: Inteligência Artificial (Isolation Forest)",
        "tags": ["ic", "soc", "ia"],
        "timezone": "browser",
        "refresh": "10s",
        "panels": [
            # Painel 1: Tráfego Total
            {
                "id": 1, "type": "stat", "gridPos": {"x": 0, "y": 0, "w": 4, "h": 4},
                "title": "🌐 Tráfego Total Analisado",
                "targets": [{
                    "datasource": {"type": "elasticsearch", "uid": ds_uid},
                    "index": "projeto-anomalias-ia", "query": "*", "timeField": "@timestamp",
                    "metrics": [{"type": "count", "id": "1"}]
                }]
            },
            # Painel 2: Bloqueios IA
            {
                "id": 2, "type": "stat", "gridPos": {"x": 4, "y": 0, "w": 4, "h": 4},
                "title": "🚨 Bloqueios pela IA",
                "options": {"colorMode": "background"},
                "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "red"}}},
                "targets": [{
                    "datasource": {"type": "elasticsearch", "uid": ds_uid},
                    "index": "projeto-anomalias-ia", "query": "classificacao_ia:\"Anomalia\"",
                    "timeField": "@timestamp", "metrics": [{"type": "count", "id": "1"}]
                }]
            },
            # Painel 3: Ataques Reais (Ground Truth)
            {
                "id": 3, "type": "stat", "gridPos": {"x": 8, "y": 0, "w": 4, "h": 4},
                "title": "🎯 Ataques Reais (Gabarito)",
                "options": {"colorMode": "background"},
                "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "orange"}}},
                "targets": [{
                    "datasource": {"type": "elasticsearch", "uid": ds_uid},
                    "index": "projeto-anomalias-ia", "query": "label_real:\"Anomalia\"",
                    "timeField": "@timestamp", "metrics": [{"type": "count", "id": "1"}]
                }]
            },
            # Painel 4: Donut - Proporção da Decisão
            {
                "id": 4, "type": "piechart", "gridPos": {"x": 12, "y": 0, "w": 12, "h": 8},
                "title": "Proporção da Decisão da Inteligência Artificial",
                "options": {"pieType": "donut"},
                "targets": [{
                    "datasource": {"type": "elasticsearch", "uid": ds_uid},
                    "index": "projeto-anomalias-ia", "query": "*", "timeField": "@timestamp",
                    "metrics": [{"type": "count", "id": "1"}],
                    "bucketAggs": [{"type": "terms", "field": "classificacao_ia.keyword", "id": "2", "settings": {"size": "2"}}]
                }]
            },
            # Painel 5: Top URLs Atacadas (Onde o IP falha, a URL entrega)
            {
                "id": 5, "type": "bargauge", "gridPos": {"x": 0, "y": 4, "w": 12, "h": 8},
                "title": "🔥 Top Endpoints Alvos de Anomalia",
                "options": {"displayMode": "gradient", "orientation": "horizontal"},
                "targets": [{
                    "datasource": {"type": "elasticsearch", "uid": ds_uid},
                    "index": "projeto-anomalias-ia", "query": "classificacao_ia:\"Anomalia\"",
                    "timeField": "@timestamp", "metrics": [{"type": "count", "id": "1"}],
                    "bucketAggs": [{"type": "terms", "field": "url.keyword", "id": "2", "settings": {"size": "5", "order": "desc", "orderBy": "1"}}]
                }]
            },
            # Painel 6: Linha do Tempo (Timeline)
            {
                "id": 6, "type": "timeseries", "gridPos": {"x": 0, "y": 12, "w": 24, "h": 8},
                "title": "Linha do Tempo: Monitoramento Ativo (Normal vs Anomalia)",
                "options": {"legend": {"displayMode": "list"}},
                "targets": [
                    {
                        "datasource": {"type": "elasticsearch", "uid": ds_uid},
                        "index": "projeto-anomalias-ia", "query": "classificacao_ia:\"Anomalia\"", "alias": "Bloqueios IA",
                        "timeField": "@timestamp", "metrics": [{"type": "count", "id": "1"}],
                        "bucketAggs": [{"type": "date_histogram", "field": "@timestamp", "id": "2", "settings": {"interval": "auto"}}]
                    },
                    {
                        "datasource": {"type": "elasticsearch", "uid": ds_uid},
                        "index": "projeto-anomalias-ia", "query": "classificacao_ia:\"Normal\"", "alias": "Tráfego Limpo",
                        "timeField": "@timestamp", "metrics": [{"type": "count", "id": "1"}],
                        "bucketAggs": [{"type": "date_histogram", "field": "@timestamp", "id": "2", "settings": {"interval": "auto"}}]
                    }
                ]
            }
        ]
    }

    payload = {
        "dashboard": dashboard,
        "overwrite": True,
        "message": "Dashboard Atualizado"
    }
    
    r = SESSION.post(f"{BASE}/api/dashboards/db", json=payload)
    if r.status_code in [200, 201]:
        url = f"{BASE}{r.json().get('url', '')}"
        print(f"[✔] Dashboard criado com sucesso!")
        print(f"    👉 Acesse: {url}")
    else:
        print(f"[!] Erro: {r.status_code}")

if __name__ == "__main__":
    print("=" * 60)
    print("📊  GRAFANA SETUP — Dashboard de Apresentação")
    print("=" * 60)
    
    if verificar_grafana():
        ds_uid = criar_datasource()
        criar_dashboard_soc(ds_uid)