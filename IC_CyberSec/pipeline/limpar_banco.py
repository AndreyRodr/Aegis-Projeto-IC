"""
================================================================================
LIMPADOR DE BANCO E LOGS - Preparação para novos testes
================================================================================
"""
import os
import requests
import warnings
from elasticsearch import Elasticsearch

# Desativa alertas de conexão HTTPS não verificada (comum em localhost)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configurações
ES_URL_NGINX = "http://localhost:9201"
ES_URL_WAZUH = "https://localhost:9200"
USER_WAZUH = "admin"
PASS_WAZUH = "SecretPassword" # Ajuste caso a senha do Wazuh Indexer seja diferente

def limpar_banco():
    print("=" * 60)
    print("🧹 LIMPANDO LABORATÓRIO PARA NOVO TESTE")
    print("=" * 60)

    # 1. Limpando a IA (Nginx Logs) - Usa a biblioteca elasticsearch normalmente
    try:
        es_ia = Elasticsearch([ES_URL_NGINX])
        if es_ia.indices.exists(index="projeto-anomalias-ia"):
            es_ia.indices.delete(index="projeto-anomalias-ia")
            print("[OK] Índice 'projeto-anomalias-ia' deletado (Logs da IA zerados).")
        else:
            print("[-] Índice da IA já estava limpo.")
    except Exception as e:
        print(f"[!] Erro ao limpar Nginx/IA: {e}")

    # 2. Limpando os Alertas do Wazuh via Requests (Evita erro 406 de compatibilidade)
    try:
        url_delete = f"{ES_URL_WAZUH}/wazuh-alerts-*/_delete_by_query"
        payload = {"query": {"match_all": {}}}
        headers = {"Content-Type": "application/json"}
        
        resposta = requests.post(
            url_delete, 
            auth=(USER_WAZUH, PASS_WAZUH), 
            headers=headers, 
            json=payload, 
            verify=False
        )
        
        if resposta.status_code in [200, 201]:
            dados = resposta.json()
            deletados = dados.get('deleted', 0)
            print(f"[OK] Wazuh limpo. {deletados} alertas antigos apagados com sucesso.")
        else:
            print(f"[!] Erro ao limpar Wazuh. Status {resposta.status_code}: {resposta.text}")
    except Exception as e:
        print(f"[!] Erro de conexão ao limpar Wazuh: {e}")

    # 3. Limpando arquivos CSV antigos
    arquivos_locais = [
        "dados/alertas_wazuh.csv",
        "dados/base_completa.csv"
    ]
    for arq in arquivos_locais:
        if os.path.exists(arq):
            os.remove(arq)
            print(f"[OK] Arquivo {arq} removido.")

    print("=" * 60)
    print("✅ Ambiente totalmente limpo e pronto para o gerador de dataset!")

if __name__ == "__main__":
    limpar_banco()