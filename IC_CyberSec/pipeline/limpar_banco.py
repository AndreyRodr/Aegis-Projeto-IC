"""
limpar_banco.py — Limpeza completa do ambiente de laboratório
Apaga: logs Nginx · CSVs · JSONs · PNGs · índices Elasticsearch
"""
import sys
import warnings
from pathlib import Path

# =======================================================================
# O PULO DO GATO: Ensina ao Python onde está a raiz do projeto
# =======================================================================
DIRETORIO_ATUAL = Path(__file__).resolve().parent
DIRETORIO_RAIZ = DIRETORIO_ATUAL.parent
sys.path.insert(0, str(DIRETORIO_RAIZ))

# Agora o Python consegue enxergar o arquivo caminhos.py na raiz!
from caminhos import (
    RAIZ, DATA_LOGS, CSV_IA, CSV_WAZUH, CSV_CSIC,
    JSON_METRICAS, JSON_COMPARATIVO, JSON_INSIGHTS,
    PNG_MATRIZ_V2, PNG_4_QUAD, PNG_VENN, PNG_FALSOS_NEG, PNG_MATRIZ_CSIC,
    RELATORIOS
)

from elasticsearch import Elasticsearch

warnings.filterwarnings('ignore')

ES_HOST  = "http://127.0.0.1:9201"
INDICES  = ["projeto-nginx-brutos", "projeto-anomalias-ia", "resultados-ia-csic2010", "wazuh-alerts-*"]

LOGS_NGINX = [
    DATA_LOGS / "access.log",
    DATA_LOGS / "error.log",
]

ARQUIVOS_DELETAR = [
    CSV_IA, CSV_WAZUH, CSV_CSIC,
    JSON_METRICAS, JSON_COMPARATIVO, JSON_INSIGHTS,
    PNG_MATRIZ_V2, PNG_4_QUAD, PNG_VENN, PNG_FALSOS_NEG, PNG_MATRIZ_CSIC,
    RELATORIOS / "metricas_csic2010.json",
]

def fase_logs_nginx():
    print("\n[*] FASE 1 — Logs do Nginx (esvaziar)")
    ok = pulados = 0
    for log in LOGS_NGINX:
        if log.exists():
            log.write_text("")
            print(f"  [OK] Esvaziado: {log}")
            ok += 1
        else:
            print(f"  [-]  Não encontrado: {log}")
            pulados += 1

    for log in RAIZ.glob("execucao_gerador*.log"):
        log.unlink()
        print(f"  [OK] Removido: {log.name}")
        ok += 1
    for log in (RELATORIOS).glob("execucao_gerador*.log"):
        log.unlink()
        print(f"  [OK] Removido: {log.name}")
        ok += 1

    print(f"  → {ok} limpos | {pulados} não encontrados")

def fase_arquivos_gerados():
    print("\n[*] FASE 2 — Arquivos gerados (CSVs · JSONs · PNGs)")
    ok = pulados = 0
    for arq in ARQUIVOS_DELETAR:
        if arq.exists():
            arq.unlink()
            tipo = arq.suffix.upper().lstrip('.')
            print(f"  [OK] {tipo:<4}  deletado: {arq.name}")
            ok += 1
        else:
            pulados += 1
    print(f"  → {ok} deletados | {pulados} já inexistentes")

def fase_elasticsearch():
    print("\n[*] FASE 3 — Índices do Elasticsearch")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        es = Elasticsearch(ES_HOST, verify_certs=False)
        if not es.ping():
            print("  [!] Elasticsearch offline — pulando esta fase.")
            return
        for idx in INDICES:
            r = es.indices.delete(index=idx, ignore_unavailable=True)
            if r.get('acknowledged'):
                print(f"  [OK] Índice deletado:    {idx}")
            else:
                print(f"  [-]  Já inexistente:     {idx}")
    except Exception as e:
        print(f"  [!] Erro em '{idx}': {e}")

def confirmar():
    print("=" * 55)
    print("  LIMPEZA COMPLETA DO AMBIENTE — IC_CyberSec")
    print("=" * 55)
    print("\n  O que será apagado:")
    print("  • Logs do Nginx (access.log, error.log) — esvaziados")
    print("  • Todos os CSVs gerados (dados/)")
    print("  • Todos os JSONs gerados (relatorios/)")
    print("  • Todos os PNGs gerados  (graficos/)")
    print("  • Índices Elasticsearch  (projeto-nginx-brutos, etc)")
    print()
    resp = input("  Confirmar? [s/N] ").strip().lower()
    return resp == 's'

if __name__ == "__main__":
    if not confirmar():
        print("\n  Cancelado. Nenhum arquivo foi modificado.\n")
        exit(0)

    fase_logs_nginx()
    fase_arquivos_gerados()
    fase_elasticsearch()

    print("\n" + "=" * 55)
    print("  Laboratório zerado. Pronto para novo experimento.")
    print("  Próximo passo: python pipeline/gerador_dataset_v2.py")
    print("=" * 55 + "\n")