"""
caminhos.py — Módulo central de caminhos do projeto IC_CyberSec
Importado por todos os scripts para garantir consistência.
Coloque este arquivo na raiz do projeto (IC_CyberSec/).
"""
from pathlib import Path

# Raiz do projeto = pasta onde este arquivo está
RAIZ = Path(__file__).parent.resolve()

# Pastas de código
PIPELINE   = RAIZ / "pipeline"
ANALISE    = RAIZ / "analise"
ESTUDO     = RAIZ / "estudo_caso"
INFRA      = RAIZ / "infra"

# Pastas de saída (criadas automaticamente se não existirem)
GRAFICOS   = RAIZ / "graficos"
DADOS      = RAIZ / "dados"
RELATORIOS = RAIZ / "relatorios"

# Entradas fixas
DATA_LOGS       = RAIZ / "data" / "logs"
PAYLOAD_FULL    = RAIZ / "data" / "payload_full.csv"

# Arquivos gerados — dados
CSV_IA          = DADOS / "resultados_ia_ambiente_controlado.csv"
CSV_WAZUH       = DADOS / "alertas_wazuh.csv"
CSV_CSIC        = DADOS / "csic2010_limpo.csv"

# Arquivos gerados — relatórios JSON
JSON_METRICAS   = RELATORIOS / "metricas_ia_ambiente_controlado.json"
JSON_COMPARATIVO = RELATORIOS / "relatorio_comparativo.json"
JSON_INSIGHTS   = RELATORIOS / "insights_falsos_negativos.json"

# Arquivos gerados — gráficos PNG
PNG_MATRIZ_V2   = GRAFICOS / "matriz_confusao_v2.png"
PNG_4_QUAD      = GRAFICOS / "grafico_4_quadrantes.png"
PNG_VENN        = GRAFICOS / "grafico_venn.png"
PNG_FALSOS_NEG  = GRAFICOS / "analise_falsos_negativos.png"
PNG_MATRIZ_CSIC = GRAFICOS / "matriz_estudo_caso.png"


def garantir_pastas():
    """Cria todas as pastas de saída se não existirem."""
    for pasta in [GRAFICOS, DADOS, RELATORIOS]:
        pasta.mkdir(parents=True, exist_ok=True)