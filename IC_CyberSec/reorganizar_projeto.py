"""
reorganizar_projeto.py — Reorganiza IC_CyberSec para a estrutura final
Execute na raiz do projeto.
"""
import shutil, glob
from pathlib import Path

RAIZ = Path(".")

MOVER = {
    "infra":      ["docker-compose.yml","nginx.conf","logstash.conf","wazuh-docker"],
    "data":       ["logs","payload_full.csv"],
    "pipeline":   ["gerador_dataset.py","gerador_dataset_v2.py","detector_anomalias.py",
                   "detector_anomalias_v2.py","extrator_wazuh.py","limpar_banco.py"],
    "analise":    ["comparador_wazuh_VS_Ia.py","comparador_wazuh_ia.py",
                   "analise_falso_negativo.py","analise_falsos_negativos.py"],
    "estudo_caso":["download_dataset.py","validacao_estudo_caso.py"],
    "grafana":    ["grafana.setup.py","grafana_setup.py"],
    "graficos":   ["matriz_confusao.png","matriz_confusao_v2.png","matriz_estudo_caso.png",
                   "grafico_4_quadrantes.png","grafico_venn.png","analise_falsos_negativos.png"],
    "dados":      ["resultados_ia_ambiente_controlado.csv","alertas_wazuh.csv",
                   "csic2010_limpo.csv","dataset_csic2010_limpo.csv"],
    "relatorios": ["metricas_ia_ambiente_controlado.json","relatorio_comparativo.json",
                   "insights_falsos_negativos.json","metricas_csic2010.json"],
}

GITIGNORE_ADICIONAR = [
    "\n# Saídas geradas automaticamente",
    "graficos/","dados/","relatorios/",
    "data/logs/","data/payload_full.csv",
    "__pycache__/","*.pyc",".env",
]

ENV_EXEMPLO = """\
# Copie para .env e preencha
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
WAZUH_URL=https://localhost:55000
ES_HOST=http://127.0.0.1:9201
GRAFANA_URL=http://localhost:3001
GRAFANA_USER=admin
GRAFANA_PASSWORD=admin
"""

def criar_pastas():
    for p in MOVER:
        Path(p).mkdir(exist_ok=True)
    # logs de execução também vão para relatorios
    Path("relatorios").mkdir(exist_ok=True)
    print("[OK] Pastas criadas.")

def _mover_um(origem: Path, destino: Path):
    if not origem.exists() or destino.exists():
        return False
    fn = shutil.copytree if origem.is_dir() else shutil.move
    fn(str(origem), str(destino))
    print(f"  {origem.name} → {destino.parent.name}/")
    return True

def mover_arquivos():
    ok = nao = 0
    for dest, nomes in MOVER.items():
        for nome in nomes:
            origem = RAIZ / nome
            if _mover_um(origem, RAIZ / dest / nome):
                ok += 1
            else:
                nao += 1
    # move logs de execução para relatorios/
    for log in RAIZ.glob("execucao_gerador*.log"):
        if _mover_um(log, RAIZ / "relatorios" / log.name):
            ok += 1
    print(f"[OK] {ok} movidos. {nao} não encontrados (normal).")

def atualizar_gitignore():
    gi = RAIZ / ".gitignore"
    existentes = set(gi.read_text().splitlines()) if gi.exists() else set()
    with open(gi, "a") as f:
        for l in GITIGNORE_ADICIONAR:
            if l.strip() not in existentes:
                f.write(l + "\n")
    print("[OK] .gitignore atualizado.")

def gerar_env_exemplo():
    (RAIZ / ".env.exemplo").write_text(ENV_EXEMPLO)
    print("[OK] .env.exemplo criado.")

if __name__ == "__main__":
    print("="*50)
    print("REORGANIZADOR — IC_CyberSec")
    print("="*50)
    criar_pastas()
    mover_arquivos()
    atualizar_gitignore()
    gerar_env_exemplo()
    print("""
[OK] Estrutura final:
  infra/        docker, nginx, logstash, wazuh
  data/         logs brutos, payload_full.csv
  pipeline/     scripts de geração e detecção
  analise/      comparador, falsos negativos
  estudo_caso/  CSIC 2010
  grafana/      setup
  graficos/     *.png  (gerados automaticamente)
  dados/        *.csv  (gerados automaticamente)
  relatorios/   *.json (gerados automaticamente)
  caminhos.py   módulo central de paths
  README.md
""")