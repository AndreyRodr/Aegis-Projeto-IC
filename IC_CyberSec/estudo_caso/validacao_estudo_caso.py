"""
validacao_estudo_caso.py — Validação com dataset público CSIC 2010
Entrada:  data/payload_full.csv  (ou caminho do kagglehub)
Saídas:   graficos/matriz_estudo_caso.png
          dados/csic2010_limpo.csv
          relatorios/metricas_ia_ambiente_controlado.json  (seção estudo_caso)
"""
import sys, json, warnings
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from elasticsearch import Elasticsearch, helpers
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, str(Path(__file__).parent.parent))
from IC_CyberSec.caminhos import (garantir_pastas, PAYLOAD_FULL, PNG_MATRIZ_CSIC,
                      CSV_CSIC, JSON_METRICAS, RELATORIOS)

warnings.filterwarnings('ignore')

CONFIG = {
    "es_host":       "http://127.0.0.1:9201",
    "index_destino": "resultados-ia-csic2010",
    "contamination": 0.37,
}

ARQUIVO_CSIC = PAYLOAD_FULL  # data/payload_full.csv


def carregar():
    if not ARQUIVO_CSIC.exists():
        print(f"[!] {ARQUIVO_CSIC} não encontrado.")
        print("    Rode download_dataset.py primeiro.")
        exit(1)
    print(f"[*] Lendo {ARQUIVO_CSIC.name}...")
    df = pd.read_csv(ARQUIVO_CSIC, encoding='latin-1', on_bad_lines='skip', engine='python')
    df['payload'] = df['payload'].astype(str).str.encode('ascii','ignore').str.decode('ascii')
    print(f"[OK] {len(df)} registros.")
    return df


def features(df):
    print("[*] Engenharia de Features...")
    df['tamanho_payload']        = df['payload'].apply(len)
    df['qtd_caracteres_especiais'] = df['payload'].apply(lambda x: sum(not c.isalnum() for c in x))
    df['qtd_espacos']            = df['payload'].apply(lambda x: x.count(' '))
    df['label_real'] = df['label'].apply(
        lambda x: 'Anomalia' if str(x).lower() == 'anom' else 'Normal')
    return df, df[['tamanho_payload','qtd_caracteres_especiais','qtd_espacos']]


def aplicar_ia(df, X):
    print("[*] Treinando Isolation Forest (CSIC 2010)...")
    modelo = IsolationForest(n_estimators=200, contamination=CONFIG["contamination"],
                             random_state=42)
    df['predicao_ia']      = modelo.fit_predict(X)
    df['classificacao_ia'] = ['Anomalia' if x==-1 else 'Normal' for x in df['predicao_ia']]
    return df


def metricas_e_grafico(df):
    labels = ['Normal','Anomalia']
    report = classification_report(df['label_real'], df['classificacao_ia'],
                                   labels=labels, output_dict=True)
    print("\n" + classification_report(df['label_real'], df['classificacao_ia'], labels=labels))

    cm = confusion_matrix(df['label_real'], df['classificacao_ia'], labels=labels)
    plt.figure(figsize=(8,6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges', xticklabels=labels, yticklabels=labels)
    plt.title('Validação Científica — CSIC 2010', fontsize=14)
    plt.ylabel('Gabarito Real', fontsize=12)
    plt.xlabel('Predição da IA', fontsize=12)
    plt.tight_layout()
    plt.savefig(PNG_MATRIZ_CSIC, dpi=300)
    plt.close()
    print(f"[OK] Gráfico → {PNG_MATRIZ_CSIC}")

    resultado = {
        "estudo_caso_csic2010": {
            "acuracia":          round(report['accuracy'],4),
            "precisao_anomalia": round(report['Anomalia']['precision'],4),
            "recall_anomalia":   round(report['Anomalia']['recall'],4),
            "f1_anomalia":       round(report['Anomalia']['f1-score'],4),
            "total_registros":   len(df),
            "gerado_em":         datetime.now().isoformat()
        }
    }
    metricas_path = RELATORIOS / "metricas_csic2010.json"
    with open(metricas_path, 'w') as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)
    print(f"[OK] Métricas → {metricas_path}")
    return resultado


def salvar_csv(df):
    df.to_csv(CSV_CSIC, index=False)
    print(f"[OK] CSV → {CSV_CSIC}")


def enviar_elasticsearch(df):
    try:
        es = Elasticsearch(CONFIG["es_host"])
        if not es.ping():
            print("[!] Elasticsearch offline, pulando indexação.")
            return
        agora = datetime.utcnow().isoformat()
        acoes = [{"_index": CONFIG["index_destino"],
                  "_source": {**doc, "@timestamp": agora}}
                 for doc in df.to_dict(orient='records')]
        helpers.bulk(es, acoes)
        print(f"[OK] {len(acoes)} registros indexados em '{CONFIG['index_destino']}'")
    except Exception as e:
        print(f"[!] Erro Elasticsearch: {e}")


if __name__ == "__main__":
    garantir_pastas()
    df        = carregar()
    df, X     = features(df)
    df        = aplicar_ia(df, X)
    resultado = metricas_e_grafico(df)
    salvar_csv(df)
    enviar_elasticsearch(df)
    r = resultado['estudo_caso_csic2010']
    print(f"\n[OK] Acurácia {r['acuracia']*100:.1f}% | Recall {r['recall_anomalia']*100:.1f}%")