"""
detector_anomalias_v2.py — Pipeline de detecção c/ IA Robusta
CORREÇÕES: 
 - contamination="auto" (Deixa a matemática decidir o corte).
 - Gabarito imune ao UA (Usa IPs e assinaturas para ground truth).
"""
import sys, math, json, warnings
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from elasticsearch import Elasticsearch, helpers
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, str(Path(__file__).parent.parent))
from caminhos import garantir_pastas, CSV_IA, JSON_METRICAS, PNG_MATRIZ_V2

warnings.filterwarnings('ignore')

CONFIG = {
    "es_host":          "http://127.0.0.1:9201",
    "index_origem":     "projeto-nginx-brutos",
    "index_destino":    "projeto-anomalias-ia",
    "if_contamination": "auto", 
    "if_n_estimators":  200,
    "if_random_state":  42,
}

FERRAMENTAS_UA  = ['nmap', 'sqlmap', 'burp', 'nikto', 'masscan', 'zgrab', 'nuclei']
PAYLOADS_URL = [
    'union select', '<script', '../', 'etc/passwd', 'cmd=', 'eval(', 
    'or 1=1', '"="', 'alert(1)', 'system32'
    ]
ENDPOINTS_LOGIN = ['/rest/user/login', '/api/users', '/login', '/admin', '/auth']
IPS_ATACANTES   = ["10.0.0.1", "10.0.0.2", "172.16.0.99", "185.220.101.5"] # Usado para o Ground Truth

def extrair_dados(es):
    print("[*] Extraindo logs do Elasticsearch via Scroll API (suporta > 10k)...")
    
    # O helpers.scan burla a trava de 10k dividindo a busca em pequenos lotes automáticos
    cursor = helpers.scan(
        es,
        index=CONFIG["index_origem"],
        query={"query": {"match_all": {}}}
    )
    
    logs = [dict(**h['_source'], _id=h['_id']) for h in cursor]
    df = pd.DataFrame(logs)
    
    print(f"[OK] {len(df)} logs extraídos com sucesso.")
    return df

def preparar_features(df):
    print("[*] Engenharia de Features (6 variáveis focadas no comportamento)...")

    for col, val in {'user_agent':'', 'url':'/', 'status':'200', 'bytes':'0', 'clientip':'0.0.0.0'}.items():
        if col not in df.columns: df[col] = val

    df['status_code_num']    = pd.to_numeric(df['status'], errors='coerce').fillna(200)
    df['bytes_transferidos'] = pd.to_numeric(df['bytes'],  errors='coerce').fillna(0)
    df['tamanho_url']        = df['url'].apply(lambda x: len(str(x)))

    df['is_erro'] = (df['status_code_num'] >= 400).astype(int)
    df['taxa_erro_endpoint'] = df.groupby('url')['is_erro'].transform('mean')
    df['freq_endpoint_erro'] = df.groupby('url')['is_erro'].transform('sum')
    df['eh_endpoint_login'] = df['url'].apply(lambda x: 1 if any(e in str(x).lower() for e in ENDPOINTS_LOGIN) else 0)

    # CORREÇÃO: O Gabarito oficial agora identifica o atacante pelo IP simulado, não pelo User-Agent
    def rotular(row):
        ua     = str(row.get('user_agent', '')).lower()
        url    = str(row.get('url', '')).lower()
        msg    = str(row.get('message', '')).lower()
        ip     = str(row.get('clientip', ''))
        method = str(row.get('method', '')).upper()

        if any(t in ua for t in FERRAMENTAS_UA): return 'Anomalia'
        if any(p in url for p in PAYLOADS_URL): return 'Anomalia'
        if any(t in msg for t in ['nmap scripting', 'sqlmap', 'union select']): return 'Anomalia'
        if ip in IPS_ATACANTES: return 'Anomalia'
        
        # CORREÇÃO DO GABARITO: Qualquer POST no endpoint de login foi o nosso script de força bruta!
        if '/rest/user/login' in url and method == 'POST': return 'Anomalia'
        
        return 'Normal'

    df['label_real'] = df.apply(rotular, axis=1)

    n_normal   = (df['label_real'] == 'Normal').sum()
    n_anomalia = (df['label_real'] == 'Anomalia').sum()
    print(f"[OK] Ground Truth -> Normal: {n_normal} | Anomalia: {n_anomalia} ({(n_anomalia/max(len(df), 1)*100):.1f}%)")

    features = ['status_code_num','bytes_transferidos','tamanho_url', 'taxa_erro_endpoint','freq_endpoint_erro','eh_endpoint_login']
    return df, df[features]

def aplicar_ia(df, X):
    print("\n[*] Treinando Isolation Forest (Contaminação Automática)...")
    modelo = IsolationForest(
        n_estimators=CONFIG["if_n_estimators"],
        contamination=CONFIG["if_contamination"],
        random_state=CONFIG["if_random_state"]
    )
    df['predicao_ia']      = modelo.fit_predict(X)
    df['classificacao_ia'] = ['Anomalia' if x == -1 else 'Normal' for x in df['predicao_ia']]
    df['score_anomalia']   = modelo.decision_function(X)
    return df

def gerar_metricas(df):
    labels = ['Normal', 'Anomalia']
    report = classification_report(df['label_real'], df['classificacao_ia'], labels=labels, output_dict=True)
    print("\n" + classification_report(df['label_real'], df['classificacao_ia'], labels=labels))

    cm = confusion_matrix(df['label_real'], df['classificacao_ia'], labels=labels)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title('Matriz de Confusão — Isolation Forest (Contaminação Auto)', fontsize=14)
    plt.ylabel('Gabarito Oficial (Ground Truth)', fontsize=12)
    plt.xlabel('Predição da IA', fontsize=12)
    plt.tight_layout()
    plt.savefig(PNG_MATRIZ_V2, dpi=300)
    plt.close()

    tn, fp, fn, tp = cm.ravel()
    metricas = {
        "modelo": "Isolation Forest v2",
        "features": ["status_code_num", "bytes_transferidos", "tamanho_url", "taxa_erro_endpoint", "freq_endpoint_erro", "eh_endpoint_login"],
        "resultados": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
            "acuracia":          round(report['accuracy'], 4),
            "precisao_anomalia": round(report['Anomalia']['precision'], 4),
            "recall_anomalia":   round(report['Anomalia']['recall'], 4),
            "f1_anomalia":       round(report['Anomalia']['f1-score'], 4),
        },
        "gerado_em": datetime.now().isoformat()
    }
    with open(JSON_METRICAS, 'w') as f: json.dump(metricas, f, indent=2, ensure_ascii=False)
    return metricas

def exportar(df, es):
    df.to_csv(CSV_IA, index=False)
    def limpar(doc): return {k: (None if isinstance(v, float) and (math.isnan(v) or math.isinf(v)) else v) for k, v in doc.items()}
    ok, erros = 0, 0
    for doc in df.to_dict(orient='records'):
        did = doc.pop('_id', None)
        try:
            es.index(index=CONFIG["index_destino"], id=did, document=limpar(doc))
            ok += 1
        except: erros += 1
    print(f"[OK] {ok} registros salvos no Elasticsearch (Erros: {erros})")

if __name__ == "__main__":
    garantir_pastas()
    es = Elasticsearch(CONFIG["es_host"])
    if not es.ping():
        print("[✘] Elasticsearch offline.")
        exit(1)
    df = extrair_dados(es)
    if df.empty: exit(1)
    df, X = preparar_features(df)
    df    = aplicar_ia(df, X)
    m     = gerar_metricas(df)
    exportar(df, es)