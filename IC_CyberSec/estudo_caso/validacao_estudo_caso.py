import sys
import gc
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import confusion_matrix, accuracy_score, recall_score, precision_score, f1_score

# -------------------------------------------------------------------------
# Configuração de Caminhos
# -------------------------------------------------------------------------
DIRETORIO_ATUAL = Path(__file__).resolve().parent
DIRETORIO_RAIZ = DIRETORIO_ATUAL.parent

if str(DIRETORIO_RAIZ) not in sys.path:
    sys.path.append(str(DIRETORIO_RAIZ))

try:
    from caminhos import DIRETORES
except ImportError:
    DIRETORES = {
        "estudo_caso": DIRETORIO_RAIZ / "dados" / "estudo_caso",
        "graficos": DIRETORIO_RAIZ / "graficos"
    }

# Variáveis comportamentais essenciais do fluxo HTTP/TCP
ATRIBUTOS_CHAVE_WEB = [
    'Destination Port', 
    'Init_Win_bytes_backward', 
    'Init_Win_bytes_forward', 
    'PSH Flag Count', 
    'Down/Up Ratio', 
    'min_seg_size_forward', 
    'Average Packet Size', 
    'Packet Length Mean'
]

def carregar_dados_cicids2017_otimizados():
    """
    Carrega os dados do CIC-IDS2017 selecionando as variáveis descritivas do protocolo HTTP.
    """
    pasta_dados = DIRETORES.get("estudo_caso", DIRETORIO_RAIZ / "dados" / "estudo_caso")
    arquivos_csv = list(pasta_dados.glob("*.csv"))

    if not arquivos_csv:
        print(f"[X] Nenhum arquivo .csv encontrado em {pasta_dados}")
        return None, None

    caminho_csv = arquivos_csv[0]
    print(f"[*] Carregando dataset do Estudo de Caso: {caminho_csv.name}...")

    try:
        df_bruto = pd.read_csv(caminho_csv, encoding='cp1252', low_memory=False)
    except Exception:
        df_bruto = pd.read_csv(caminho_csv, encoding='utf-8', errors='ignore', low_memory=False)

    df_bruto.columns = df_bruto.columns.str.strip()

    colunas_label = [c for c in df_bruto.columns if c.lower() == 'label']
    if not colunas_label:
        print("[X] Coluna 'Label' não localizada.")
        return None, None
    col_label = colunas_label[0]

    # Gabarito Binário: 0 = BENIGN, 1 = Ataques Web (SQLi, XSS, Brute Force)
    y_ground_truth = df_bruto[col_label].apply(
        lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1
    ).to_numpy()

    # Selecionar variáveis descritivas presentes
    colunas_validas = [c for c in ATRIBUTOS_CHAVE_WEB if c in df_bruto.columns]

    X = df_bruto[colunas_validas].apply(pd.to_numeric, errors='coerce').copy()
    del df_bruto
    gc.collect()

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    qtd_benigno = np.bincount(y_ground_truth)[0]
    qtd_ataque = np.bincount(y_ground_truth)[1] if len(np.bincount(y_ground_truth)) > 1 else 0

    print(f"[✓] Atributos extraídos: {X.shape[1]} variáveis essenciais de conexão.")
    print(f"[*] Registros lidos: {qtd_benigno:,} Legítimos | {qtd_ataque:,} Ataques Web (SQLi, XSS, Brute Force).")

    return X_scaled, y_ground_truth

def executar_estudo_caso():
    """
    Executa o Isolation Forest utilizando a função de corte natural da árvore.
    """
    X_scaled, y_true = carregar_dados_cicids2017_otimizados()
    if X_scaled is None:
        return

    print("\n" + "=" * 70)
    print("[*] EXECUTANDO MODELAGEM NÃO SUPERVISIONADA (AEGIS - ISOLATION FOREST)")
    print("=" * 70)

    # Uso da contaminação no modo automático para respeitar a decisão geométrica
    modelo_ia = IsolationForest(
        contamination='auto',
        random_state=42,
        n_jobs=-1
    )

    modelo_ia.fit(X_scaled)
    predicoes_raw = modelo_ia.predict(X_scaled)

    # Mapeamento do modelo: 1 = Normal (0), -1 = Anomalia (1)
    y_pred = np.where(predicoes_raw == -1, 1, 0)

    # Cálculo das Métricas
    vn, fp, fn, vp = confusion_matrix(y_true, y_pred).ravel()
    acuracia = accuracy_score(y_true, y_pred)
    cobertura_recall = recall_score(y_true, y_pred)
    precisao = precision_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("\n" + "📊 RESULTADOS DA VALIDAÇÃO DO ESTUDO DE CASO (CIC-IDS2017 WEB)".center(70))
    print("-" * 70)
    print(f" Verdadeiros Negativos (Legítimos Aprovados): {vn:>10,}")
    print(f" Falsos Positivos      (Alarme Falso)        : {fp:>10,}")
    print(f" Falsos Negativos      (Ataques Evadidos)    : {fn:>10,}")
    print(f" Verdadeiros Positivos (Ataques Detectados)  : {vp:>10,}")
    print("-" * 70)
    print(f" Cobertura / Recall (Taxa de Detecção)       : {cobertura_recall * 100:>9.2f}%")
    print(f" Precisão do Modelo                         : {precisao * 100:>9.2f}%")
    print(f" Acurácia Geral                              : {acuracia * 100:>9.2f}%")
    print(f" Pontuação F1 (F1-Score)                     : {f1 * 100:>9.2f}%")
    print("=" * 70)

    # Geração e Salvamento do Gráfico da Matriz de Confusão
    plt.figure(figsize=(8, 6))
    matriz = np.array([[vn, fp], [fn, vp]])
    sns.heatmap(
        matriz, 
        annot=True, 
        fmt=',d', 
        cmap='Blues',
        xticklabels=['Normal', 'Anomalia'],
        yticklabels=['Normal', 'Anomalia']
    )
    plt.title('Matriz de Confusão — Isolation Forest (CIC-IDS2017 Web Attacks)')
    plt.xlabel('Predição da IA')
    plt.ylabel('Gabarito Oficial (Ground Truth)')
    
    pasta_graficos = DIRETORES.get("graficos", DIRETORIO_RAIZ / "graficos")
    pasta_graficos.mkdir(parents=True, exist_ok=True)
    caminho_imagem = pasta_graficos / "matriz_confusao_estudo_caso.png"
    plt.savefig(caminho_imagem, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"\n[✓] Gráfico da Matriz de Confusão salvo em: {caminho_imagem}")

if __name__ == "__main__":
    executar_estudo_caso()