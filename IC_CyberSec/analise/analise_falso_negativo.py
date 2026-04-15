"""
analise_falso_negativo.py — Por que ataques escaparam da IA?
Entrada:  dados/resultados_ia_ambiente_controlado.csv
Saídas:   graficos/analise_falsos_negativos.png
          relatorios/insights_falsos_negativos.json
"""
import sys, json, warnings
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).parent.parent))
from caminhos import garantir_pastas, CSV_IA, PNG_FALSOS_NEG, JSON_INSIGHTS

warnings.filterwarnings('ignore')

FEATURES = ['tamanho_url','status_code_num','bytes_transferidos','freq_ip_total','taxa_erro_por_ip']

INTERPRETACOES = {
    "tamanho_url": (
        "FN têm URLs mais curtas — semelhantes ao tráfego normal, dificultando separação matemática.",
        "URLs longas não foram suficientes para diferenciar ataques de tráfego normal."
    ),
    "status_code_num": (
        "FN retornaram status 200 — comportaram-se como requisições legítimas para o servidor.",
        "FN geraram mais erros que os detectados, mas o modelo não os isolou."
    ),
    "bytes_transferidos": (
        "FN transferiram poucos bytes — volume próximo ao tráfego normal (ataques furtivos).",
        "Volume de dados não foi fator diferenciador."
    ),
    "freq_ip_total": (
        "FN fizeram poucas requisições — slow attacks que distribuem o tráfego para evitar detecção.",
        "Frequência não foi determinante para esses falsos negativos."
    ),
    "taxa_erro_por_ip": (
        "FN geraram poucos erros HTTP — ataques sofisticados que não disparam alarmes por taxa de erro.",
        "Taxa de erro similar entre detectados e não detectados."
    ),
}


def carregar():
    if not CSV_IA.exists():
        print(f"[✘] {CSV_IA} não encontrado. Rode o detector primeiro.")
        exit(1)
    df = pd.read_csv(CSV_IA)
    vp = df[(df['label_real']=='Anomalia') & (df['classificacao_ia']=='Anomalia')]
    fn = df[(df['label_real']=='Anomalia') & (df['classificacao_ia']=='Normal')]
    fp = df[(df['label_real']=='Normal')   & (df['classificacao_ia']=='Anomalia')]
    vn = df[(df['label_real']=='Normal')   & (df['classificacao_ia']=='Normal')]
    total = len(vp)+len(fn)
    print(f"  VP: {len(vp)} | FN: {len(fn)} | FP: {len(fp)} | VN: {len(vn)}")
    if total:
        print(f"  Taxa FN: {len(fn)/total*100:.1f}%")
    return df, fn, vp, fp


def analisar(fn, vp):
    feats_presentes = [f for f in FEATURES if f in fn.columns]
    insights = {}
    print(f"\n  {'Feature':<25} {'Detectados':>12} {'Escaparam':>12} {'Diferença':>12}")
    print("  " + "-"*65)
    for feat in feats_presentes:
        med_vp = vp[feat].mean() if not vp.empty else 0
        med_fn = fn[feat].mean() if not fn.empty else 0
        diff   = med_vp - med_fn
        print(f"  {feat:<25} {med_vp:>12.2f} {med_fn:>12.2f} {diff:>+12.2f}")
        interp = INTERPRETACOES.get(feat, ("Sem interpretação.",""))
        insights[feat] = {
            "media_vp": round(med_vp,2), "media_fn": round(med_fn,2),
            "diferenca": round(diff,2),
            "interpretacao": interp[0] if diff > 0 else interp[1]
        }
    return insights


def gerar_grafico(df, fn, vp, fp):
    feats = [f for f in FEATURES if f in df.columns]
    if not feats:
        print("[!] Features não encontradas, pulando gráfico.")
        return

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Análise de Falsos Negativos — Por que ataques escaparam da IA?',
                 fontsize=14, fontweight='bold')

    ax1 = axes[0,0]
    if 'tamanho_url' in feats:
        ax1.hist(vp['tamanho_url'].clip(0,500), bins=30, alpha=0.6, color='#2196F3', label='Detectados (VP)')
        ax1.hist(fn['tamanho_url'].clip(0,500), bins=30, alpha=0.6, color='#F44336', label='Escaparam (FN)')
        ax1.set_title('Distribuição: Tamanho da URL'); ax1.set_xlabel('Caracteres')
        ax1.legend(); ax1.grid(alpha=0.3)

    ax2 = axes[0,1]
    if 'freq_ip_total' in feats:
        ax2.hist(vp['freq_ip_total'].clip(0,200), bins=30, alpha=0.6, color='#2196F3', label='Detectados (VP)')
        ax2.hist(fn['freq_ip_total'].clip(0,200), bins=30, alpha=0.6, color='#F44336', label='Escaparam (FN)')
        ax2.set_title('Distribuição: Frequência por IP'); ax2.set_xlabel('Nº Requisições')
        ax2.legend(); ax2.grid(alpha=0.3)

    ax3 = axes[1,0]
    if 'status_code_num' in feats and not fn.empty:
        sc = fn['status_code_num'].value_counts().head(8)
        cores = ['#F44336' if s>=400 else '#FF9800' if s>=300 else '#4CAF50' for s in sc.index]
        ax3.bar(sc.index.astype(str), sc.values, color=cores)
        ax3.set_title('Status HTTP dos Ataques Não Detectados (FN)')
        ax3.set_xlabel('Status HTTP'); ax3.grid(axis='y', alpha=0.3)

    ax4 = axes[1,1]
    if 'taxa_erro_por_ip' in feats:
        grupos = ['VP\n(detectados)','FN\n(escaparam)','FP\n(falso alarme)']
        taxas  = [vp['taxa_erro_por_ip'].mean() if not vp.empty else 0,
                  fn['taxa_erro_por_ip'].mean() if not fn.empty else 0,
                  fp['taxa_erro_por_ip'].mean() if not fp.empty else 0]
        bars = ax4.bar(grupos, taxas, color=['#2196F3','#F44336','#FF9800'], edgecolor='white')
        ax4.set_title('Taxa Média de Erros HTTP por Grupo')
        ax4.set_ylabel('Taxa de Erros (média)'); ax4.grid(axis='y', alpha=0.3)
        for b, v in zip(bars, taxas):
            ax4.text(b.get_x()+b.get_width()/2, b.get_height()+.002,
                     f'{v:.3f}', ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.savefig(PNG_FALSOS_NEG, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] Gráfico → {PNG_FALSOS_NEG}")


RECOMENDACOES = [
    {"prioridade":"Alta",   "feature":"Entropia do payload",
     "justificativa":"Payloads de ataque têm aleatoriedade diferente de texto natural, mesmo curtos."},
    {"prioridade":"Alta",   "feature":"Intervalo médio entre requisições do mesmo IP",
     "justificativa":"Slow attacks têm intervalos regulares e mecânicos, diferente de humanos."},
    {"prioridade":"Média",  "feature":"Diversidade de endpoints por IP",
     "justificativa":"Scanners varrem múltiplos endpoints; usuários ficam em poucos caminhos."},
    {"prioridade":"Média",  "feature":"Proporção GET vs POST por IP",
     "justificativa":"Ataques de injeção concentram POSTs; varreduras concentram GETs."},
]


if __name__ == "__main__":
    garantir_pastas()
    df, fn, vp, fp = carregar()

    if fn.empty:
        print("[OK] Nenhum falso negativo encontrado.")
    else:
        insights = analisar(fn, vp)
        gerar_grafico(df, fn, vp, fp)
        resultado = {
            "total_fn": len(fn),
            "insights": insights,
            "recomendacoes": RECOMENDACOES
        }
        with open(JSON_INSIGHTS, 'w') as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)
        print(f"[OK] Insights → {JSON_INSIGHTS}")
        print("\n  Recomendações para trabalho futuro:")
        for r in RECOMENDACOES:
            print(f"  [{r['prioridade']}] {r['feature']}: {r['justificativa']}")