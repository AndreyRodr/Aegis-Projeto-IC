"""
comparador_wazuh_VS_Ia.py — Análise comparativa de 4 quadrantes
CORREÇÃO: cruzamento por user_agent (não IP, pois todo tráfego
          Docker usa o mesmo IP gateway 172.18.0.1).

Entradas: dados/resultados_ia_ambiente_controlado.csv
          dados/alertas_wazuh.csv
Saídas:   graficos/grafico_4_quadrantes.png
          graficos/grafico_venn.png
          relatorios/relatorio_comparativo.json
"""
import sys, json, warnings
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

sys.path.insert(0, str(Path(__file__).parent.parent))
from caminhos import (garantir_pastas, CSV_IA, CSV_WAZUH,
                      PNG_4_QUAD, PNG_VENN, JSON_COMPARATIVO)

warnings.filterwarnings('ignore')

# Ferramentas de ataque — usadas para identificar registros no Wazuh e na IA
FERRAMENTAS = ['nmap', 'sqlmap', 'burp', 'nikto', 'masscan',
               'python-requests/2.28', 'zgrab', 'nuclei']


def carregar():
    print("[*] Carregando dados...")
    for arq in [CSV_IA, CSV_WAZUH]:
        if not arq.exists():
            print(f"[✘] Não encontrado: {arq}")
            exit(1)
    df_ia    = pd.read_csv(CSV_IA)
    df_wazuh = pd.read_csv(CSV_WAZUH)
    print(f"[OK] IA: {len(df_ia)} registros | Wazuh: {len(df_wazuh)} alertas")
    return df_ia, df_wazuh


def _extrair_ferramenta(ua: str) -> str:
    """Retorna o nome da ferramenta detectada no user_agent, ou '' se normal."""
    ua = str(ua).lower()
    for f in FERRAMENTAS:
        if f in ua:
            return f
    return ''


def calcular_quadrantes(df_ia, df_wazuh):
    """
    Estratégia de cruzamento por user_agent.

    Como todo tráfego Docker vem do mesmo IP (172.18.0.1), usamos o
    user_agent como identificador do tipo de tráfego.

    - "detectado pelo Wazuh"  = user_agent aparece em algum alerta do Wazuh
    - "detectado pela IA"     = linha classificada como Anomalia pelo modelo
    - "ataque real (GT)"      = label_real == 'Anomalia'

    O cruzamento é feito registro a registro (não por IP único),
    o que reflete a realidade do ambiente controlado.
    """
    print("[*] Calculando quadrantes (cruzamento por user_agent)...")

    # UAs que o Wazuh reportou como suspeitos
    uas_wazuh_alertadas = set()
    for desc in df_wazuh['descricao_regra'].dropna():
        desc_lower = desc.lower()
        for f in FERRAMENTAS:
            if f in desc_lower:
                uas_wazuh_alertadas.add(f)

    # Se o Wazuh não menciona ferramentas por nome na descrição,
    # considera que ele detectou tudo com erros 400 (comportamento observado)
    wazuh_detectou_erros_400 = any('400' in str(d) for d in df_wazuh['descricao_regra'])
    wazuh_nivel_medio = (df_wazuh['nivel_wazuh'] >= 7).any()

    # Classifica cada linha do CSV da IA
    resultados = []
    for _, row in df_ia.iterrows():
        ua        = str(row.get('user_agent', '')).lower()
        ferramenta = _extrair_ferramenta(ua)
        e_ataque  = row['label_real'] == 'Anomalia'
        ia_achou  = row['classificacao_ia'] == 'Anomalia'

        # Wazuh detectou? — se a requisição gerou erro 400/401 E o Wazuh tem alertas de 400
        status    = int(row.get('status_code_num', 200))
        wazuh_achou = (
            (ferramenta and ferramenta in uas_wazuh_alertadas) or
            (wazuh_detectou_erros_400 and status >= 400) or
            (wazuh_nivel_medio and ferramenta != '')
        )

        resultados.append({
            'e_ataque': e_ataque, 'ia_achou': ia_achou, 'wazuh_achou': wazuh_achou,
            'user_agent': ua[:60], 'ferramenta': ferramenta, 'status': status
        })

    df_r = pd.DataFrame(resultados)
    ataques = df_r[df_r['e_ataque']]
    total   = len(ataques)

    if total == 0:
        print("[!] Nenhum ataque no ground truth. Verifique o detector.")
        exit(1)

    q1 = len(ataques[ataques['ia_achou']  & ataques['wazuh_achou']])
    q2 = len(ataques[~ataques['ia_achou'] & ataques['wazuh_achou']])
    q3 = len(ataques[ataques['ia_achou']  & ~ataques['wazuh_achou']])
    q4 = len(ataques[~ataques['ia_achou'] & ~ataques['wazuh_achou']])

    fp_ia    = len(df_r[~df_r['e_ataque'] & df_r['ia_achou']])
    fp_wazuh = len(df_r[~df_r['e_ataque'] & df_r['wazuh_achou']])

    cob_wazuh   = (q1 + q2) / total
    cob_ia      = (q1 + q3) / total
    cob_hibrida = (q1 + q2 + q3) / total
    ganho       = cob_hibrida - max(cob_wazuh, cob_ia)

    print(f"\n  Total ataques (GT):     {total} requisições")
    print(f"  Q1 — Ambos detectaram:  {q1:4d} ({q1/total*100:.1f}%)")
    print(f"  Q2 — Só Wazuh:          {q2:4d} ({q2/total*100:.1f}%)")
    print(f"  Q3 — Só IA:             {q3:4d} ({q3/total*100:.1f}%)")
    print(f"  Q4 — Nenhum detectou:   {q4:4d} ({q4/total*100:.1f}%)")
    print(f"\n  Cobertura Wazuh:        {cob_wazuh*100:.1f}%")
    print(f"  Cobertura IA:           {cob_ia*100:.1f}%")
    print(f"  Cobertura Híbrida:      {cob_hibrida*100:.1f}%  (+{ganho*100:.1f}pp)")
    print(f"\n  Falsos positivos IA:    {fp_ia}")
    print(f"  Falsos positivos Wazuh: {fp_wazuh}")

    # Quais ferramentas cada sistema viu
    if q3 > 0:
        print(f"\n  Ataques no ponto cego do Wazuh (só IA detectou):")
        fn_ia = ataques[ataques['ia_achou'] & ~ataques['wazuh_achou']]
        for f, n in fn_ia['ferramenta'].value_counts().head(5).items():
            print(f"    [{n:4d}x] {f or '(sem ferramenta identificada)'}")
    if q2 > 0:
        print(f"\n  Ataques no ponto cego da IA (só Wazuh detectou):")
        fn_wazuh = ataques[~ataques['ia_achou'] & ataques['wazuh_achou']]
        for f, n in fn_wazuh['ferramenta'].value_counts().head(5).items():
            print(f"    [{n:4d}x] {f or '(sem ferramenta identificada)'}")

    relatorio = {
        "data_analise": datetime.now().isoformat(),
        "metodologia": "Cruzamento por user_agent (ambiente Docker usa IP único 172.18.0.1)",
        "totais": {"ataques_gt": total, "alertas_wazuh": len(df_wazuh)},
        "quadrantes": {
            "Q1_ambos":    {"count": q1, "pct": round(q1/total*100, 1)},
            "Q2_so_wazuh": {"count": q2, "pct": round(q2/total*100, 1)},
            "Q3_so_ia":    {"count": q3, "pct": round(q3/total*100, 1)},
            "Q4_nenhum":   {"count": q4, "pct": round(q4/total*100, 1)},
        },
        "performance": {
            "cobertura_wazuh":   round(cob_wazuh, 4),
            "cobertura_ia":      round(cob_ia, 4),
            "cobertura_hibrida": round(cob_hibrida, 4),
            "ganho_pp":          round(ganho * 100, 2),
            "fp_ia": fp_ia, "fp_wazuh": fp_wazuh,
        },
        "conclusao": (
            f"Arquitetura híbrida cobre {cob_hibrida*100:.1f}% dos ataques. "
            f"A IA capturou {q3} requisições no ponto cego do Wazuh (Q3); "
            f"o Wazuh capturou {q2} no ponto cego da IA (Q2). "
            f"Ganho de {ganho*100:.1f}pp vs. melhor sistema isolado."
        )
    }
    with open(JSON_COMPARATIVO, 'w') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Relatório → {JSON_COMPARATIVO}")
    return relatorio


def grafico_barras(rel):
    q      = rel['quadrantes']
    labels = ['Q1\nAmbos', 'Q2\nSó Wazuh', 'Q3\nSó IA', 'Q4\nNenhum']
    vals   = [q['Q1_ambos']['count'], q['Q2_so_wazuh']['count'],
              q['Q3_so_ia']['count'], q['Q4_nenhum']['count']]
    pcts   = [q['Q1_ambos']['pct'],   q['Q2_so_wazuh']['pct'],
              q['Q3_so_ia']['pct'],   q['Q4_nenhum']['pct']]
    cores  = ['#2196F3', '#4CAF50', '#FF9800', '#F44336']

    p     = rel['performance']
    sis   = ['Wazuh\nIsolado', 'IA\nIsolada', 'Arquitetura\nHíbrida']
    covs  = [p['cobertura_wazuh']*100, p['cobertura_ia']*100, p['cobertura_hibrida']*100]
    cores2 = ['#4CAF50', '#FF9800', '#2196F3']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    bars = ax1.bar(labels, vals, color=cores, edgecolor='white', linewidth=1.5)
    ax1.set_title('Análise de Cobertura — 4 Quadrantes\n(Requisições de Ataque)', fontsize=13)
    ax1.set_ylabel('Nº de Requisições Atacantes')
    for b, v, pct in zip(bars, vals, pcts):
        ax1.text(b.get_x()+b.get_width()/2, b.get_height()+.5,
                 f'{v}\n({pct}%)', ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    ax1.set_ylim(0, max(vals)*1.25 if vals else 10)

    bars2 = ax2.bar(sis, covs, color=cores2, edgecolor='white', linewidth=1.5)
    ax2.set_title('Cobertura por Sistema (%)', fontsize=13)
    ax2.set_ylabel('Taxa de Cobertura (%)')
    ax2.set_ylim(0, 110)
    ax2.axhline(100, color='red', linestyle='--', alpha=0.4, label='100%')
    for b, v in zip(bars2, covs):
        ax2.text(b.get_x()+b.get_width()/2, b.get_height()+1,
                 f'{v:.1f}%', ha='center', va='bottom', fontsize=12, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    ax2.legend()

    plt.suptitle('Comparação: Wazuh vs. Isolation Forest\nProjeto IC — Análise Preditiva de Vulnerabilidades',
                 fontsize=13, fontweight='bold')
    plt.tight_layout()
    plt.savefig(PNG_4_QUAD, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] Gráfico 4 quadrantes → {PNG_4_QUAD}")


def grafico_venn(rel):
    q     = rel['quadrantes']
    total = rel['totais']['ataques_gt']
    q1    = q['Q1_ambos']['count']
    q2    = q['Q2_so_wazuh']['count']
    q3    = q['Q3_so_ia']['count']
    q4    = q['Q4_nenhum']['count']

    fig, ax = plt.subplots(figsize=(10, 7))
    ax.set_xlim(0, 10); ax.set_ylim(0, 8); ax.axis('off')

    ax.add_patch(plt.Circle((3.8, 4), 2.5, color='#4CAF50', alpha=0.35))
    ax.add_patch(plt.Circle((6.2, 4), 2.5, color='#FF9800', alpha=0.35))

    ax.text(2.5, 4, f'Só Wazuh\n{q2} req.\n({q2/max(total,1)*100:.0f}%)',
            ha='center', va='center', fontsize=11, fontweight='bold', color='#1B5E20')
    ax.text(5.0, 4, f'Ambos\n{q1} req.\n({q1/max(total,1)*100:.0f}%)',
            ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(7.5, 4, f'Só IA\n{q3} req.\n({q3/max(total,1)*100:.0f}%)',
            ha='center', va='center', fontsize=11, fontweight='bold', color='#E65100')

    if q4 > 0:
        ax.text(5.0, 1, f'Nenhum detectou: {q4} req. ({q4/max(total,1)*100:.0f}%)',
                ha='center', va='center', fontsize=11, color='#C62828', fontweight='bold',
                bbox=dict(boxstyle='round', facecolor='#FFEBEE', edgecolor='#F44336'))

    ax.legend(handles=[
        mpatches.Patch(color='#4CAF50', alpha=0.6,
                       label=f'Wazuh  ({(q1+q2)/max(total,1)*100:.0f}% cobertura)'),
        mpatches.Patch(color='#FF9800', alpha=0.6,
                       label=f'IA     ({(q1+q3)/max(total,1)*100:.0f}% cobertura)'),
    ], loc='upper right', fontsize=11)

    ax.set_title(
        f'Diagrama de Venn — Cobertura de Detecção\n'
        f'Híbrido: {(q1+q2+q3)/max(total,1)*100:.0f}% | '
        f'Total requisições atacantes: {total}',
        fontsize=13, fontweight='bold')

    plt.tight_layout()
    plt.savefig(PNG_VENN, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] Venn → {PNG_VENN}")


if __name__ == "__main__":
    garantir_pastas()
    df_ia, df_wazuh = carregar()
    rel = calcular_quadrantes(df_ia, df_wazuh)
    grafico_barras(rel)
    grafico_venn(rel)
    print(f"\n[OK] {rel['conclusao']}")