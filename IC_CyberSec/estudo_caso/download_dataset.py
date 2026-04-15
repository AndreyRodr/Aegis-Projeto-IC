import warnings
import pandas as pd
import os

warnings.filterwarnings('ignore')

print("\n" + "="*50)
print("📥 DOWNLOAD E LIMPEZA DO DATASET CIENTÍFICO (CSIC 2010)")
print("="*50)

try:
    import kagglehub
except ImportError:
    print("[!] A biblioteca 'kagglehub' não está instalada.")
    exit()

def baixar_e_limpar_dataset():
    print("[*] Conectando ao Kaggle e baixando a pasta do dataset...")
    caminho_pasta = kagglehub.dataset_download("evg3n1j/httpparamsdataset")
    
    # Vamos usar o arquivo FULL, que contém todos os mais de 31.000 registros juntos!
    caminho_arquivo_full = os.path.join(caminho_pasta, "payload_full.csv")
    
    print(f"[*] Lendo o arquivo CSV completo (Benignos + Ataques)...")
    
    try:
        df_bruto = pd.read_csv(
            caminho_arquivo_full, 
            encoding='latin-1', 
            on_bad_lines='skip', 
            engine='python'
        )
    except Exception as e:
        print(f"[!] Erro ao ler o arquivo: {e}")
        return
        
    qtd_linhas = len(df_bruto)
    
    # A Correção do Gabarito: Lendo a palavra 'anom' em vez do número 1
    qtd_ataques = len(df_bruto[df_bruto['label'].astype(str).str.lower() == 'anom'])
    
    print(f"[✔] Dataset lido com sucesso! Total: {qtd_linhas} requisições.")
    print(f"[🔍] Foram encontrados {qtd_ataques} ataques reais no gabarito.")
    
    nome_arquivo_limpo = "dataset_csic2010_limpo.csv"
    print(f"[*] Salvando o dataset MISTURADO localmente...")
    
    df_bruto.to_csv(nome_arquivo_limpo, index=False)
    
    print(f"[🚀] Processo concluído! O arquivo está pronto para a validação real.\n")

if __name__ == "__main__":
    baixar_e_limpar_dataset()