# 🛡️ Aegis — Arquitetura Híbrida para Análise Preditiva de Vulnerabilidades Web

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Containers-blue)](https://www.docker.com/)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blueviolet)](https://wazuh.com/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-ELK-green)](https://www.elastic.co/)
[![License](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)](https://creativecommons.org/licenses/by/4.0/)

O **Aegis** é um ecossistema defensivo cibernético desenvolvido como projeto de Iniciação Científica no **Instituto Federal de São Paulo (IFSP) – Câmpus Jacareí**. A solução integra a análise determinística por assinaturas do SIEM open-source **Wazuh** com a capacidade preditiva não supervisionada do algoritmo **Isolation Forest** (Machine Learning), processando logs HTTP e tráfego de aplicação em tempo real para mitigar simultaneamente **pontos cegos (Zero-Days)** e a **fadiga de alertas** em Centros de Operações de Segurança (SOC).

---

## 📌 Sumário

- [Visão Geral e Arquitetura](#-visão-geral-e-arquitetura)
- [Estrutura do Repositório](#-estrutura-do-repositório)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação e Configuração](#-instalação-e-configuração)
- [Fluxo de Execução](#-fluxo-de-execução)
- [Resultados do Benchmark](#-resultados-do-benchmark)
- [Autores](#-autores)

---

## 🏗️ Visão Geral e Arquitetura

O pipeline do ecossistema é dividido em 3 fases principais:

1. **Preparação e Coleta:** Proxy reverso Nginx gerando logs de tráfego (legítimo e malicioso) direcionados à aplicação *OWASP Juice Shop* em contêineres Docker, além da ingestão do benchmark internacional **CIC-IDS2017**.
2. **Processamento e IA (ETL):** Ingestão via Stack ELK (*Logstash* e *Elasticsearch*), engenharia de recursos comportamentais/volumétricos via *Pandas* e detecção geométrica de anomalias com *Isolation Forest* (Scikit-Learn).
3. **Visualização Operacional:** Dashboards em tempo real no *Grafana* para correlação entre alertas estáticos do Wazuh e anomalias preditas pela IA.

---

## 📂 Estrutura do Repositório

```text
Aegis-Projeto-IC/
├── IC_CyberSec/
│   ├── analise/                             # Scripts de análise comparativa (Ambiente Laboratorial)
│   │   ├── analise_falso_negativo.py        # Diagnóstico de evasões e falhas de cobertura
│   │   └── comparador_wazuh_VS_Ia.py        # Validação cruzada SIEM vs. Isolation Forest
│   ├── estudo_caso/                         # Scripts para validação externa no CIC-IDS2017
│   │   ├── comparador_estudo_caso.py        # Métricas agregadas no benchmark (Recall, Precisão, F1)
│   │   ├── disparador_logs_estudo_caso.py   # Replay de logs do CIC-IDS2017 via socket UDP
│   │   └── validacao_estudo_caso.py         # Testes e matrizes de confusão do estudo de caso
│   ├── grafana/
│   │   └── grafana_setup.py                 # Automação de criação de dashboards e datasources
│   ├── infra/                               # Configurações de infraestrutura conteinerizada
│   │   ├── docker-compose.yml               # Orquestração do Nginx, Juice Shop, ELK e Wazuh
│   │   ├── logstash.conf                    # Pipelines Grok/ETL para fatiamento de logs HTTP
│   │   └── nginx.conf                       # Configuração de proxy reverso e logging estendido
│   ├── pipeline/                            # Pipeline preditivo e geradores
│   │   ├── detector_anomalias.py            # Treinamento e inferência assíncrona com Isolation Forest
│   │   ├── extrator_wazuh.py                # Integração e extração de alertas via API do Wazuh
│   │   ├── gerador_dataset.py               # Automação de testes de estresse e injeção de ataques
│   │   └── limpar_banco.py                  # Manutenção e purge dos índices do Elasticsearch
│   ├── caminhos.py                          # Definições globais de rotas e diretórios do projeto
│   └── requirements.txt                     # Dependências Python do projeto
└── wazuh-docker/                            # Cluster/Agentes Docker dedicados do Wazuh
```

---

## ⚙️ Pré-requisitos

Antes de iniciar, garanta que possui instalado no seu ambiente:

- **Docker** (v20.10+) e **Docker Compose** (v2.0+)
- **Python** 3.10 ou superior
- Recomendado: Mínimo de **8 GB de RAM** alocados para o Docker Engine (devido à stack ELK + Wazuh).

---

## 🚀 Instalação e Configuração

### 1. Clonar o Repositório
```bash
git clone [https://github.com/AndreyRodr/Aegis-Projeto-IC.git](https://github.com/AndreyRodr/Aegis-Projeto-IC.git)
cd Aegis-Projeto-IC/IC_CyberSec
```

### 2. Configurar o Ambiente Virtual Python
```
Bash
python -m venv venv
# No Linux/macOS:
source venv/bin/activate
# No Windows:
.\venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Subir a Infraestrutura de Contêineres

Navegue até a pasta de infraestrutura e inicie os serviços:
```Bash

cd infra
docker-compose up -d
```
> **Destaque:** Os serviços Nginx (Proxy), OWASP Juice Shop, Elasticsearch, Logstash, Grafana e Wazuh estarão operacionais.  

## 🔄 Fluxo de Execução
### A) Teste de Estresse Laboratorial (Nginx + Juice Shop)Gerar tráfego e simular ataques em tempo real:
```Bash
python pipeline/gerador_dataset.py
```

### 1. Executar a IA para detecção não supervisionada de anomalias:
```Bash
python pipeline/detector_anomalias.py
```

### 2. Extrair alertas correlacionados do Wazuh:
```Bash
python pipeline/extrator_wazuh.py
```

### 3. Gerar comparativo e Matriz de Confusão do ambiente laboratorial:
```Bash
python analise/comparador_wazuh_VS_Ia.py
```

### B) Validação Externa no Benchmark CIC-IDS2017
### 1. Transmitir logs do dataset para o Logstash via UDP:

```bash
python estudo_caso/disparador_logs_estudo_caso.py
```

### 2. Executar a validação e calcular métricas de desempenho:

```Bash
python estudo_caso/validacao_estudo_caso.py
python estudo_caso/comparador_estudo_caso.py
```

## 📊 Resultados do Benchmark

A tabela abaixo sintetiza o desempenho comparativo obtido durante os testes de validação no benchmark internacional **CIC-IDS2017 (Thursday Web Attacks)**:

| Modelo / Abordagem | Recall | Precisão | Acurácia | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **SIEM Wazuh (Regras Estáticas)** | 84,63% | 35,13% | 97,80% | 49,65% |
| **Isolation Forest (IA Pura)** | **91,97%** | 5,39% | 79,24% | 10,18% |
| **Arquitetura Híbrida Aegis (Sinergia)** | 77,84% | **70,27%** | **99,30%** | **73,86%** |

> **Destaque:** A validação cruzada do ecossistema Aegis reduziu o volume de Falsos Positivos de **35.190 para apenas 718 requisições**, resolvendo o gargalo da **fadiga de alertas** em SOCs e elevando a precisão geral para **70,27%**.

---

## 👥 Autores

- **Andrey Rodrigues Moreira** — *Desenvolvedor e Pesquisador Principal*  
  Graduando em Análise e Desenvolvimento de Sistemas — IFSP Câmpus Jacareí
- **Prof. Olavo Olimpio de Matos Junior** — *Orientador do Projeto*  
  Docente — IFSP Câmpus Jacareí

---

### 📄 Licença e Vínculo Institucional

Este projeto foi desenvolvido no âmbito do programa de **Iniciação Científica (IC)** do **Instituto Federal de São Paulo (IFSP) – Câmpus Jacareí** (Núcleo de Sistemas).

- **Texto e Artigo Científico:** Licenciados sob [Creative Commons Attribution 4.0 International (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/) conforme publicação na revista *RECIMA21*.
- **Código-Fonte e Infraestrutura:** Disponibilizados em caráter acadêmico e de código aberto para fins de reprodutibilidade científica.
