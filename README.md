# 🛡️ Aegis — Arquitetura Híbrida para Detecção de Ameaças Web

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Containers-blue)](https://www.docker.com/)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blueviolet)](https://wazuh.com/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-ELK-green)](https://www.elastic.co/)
[![DOI](https://img.shields.io/badge/DOI-10.47820%2Frecima21.v7i8.8820-orange)](https://doi.org/10.47820/recima21.v7i8.8820)
[![License](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)](https://creativecommons.org/licenses/by/4.0/)

O **Aegis** é um projeto de Iniciação Científica desenvolvido no **Instituto Federal de São Paulo (IFSP) — Câmpus Jacareí**, voltado à detecção de ameaças e anomalias em aplicações web.

A arquitetura combina duas abordagens complementares:

- **Wazuh SIEM**, responsável pela detecção baseada em regras e assinaturas;
- **Isolation Forest**, utilizado para detecção não supervisionada de anomalias a partir de características comportamentais e volumétricas do tráfego.

O objetivo do projeto é investigar como a correlação entre mecanismos determinísticos e Machine Learning pode melhorar a capacidade de detecção e reduzir o volume de falsos positivos em cenários de segurança operacional.

---

## 📄 Publicação Científica

O desenvolvimento e a validação do Aegis resultaram no artigo:

> **Análise Preditiva de Vulnerabilidades em Aplicações Web Usando Logs de Servidor: Uma Arquitetura Híbrida**  
> **Andrey Rodrigues Moreira; Olavo Olimpio de Matos Junior**  
> *RECIMA21 — Revista Científica Multidisciplinar*, 2026.

- 📘 **DOI:** https://doi.org/10.47820/recima21.v7i8.8820
- 🌐 **Página do artigo:** https://recima21.com.br/recima21/pt_BR/article/view/8820
- 📄 **PDF oficial:** https://recima21.com.br/recima21/pt_BR/article/view/8820/5842
- 🎓 **Apresentação acadêmica:** ERMAC Regional 8 — INPE, São José dos Campos, 06/2026 — apresentação oral e pôster.

---

## 📊 Principais Resultados

A validação externa foi realizada sobre **170.366 requisições** do subconjunto *Thursday Web Attacks* do **CIC-IDS2017**.

| Modelo / Abordagem | Recall | Precisão | Acurácia | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Wazuh** | 84,63% | 35,13% | 97,80% | 49,65% |
| **Isolation Forest** | **91,97%** | 5,39% | 79,24% | 10,18% |
| **Arquitetura Híbrida Aegis** | 77,84% | **70,27%** | **99,30%** | **73,86%** |

Na validação externa, a camada híbrida reduziu os falsos positivos de **35.190 para 718** em comparação ao modelo de Machine Learning utilizado isoladamente, elevando a precisão para **70,27%** e o F1-Score para **73,86%**.

> Os resultados devem ser interpretados em conjunto: em datasets altamente desbalanceados, métricas como precisão, recall e F1-Score são especialmente relevantes para complementar a acurácia.

---

## 🏗️ Arquitetura

O pipeline do Aegis é dividido em três etapas principais:

1. **Preparação e coleta**  
   Ambiente conteinerizado com **Nginx**, **OWASP Juice Shop**, **Docker** e **Wazuh**, além da utilização do CIC-IDS2017 para validação externa.

2. **Processamento e Machine Learning**  
   Ingestão e transformação de logs com **Logstash** e **Elasticsearch**, engenharia de atributos com **Pandas** e detecção de anomalias com **Isolation Forest / Scikit-learn**.

3. **Correlação e visualização**  
   Correlação entre alertas do Wazuh e predições do modelo, com apoio de dashboards no **Grafana** para análise operacional dos resultados.

```text
Tráfego HTTP / CIC-IDS2017
          │
          ▼
      Nginx / Logs
          │
          ▼
       Logstash
          │
          ▼
    Elasticsearch
       │       │
       │       └──────────────► Wazuh SIEM
       │
       ▼
Feature Engineering
       │
       ▼
 Isolation Forest
       │
       └──────────────┐
                      ▼
               Correlação Aegis
                      │
                      ▼
                   Grafana
```

---

## 🧰 Tecnologias

**Segurança e observabilidade**  
Wazuh • Nginx • OWASP Juice Shop • Grafana

**Dados e Machine Learning**  
Python • Pandas • Scikit-learn • Isolation Forest

**Pipeline e infraestrutura**  
Docker • Docker Compose • Logstash • Elasticsearch

**Validação**  
CIC-IDS2017 • métricas de classificação • matrizes de confusão • análise de falsos positivos e falsos negativos

---

## 📂 Estrutura do Repositório

```text
Aegis-Projeto-IC/
├── IC_CyberSec/
│   ├── analise/
│   │   ├── analise_falso_negativo.py
│   │   └── comparador_wazuh_VS_Ia.py
│   ├── estudo_caso/
│   │   ├── comparador_estudo_caso.py
│   │   ├── disparador_logs_estudo_caso.py
│   │   └── validacao_estudo_caso.py
│   ├── grafana/
│   │   └── grafana_setup.py
│   ├── infra/
│   │   ├── docker-compose.yml
│   │   ├── logstash.conf
│   │   └── nginx.conf
│   ├── pipeline/
│   │   ├── detector_anomalias.py
│   │   ├── extrator_wazuh.py
│   │   ├── gerador_dataset.py
│   │   └── limpar_banco.py
│   ├── caminhos.py
│   └── requirements.txt
└── wazuh-docker/
```

---

## ⚙️ Pré-requisitos

- **Docker** 20.10 ou superior
- **Docker Compose** 2.0 ou superior
- **Python** 3.10 ou superior
- Recomendado: pelo menos **8 GB de RAM** disponíveis para o Docker Engine devido ao uso conjunto da stack ELK e do Wazuh.

---

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/AndreyRodr/Aegis-Projeto-IC.git
cd Aegis-Projeto-IC/IC_CyberSec
```

### 2. Configure o ambiente Python

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
.\venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Inicie a infraestrutura

```bash
cd infra
docker compose up -d
```

A infraestrutura reúne os serviços utilizados no laboratório, incluindo Nginx, OWASP Juice Shop, Elasticsearch, Logstash, Grafana e os componentes do Wazuh.

---

## 🔄 Fluxo de Execução

### Ambiente laboratorial

A partir da pasta `IC_CyberSec`:

```bash
python pipeline/gerador_dataset.py
python pipeline/detector_anomalias.py
python pipeline/extrator_wazuh.py
python analise/comparador_wazuh_VS_Ia.py
```

### Validação externa — CIC-IDS2017

```bash
python estudo_caso/disparador_logs_estudo_caso.py
python estudo_caso/validacao_estudo_caso.py
python estudo_caso/comparador_estudo_caso.py
```

---

## 👥 Autores

**Andrey Rodrigues Moreira**  
Graduando em Análise e Desenvolvimento de Sistemas — IFSP Câmpus Jacareí  
Desenvolvedor e pesquisador do Projeto Aegis

**Prof. Olavo Olimpio de Matos Junior**  
Docente — IFSP Câmpus Jacareí  
Orientador da Iniciação Científica

---

## 🎓 Vínculo Institucional

Projeto desenvolvido no âmbito do programa de **Iniciação Científica do Instituto Federal de São Paulo (IFSP) — Câmpus Jacareí**.

O artigo científico associado ao projeto foi publicado na **RECIMA21 — Revista Científica Multidisciplinar** e está disponível pelos links indicados no início deste README.

---

## 📜 Licença

O texto da publicação segue as condições indicadas pela revista. O código-fonte e a infraestrutura deste repositório são disponibilizados para fins acadêmicos, educacionais e de reprodutibilidade científica.
