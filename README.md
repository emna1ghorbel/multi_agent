# 🛡️ Multi-Agent Cyber Threat Intelligence (CTI)

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Orchestration-orange.svg)](https://github.com/langchain-ai/langgraph)

A modular, production-ready Multi-Agent system for Cyber Threat Intelligence analysis, leveraging **LangGraph**, **RAG (Retrieval-Augmented Generation)**, and the **MITRE ATT&CK** framework.

---

## 📂 Project Structure

The project is organized into a modular architecture to ensure scalability and maintainability.

### 🚀 [agent-cti/](file:///c:/Users/dell/multi_agent/agent-cti/) (Core Project)
The main modularized codebase converted from the initial research notebook.
- **`core/`**: Configuration management and LLM helper utilities.
- **`tools/`**: Atomic analytical tools (Entity extraction, RAG search, Pattern/Behavior detection).
- **`agents/`**: AI agents orchestrating analysis, MITRE mapping, and web intelligence.
- **`mitre/`**: Engines for ATT&CK mapping, severity calculation, and mitigation recommendations.
- **`pipeline/`**: LangGraph orchestration and report aggregation logic.
- **`api/`**: FastAPI backend with integrated authentication and Pydantic schemas.
- **`reporting/`**: Visual dashboards, automated PDF reports, and notification systems.

### 🧪 Additional Components
- **`cti-agent.ipynb`**: Original research notebook for exploration and prototyping.
- **`Data_Processing/`**: Scripts for data cleaning, preparation, and FAISS indexing.
- **`src/`**: Legacy source modules and shared utilities.

---

## 🛠️ Installation & Setup

### 1. Environment Preparation
Ensure you have Python 3.11 or higher installed. Create and activate a virtual environment:

```bash
# Create environment
python -m venv .venv

# Activate (Windows)
.\.venv\Scripts\activate

# Activate (Unix/macOS)
source .venv/bin/activate
```

### 2. Dependency Installation
Install all required packages for the core system:

```bash
pip install -r agent-cti/requirements.txt
```

### 3. Configuration
Copy the environment template and fill in your API keys (Groq, LangChain, Google, etc.):

```bash
cp .env.example .env
```

---

## 🚀 Usage

### Running the API Backend
To start the FastAPI server and expose the CTI endpoints:

```bash
cd agent-cti
python -m api.main
```

### Analytical Capabilities
The system processes raw CTI messages through a 5-step pipeline:
1. **Web Search**: Collects latest intelligence from RSS, Reddit, and OTX.
2. **Analysis**: Extracts IOCs and detects malicious behaviors using LLM + RAG.
3. **MITRE Mapping**: Maps behaviors to the MITRE ATT&CK matrix.
4. **Aggregation**: Consolidates results into a unified threat landscape.
5. **Reporting**: Generates a professional PDF report and visual dashboard.

---

## 📝 License
This project was developed as part of the **ENIS PFA 2025-2026**.
