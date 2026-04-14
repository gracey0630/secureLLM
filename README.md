# LLM Security Evaluation Pipeline

Multi-layer security evaluation framework for LLM-integrated applications.

## Team
- **Person A** — Evaluation Harness & Datasets
- **Person B** — Input Scanner & Policy Engine
- **Person C** — Output Guard & Demo Interface

---

## One-Command Setup

```bash
# 1. Clone and enter repo
git clone <repo-url> && cd llm-security-eval

# 2. Create virtual environment
python3.11 -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# 4. Load all datasets
python load_datasets.py

# 5. Run tests
pytest tests/
```

---

## Dataset Access

| Dataset | Access | Command |
|---------|--------|---------|
| hackaprompt/hackaprompt-dataset | Public | auto |
| deepset/prompt-injections | Public | auto |
| lmsys/lmsys-chat-1m | **Gated** — request at huggingface.co/datasets/lmsys/lmsys-chat-1m | set `HF_TOKEN` |
| ai4privacy/pii-masking-200k | Public | auto |

---

## Repository Structure

```
llm-security-eval/
├── data/                  # parquet files (gitignored, regenerate with load_datasets.py)
├── logs/                  # pipeline.jsonl event log (gitignored)
├── results/               # evaluation outputs (gitignored)
├── pipeline/              # FastAPI app (Week 2+)
├── tests/                 # pytest suite
├── load_datasets.py       # Action 2 — dataset loading
├── logging_schema.py      # Shared logging used by all layers
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## Reproducing Results

```bash
# Load datasets
python load_datasets.py

# Run evaluation harness (Week 2+)
python -m pipeline.evaluate --config configs/full_pipeline.yaml
```
