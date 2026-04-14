FROM python:3.11-slim

WORKDIR /app

# System deps for spacy / presidio
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_lg

COPY . .

# Default: run the FastAPI pipeline server
CMD ["uvicorn", "pipeline.main:app", "--host", "0.0.0.0", "--port", "8000"]
