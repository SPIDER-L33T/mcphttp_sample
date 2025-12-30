FROM python:3.11-slim

RUN groupadd -r mcpgroup && useradd -r -g mcpgroup mcpuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /tmp/logs && chown -R mcpuser:mcpgroup /tmp/logs

RUN chown -R mcpuser:mcpgroup /app

USER mcpuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8000 \
    HOST=0.0.0.0 \
    ENV=production

EXPOSE 8000

CMD ["python", "main.py"]
