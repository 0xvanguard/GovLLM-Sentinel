FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt fastapi uvicorn

# App code
COPY 02-FRAMEWORK/ ./02-FRAMEWORK/
COPY 04-DASHBOARD/ ./04-DASHBOARD/
COPY server.js .
COPY config/ ./config/

WORKDIR /app/02-FRAMEWORK

EXPOSE 8000 3000

# Start both: FastAPI + Dashboard server
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 & node /app/server.js"]
