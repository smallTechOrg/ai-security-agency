# ---- Stage 1: build frontend ----
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
# Same-origin deploy: API served from the same host, so use relative paths.
ENV VITE_API_BASE_URL=""
RUN npm run build

# ---- Stage 2: backend + static ----
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    PORT=8080 \
    FRONTEND_DIST=/app/frontend/dist

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY --from=frontend /fe/dist ./frontend/dist
RUN mkdir -p /app/data

# Cloud Run provides $PORT; serve API + SPA from one process.
CMD ["sh", "-c", "uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port ${PORT:-8080}"]
