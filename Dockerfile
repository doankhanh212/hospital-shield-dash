# ── Stage 1: Build React frontend ──────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /build

# Install dependencies first (layer caching)
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Copy source and build
COPY index.html vite.config.ts tsconfig*.json tailwind.config.ts postcss.config.js components.json ./
COPY public/ public/
COPY src/ src/
RUN npm run build


# ── Stage 2: Python API + static frontend ─────────────────────────────────
FROM python:3.12-slim AS production

# Prevent Python from writing .pyc and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY passive_asset_intel/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend application
COPY passive_asset_intel/ ./passive_asset_intel/

# Copy the built frontend into a static directory served by Nginx
COPY --from=frontend-build /build/dist ./static/

# Copy the database schema
COPY passive_asset_intel/schema.sql ./schema.sql

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

CMD ["uvicorn", "passive_asset_intel.api.main:app", "--host", "0.0.0.0", "--port", "3001", "--workers", "1"]
