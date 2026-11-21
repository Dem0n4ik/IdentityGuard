FROM node:22-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
COPY api/ /src/api/
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.13.7 AS uv
FROM python:3.12-slim-bookworm AS runtime
WORKDIR /app
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project \
    && groupadd --gid 10001 identityguard \
    && useradd --uid 10001 --gid 10001 --no-create-home identityguard \
    && install -d -o 10001 -g 10001 /app/data
COPY backend/app ./backend/app
COPY --from=web /src/frontend/dist ./frontend/dist
ENV PATH="/app/.venv/bin:${PATH}" PYTHONPATH="/app/backend" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "--factory", "app.api:from_env", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
