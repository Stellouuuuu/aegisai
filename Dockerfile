# AegisAI API (FastAPI) with the engine. The dashboard and the labs have their own images.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY engine ./engine
COPY backend ./backend
RUN pip install --no-cache-dir ".[api,pdf]" && useradd --create-home aegis && mkdir /data && chown aegis /data
USER aegis
ENV AEGIS_DB=/data/aegis.db
EXPOSE 8000
CMD ["uvicorn", "backend.app:default_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
