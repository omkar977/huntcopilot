# ml: build from the repository root, for example:
#   docker build -f deploy/docker/Dockerfile.ml -t huntcopilot/ml:dev .
# The start command on the last line is the only service-specific line besides the port.
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HC_SERVICE=ml
RUN useradd --create-home --uid 10001 hc && mkdir -p /data && chown hc:hc /data
WORKDIR /app
COPY common/ /app/common/
COPY libs/ /app/libs/
COPY services/ml/ /app/services/ml/
RUN pip install --no-cache-dir -r /app/services/ml/requirements.txt
ENV PYTHONPATH=/app/common:/app/libs:/app/services/ml
USER hc
EXPOSE 8100
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request as u; u.urlopen('http://localhost:8100/health', timeout=2)"
CMD ["sh", "-c", "exec python -m uvicorn ml_main:app --host 0.0.0.0 --port 8100"]
