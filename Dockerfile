FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY run.py ./run.py
RUN useradd -m -u 10001 appuser && mkdir /srv/data && chown -R appuser:appuser /srv/data
USER appuser
EXPOSE 8088
# Inside a container, expose to the host only via 127.0.0.1 port binding.
# The container must listen on all interfaces; compose publishes it on host 127.0.0.1 only.
ENV SIGNALHARBOR_HOST=0.0.0.0 SIGNALHARBOR_INSECURE_BIND_OK=1
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8088/api/health',timeout=2)"
CMD ["python","run.py"]
