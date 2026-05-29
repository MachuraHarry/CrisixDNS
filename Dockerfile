FROM python:3.11-slim

WORKDIR /app

# System-Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python-Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Server-Code
COPY dns_server.py .

# Ports
EXPOSE 8053/udp
EXPOSE 8080/tcp


# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Start
CMD ["python3", "dns_server.py"]
