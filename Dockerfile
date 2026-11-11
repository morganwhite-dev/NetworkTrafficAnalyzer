# Network Traffic Analyzer
#
# On macOS, Docker Desktop runs containers inside a Linux VM, so a container
# can't see your Mac's en0. Use this image for .pcap analysis and the demo
# replay; for live capture on a Mac, run the app natively (see README).
# On a Linux host, the "linux-capture" compose profile captures the host's
# interfaces with only the NET_RAW capability.

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/backend \
    NTA_HOST=0.0.0.0 \
    NTA_ALLOW_REMOTE=1 \
    NTA_DATA_DIR=/tmp/nta \
    NTA_GEO_DB=/app/data/dbip-city-lite.mmdb

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin nta

WORKDIR /app
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY samples ./samples
RUN mkdir -p /app/data && chown nta:nta /app/data

USER nta
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/favicon.svg', timeout=2)"

# Default: the bundled demo. Open the URL printed in `docker compose logs`.
CMD ["python", "-m", "app", "--replay", "samples/demo.pcap", "--loop"]
