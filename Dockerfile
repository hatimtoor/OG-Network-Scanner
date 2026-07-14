# NetScope container image.
# Note: to discover/scan the LAN, run with host networking (see docker-compose.yml);
# raw packet capture (scapy/PCAP) additionally needs --cap-add=NET_RAW/NET_ADMIN.
FROM python:3.12-slim

WORKDIR /app

# nmap for OS/service detection; iputils-ping for the ping sweep; libpcap for scapy.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap iputils-ping libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netscope ./netscope

ENV NETSCOPE_HOST=0.0.0.0 \
    NETSCOPE_OPEN_BROWSER=false \
    NETSCOPE_DB=/data/netscope.db \
    NETSCOPE_ANALYTICS_DB=/data/netscope-flows.duckdb

VOLUME ["/data"]
EXPOSE 8000

CMD ["python", "-m", "netscope"]
