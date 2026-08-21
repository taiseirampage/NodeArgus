FROM python:3.11-slim

ARG NUCLEI_VERSION=3.4.10
ARG SUBFINDER_VERSION=2.15.0
ARG TARGETARCH=amd64

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/root

WORKDIR /app

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        masscan \
        nmap \
        unzip; \
    case "${TARGETARCH}" in \
        amd64) nuclei_arch="amd64" ;; \
        arm64) nuclei_arch="arm64" ;; \
        *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip" \
        --output /tmp/nuclei.zip; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip; \
    case "${TARGETARCH}" in \
        amd64) subfinder_arch="amd64" ;; \
        arm64) subfinder_arch="arm64" ;; \
        *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${subfinder_arch}.zip" \
        --output /tmp/subfinder.zip; \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder; \
    install -m 0755 /tmp/subfinder/subfinder /usr/local/bin/subfinder; \
    rm -rf /tmp/subfinder /tmp/subfinder.zip; \
    mkdir -p /root/.config/subfinder; \
    printf '%s\n' \
        'sources:' \
        '  - crtsh' \
        '  - hackertarget' \
        '  - alienvault' \
        '  - commoncrawl' \
        '  - waybackarchive' > /root/.config/subfinder/provider-config.yaml; \
    rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates -silent -td /root/nuclei-templates

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
