FROM python:3.11-slim

ARG NUCLEI_VERSION=3.4.10
ARG SUBFINDER_VERSION=2.15.0
ARG AMASS_VERSION=4.2.0
ARG HTTTPX_VERSION=1.10.0
ARG KATANA_VERSION=1.7.0
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
    case "${TARGETARCH}" in \
        amd64) amass_arch="amd64" ;; \
        arm64) amass_arch="arm64" ;; \
        *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${amass_arch}.zip" \
        --output /tmp/amass.zip; \
    unzip -q /tmp/amass.zip -d /tmp/amass-extract; \
    amass_bin="$(find /tmp/amass-extract -type f -name amass | head -n 1)"; \
    test -n "${amass_bin}"; \
    install -m 0755 "${amass_bin}" /usr/local/bin/amass; \
    rm -rf /tmp/amass.zip /tmp/amass-extract; \
    mkdir -p /root/.config/amass /usr/share/wordlists/amass; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://raw.githubusercontent.com/owasp-amass/amass/master/examples/wordlists/subdomains-top1mil-5000.txt" \
        --output /usr/share/wordlists/amass/subdomains-top1mil-5000.txt; \
    printf '%s\n' \
        'options:' \
        '  maximum_dns_queries: 10' \
        '  bruteforce:' \
        '    enabled: true' \
        '    wordlists:' \
        '      - "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"' > /root/.config/amass/config.yaml; \
    case "${TARGETARCH}" in \
        amd64) httpx_arch="amd64" ;; \
        arm64) httpx_arch="arm64" ;; \
        *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTTPX_VERSION}/httpx_${HTTTPX_VERSION}_linux_${httpx_arch}.zip" \
        --output /tmp/httpx.zip; \
    unzip -q /tmp/httpx.zip -d /tmp/httpx; \
    install -m 0755 /tmp/httpx/httpx /usr/local/bin/httpx; \
    rm -rf /tmp/httpx /tmp/httpx.zip; \
    case "${TARGETARCH}" in \
        amd64) katana_arch="amd64" ;; \
        arm64) katana_arch="arm64" ;; \
        *) echo "Unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${katana_arch}.zip" \
        --output /tmp/katana.zip; \
    unzip -q /tmp/katana.zip -d /tmp/katana; \
    install -m 0755 /tmp/katana/katana /usr/local/bin/katana; \
    rm -rf /tmp/katana /tmp/katana.zip; \
    rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates -silent -td /root/nuclei-templates

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
