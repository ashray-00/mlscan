# Scan an untrusted artifact with no network and a non-root user.
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 mlscan \
 && mkdir -p /work \
 && chown mlscan:mlscan /work

WORKDIR /src
COPY pyproject.toml README.md LICENSE LIMITATIONS.md ./
COPY mlscan ./mlscan
RUN pip install --no-cache-dir . \
 && rm -rf /root/.cache

USER mlscan
WORKDIR /work
ENTRYPOINT ["mlscan"]
