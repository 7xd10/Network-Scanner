# Minimal runtime image. No compiler, no pip cache, no build tools in the final
# layer -- the package is pure standard-library Python.
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="netscan" \
      org.opencontainers.image.description="Asynchronous TCP port scanner with service detection, banner grabbing and exposure classification" \
      org.opencontainers.image.authors="Youssef Alaoui Hichami <alaouihichamiyoussef@gmail.com>" \
      org.opencontainers.image.source="https://github.com/7xd10/Network-Scanner" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
 && rm -rf /app/src /app/pyproject.toml /app/README.md /app/LICENSE \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin netscan

USER netscan

ENTRYPOINT ["netscan"]
CMD ["--help"]
