# MITIGATA: scope-enforced multi-agent penetration-testing engine and local dashboard.
#
#   docker build -t mitigata:local .                       # full image, with the optional angr solver
#   docker build --build-arg WITH_SOLVER=0 -t mitigata:lite .
#
# No secrets are baked into the image. The optional LLM planner reads DEEPSEEK_API_KEY from the environment at run time.
FROM python:3.12-slim-bookworm

ARG WITH_SOLVER=1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap runs discovery and port scans with TCP connect (no root needed). radare2 gives listings and strings for the
# binary agent; Debian does not package it for bookworm or trixie, so the pinned upstream .deb is fetched and its
# SHA-256 is checked before installation. Ghidra is optional and not installed here; the engine falls back to radare2.
ARG R2_VERSION=6.2.4
ARG R2_SHA256=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl \
 && curl -fsSL -o /tmp/radare2.deb \
      "https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb" \
 && echo "${R2_SHA256}  /tmp/radare2.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends /tmp/radare2.deb \
 && rm -f /tmp/radare2.deb \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 mitigata

WORKDIR /opt/mitigata
COPY pyproject.toml README.md ./
COPY mitigata ./mitigata
COPY frontend ./frontend
RUN pip install . \
 && if [ "$WITH_SOLVER" = "1" ]; then pip install "angr==9.2.*" "bitstring==4.4.0" "pycparser==3.11"; fi

# Run-time data lives in /data: the manifest, the binaries folder and the runs folder are mounted there.
WORKDIR /data
USER mitigata
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=4).status == 200 else 1)"

ENTRYPOINT ["mitigata"]
CMD ["serve", "--host", "127.0.0.1", "--scope", "/data/scope.yaml", "--out", "/data/runs", "--port", "8765"]
