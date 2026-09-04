FROM python:3.12-slim

# git is the only runtime dependency: the collector clones remote repositories.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY collector.py server.py ./

# Runs as an unprivileged user with a read-only root filesystem; /tmp is an
# emptyDir volume supplied by the Deployment and is the only writable location,
# so it holds both HOME and the transient clones.
RUN useradd --uid 1001 --no-create-home --home-dir /tmp collector
USER 1001
ENV HOME=/tmp \
    TMPDIR=/tmp \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080
CMD ["python", "server.py"]
