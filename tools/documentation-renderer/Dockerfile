FROM python:3.12-slim

WORKDIR /app
COPY renderer.py server.py ./

RUN useradd --uid 1001 --no-create-home --home-dir /tmp renderer
USER 1001
ENV HOME=/tmp \
    TMPDIR=/tmp \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080
CMD ["python", "server.py"]
