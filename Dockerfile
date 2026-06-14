FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE MANIFEST.in constraints.txt ./
COPY src ./src

RUN python -m pip install --no-cache-dir -c constraints.txt . \
    && useradd --create-home --shell /usr/sbin/nologin mcpzt \
    && chown -R mcpzt:mcpzt /app

USER mcpzt

ENTRYPOINT ["mcpzt"]
