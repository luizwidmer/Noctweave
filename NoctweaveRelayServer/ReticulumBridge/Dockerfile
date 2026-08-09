FROM python:3.13-slim

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /app/requirements.txt \
    && groupadd --system --gid 10002 noctweave \
    && useradd --system --uid 10002 --gid noctweave --create-home noctweave \
    && mkdir -p /app /config /data /usr/share/doc/noctweave-reticulum-bridge \
    && chown -R noctweave:noctweave /config /data

COPY noctweave_reticulum_bridge.py /app/noctweave_reticulum_bridge.py
COPY RETICULUM_LICENSE_NOTICE.md /usr/share/doc/noctweave-reticulum-bridge/RETICULUM_LICENSE_NOTICE.md

USER noctweave:noctweave
WORKDIR /app
VOLUME ["/config", "/data"]
ENTRYPOINT ["python", "/app/noctweave_reticulum_bridge.py"]
