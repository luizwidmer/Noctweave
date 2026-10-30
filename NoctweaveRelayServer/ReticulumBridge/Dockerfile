FROM python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8

COPY requirements.txt /app/requirements.txt
RUN apk upgrade --no-cache \
    && python -m pip install --no-cache-dir --requirement /app/requirements.txt \
    && python -m pip check \
    && python -m pip uninstall --yes pip setuptools urllib3 \
    && python -c 'import RNS, cffi, cryptography, msgpack, serial; import importlib.util; assert importlib.util.find_spec("urllib3") is None' \
    && addgroup -S -g 10002 noctweave \
    && adduser -S -D -u 10002 -G noctweave -h /home/noctweave noctweave \
    && mkdir -p /app /config /data /usr/share/doc/noctweave-reticulum-bridge \
    && chown -R noctweave:noctweave /config /data

COPY noctweave_reticulum_bridge.py /app/noctweave_reticulum_bridge.py
COPY RETICULUM_LICENSE_NOTICE.md /usr/share/doc/noctweave-reticulum-bridge/RETICULUM_LICENSE_NOTICE.md
WORKDIR /app
RUN python -c 'import noctweave_reticulum_bridge'

USER noctweave:noctweave
VOLUME ["/config", "/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9341/bridge/health', timeout=2).read(1024)"]
ENTRYPOINT ["python", "/app/noctweave_reticulum_bridge.py"]
