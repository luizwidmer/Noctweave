FROM python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /app/requirements.txt \
    && python -m pip check \
    && python -m pip uninstall --yes pip setuptools \
    && python -c 'import RNS, cffi, cryptography, msgpack, serial' \
    && addgroup -S -g 10002 noctweave \
    && adduser -S -D -u 10002 -G noctweave -h /home/noctweave noctweave \
    && mkdir -p /app /config /data /usr/share/doc/noctweave-reticulum-bridge \
    && chown -R noctweave:noctweave /config /data

COPY noctweave_reticulum_bridge.py /app/noctweave_reticulum_bridge.py
COPY RETICULUM_LICENSE_NOTICE.md /usr/share/doc/noctweave-reticulum-bridge/RETICULUM_LICENSE_NOTICE.md

USER noctweave:noctweave
WORKDIR /app
VOLUME ["/config", "/data"]
ENTRYPOINT ["python", "/app/noctweave_reticulum_bridge.py"]
