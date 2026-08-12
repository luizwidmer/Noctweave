ARG LIBOQS_VERSION=0.16.0
ARG LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183

FROM swift:6.1-jammy@sha256:cb9552a535de8d1a92373351a35ced3813791b6cca6a380bdf179ff3f3122803 AS builder
ARG LIBOQS_VERSION
ARG LIBOQS_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    git \
    libsqlite3-dev \
    libssl-dev \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN git init /tmp/liboqs \
    && git -C /tmp/liboqs remote add origin https://github.com/open-quantum-safe/liboqs.git \
    && git -C /tmp/liboqs fetch --depth 1 origin "${LIBOQS_COMMIT}" \
    && git -C /tmp/liboqs checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/liboqs rev-parse HEAD)" = "${LIBOQS_COMMIT}" \
    && cmake -G Ninja -S /tmp/liboqs -B /tmp/liboqs/build \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/liboqs/build -j"$(nproc)" \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs
WORKDIR /app
COPY . .
RUN swift build -c release \
    && strip --strip-unneeded .build/release/NoctweaveRelayServer \
    && strip --strip-unneeded "$(readlink -f /usr/local/lib/liboqs.so.9)"

FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcurl4 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/lib/swift/linux/*.so /usr/lib/swift/linux/
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/swift/linux
RUN groupadd --system --gid 10001 noctweave \
    && useradd --system --uid 10001 --gid noctweave --create-home noctweave \
    && mkdir -p /data \
    && chown noctweave:noctweave /data
WORKDIR /app
COPY --from=builder /app/.build/release/NoctweaveRelayServer /usr/local/bin/noctweave-relay
USER noctweave:noctweave
EXPOSE 9339 9340 9090
ENV NOCTWEAVE_RELAY_PORT=9339
ENV NOCTWEAVE_ADMIN_HOST=0.0.0.0
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${NOCTWEAVE_RELAY_PORT:-9339}"]
ENTRYPOINT ["/usr/local/bin/noctweave-relay"]
CMD ["--host", "0.0.0.0", "--port", "9339", "--data-dir", "/data"]
