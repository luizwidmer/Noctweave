ARG LIBOQS_VERSION=0.15.0
ARG LIBOQS_COMMIT=97f6b86b1b6d109cfd43cf276ae39c2e776aed80

FROM swift:6.1-jammy AS builder
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
    && strip --strip-unneeded /usr/local/lib/liboqs.so.0.15.0

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcurl4 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/lib/swift/linux/*.so /usr/lib/swift/linux/
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/swift/linux
RUN groupadd --system --gid 10001 noctyra \
    && useradd --system --uid 10001 --gid noctyra --create-home noctyra \
    && mkdir -p /data \
    && chown noctyra:noctyra /data
WORKDIR /app
COPY --from=builder /app/.build/release/NoctweaveRelayServer /usr/local/bin/noctweave-relay
USER noctyra:noctyra
EXPOSE 9339 9340 9090
ENV NOCTWEAVE_RELAY_PORT=9339
ENV NOCTYRA_ADMIN_HOST=0.0.0.0
ENTRYPOINT ["/usr/local/bin/noctweave-relay"]
CMD ["--host", "0.0.0.0", "--port", "9339", "--data-dir", "/data"]
