# Build stage
FROM alpine:3 AS builder

RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    pkgconfig \
    curl-dev \
    json-c-dev \
    lua5.4-dev \
    openssl-dev

WORKDIR /build
COPY . .

RUN mkdir -p build && cd build && \
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && \
    ninja

# Runtime stage
FROM alpine:3

RUN apk add --no-cache \
    libcurl \
    json-c \
    lua5.4-libs \
    libssl3 \
    libcrypto3 \
    ca-certificates

# Copy binary and plugins
COPY --from=builder /build/build/pressured /usr/local/bin/pressured
COPY --from=builder /build/build/plugins/*.so /usr/local/lib/pressured/plugins/

# Create non-root user
RUN adduser -D -u 1000 pressured
USER pressured

ENV PRESSURED_PLUGIN_DIR=/usr/local/lib/pressured/plugins

ENTRYPOINT ["/usr/local/bin/pressured"]
