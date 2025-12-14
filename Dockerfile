# Build stage - curl with mbedTLS instead of OpenSSL
FROM alpine:3.23 AS builder

RUN apk add --no-cache \
    build-base cmake ninja pkgconfig wget \
    mbedtls-dev zlib-dev json-c-dev lua5.4-dev

# Build curl with mbedTLS (Alpine's curl uses OpenSSL)
ARG CURL_VERSION=8.17.0
ARG CURL_SHA256=e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910
RUN wget -q https://curl.se/download/curl-${CURL_VERSION}.tar.gz && \
    echo "${CURL_SHA256}  curl-${CURL_VERSION}.tar.gz" | sha256sum -c - && \
    tar xzf curl-${CURL_VERSION}.tar.gz && \
    cd curl-${CURL_VERSION} && \
    ./configure \
        --prefix=/usr/local \
        --with-mbedtls \
        --without-openssl --without-gnutls --without-wolfssl \
        --without-bearssl --without-rustls \
        --without-ngtcp2 --without-nghttp3 --without-quiche --without-msh3 \
        --without-libidn2 --without-libpsl --without-brotli --without-zstd \
        --disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
        --disable-telnet --disable-tftp --disable-pop3 --disable-imap \
        --disable-smb --disable-smtp --disable-gopher --disable-mqtt \
        --disable-manual --disable-docs --disable-ftp --disable-file \
        --disable-ipfs --disable-ntlm --disable-unix-sockets --disable-cookies \
        --disable-websockets --disable-alt-svc --disable-hsts --disable-doh \
        --disable-mime --disable-dateparse --disable-netrc --disable-progress-meter \
        --disable-dnsshuffle --disable-get-easy-options --disable-form-api \
        --disable-bearer-auth --disable-digest-auth \
        --disable-kerberos-auth --disable-negotiate-auth --disable-aws \
        --enable-http --enable-proxy --enable-basic-auth --enable-ipv6 \
        --disable-static --enable-shared --enable-optimize --silent && \
    make -j$(nproc) && make install

WORKDIR /build
COPY . .

RUN PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    cmake -B build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/usr/local \
        -DTLS_BACKEND=mbedtls && \
    ninja -C build && \
    strip build/pressured build/plugins/*.so

# Runtime stage - extract only needed libraries
FROM alpine:3.23 AS runtime

RUN apk add --no-cache mbedtls json-c lua5.4-libs zlib ca-certificates

# Stage libraries with symlinks preserved (COPY dereferences symlinks with globs)
RUN mkdir -p /staged/lib /staged/usr/lib /staged/usr/local/lib
COPY --from=builder /usr/local/lib/ /tmp/curl-lib/

RUN cp -a /tmp/curl-lib/libcurl.so* /staged/usr/local/lib/ && \
    cp -a /lib/ld-musl-*.so.1 /staged/lib/ && \
    cp -a /lib/libc.musl-*.so.1 /staged/lib/ && \
    cp -a /usr/lib/libmbedtls.so* \
          /usr/lib/libmbedx509.so* \
          /usr/lib/libmbedcrypto.so* \
          /usr/lib/libjson-c.so* \
          /usr/lib/libz.so* \
          /staged/usr/lib/ && \
    cp -a /usr/lib/lua5.4/liblua-5.4.so* /staged/usr/lib/

# Final minimal image
FROM scratch

COPY --from=runtime /staged/lib/ /lib/
COPY --from=runtime /staged/usr/lib/ /usr/lib/
COPY --from=runtime /staged/usr/local/lib/ /usr/local/lib/
COPY --from=runtime /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=runtime /etc/passwd /etc/group /etc/

COPY --from=builder /build/build/pressured /usr/local/bin/
COPY --from=builder /build/build/plugins/*.so /usr/local/lib/pressured/plugins/

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib \
    PRESSURED_PLUGIN_DIR=/usr/local/lib/pressured/plugins

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/pressured"]
CMD []
