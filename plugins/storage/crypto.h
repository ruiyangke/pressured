/*
 * Crypto abstraction layer for SHA256 and HMAC-SHA256
 * Supports OpenSSL and mbedTLS backends
 */

#ifndef PRESSURED_CRYPTO_H
#define PRESSURED_CRYPTO_H

#include <stddef.h>

#define CRYPTO_SHA256_DIGEST_LENGTH 32

void crypto_sha256(const void *data, size_t len, unsigned char *hash);

void crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                        size_t data_len, unsigned char *out);

#endif /* PRESSURED_CRYPTO_H */
