/*
 * Crypto implementation using mbedTLS
 */

#include "crypto.h"
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

void crypto_sha256(const void *data, size_t len, unsigned char *hash) {
  mbedtls_sha256((const unsigned char *)data, len, hash, 0);
}

void crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                        size_t data_len, unsigned char *out) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md_info, (const unsigned char *)key, key_len,
                  (const unsigned char *)data, data_len, out);
}
