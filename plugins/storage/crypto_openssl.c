/*
 * Crypto implementation using OpenSSL
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

void crypto_sha256(const void *data, size_t len, unsigned char *hash) {
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, data, len);
  SHA256_Final(hash, &sha_ctx);
}

void crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                        size_t data_len, unsigned char *out) {
  unsigned int out_len = 32;
  HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
}
