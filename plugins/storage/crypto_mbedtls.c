/*
 * Crypto implementation using mbedTLS (PSA Crypto API)
 *
 * mbedTLS 4 removed the legacy mbedtls_sha256/mbedtls_md_hmac APIs; PSA is
 * available in both mbedTLS 3.6 and 4.x.
 */

#include "crypto.h"
#include <psa/crypto.h>
#include <string.h>

void crypto_sha256(const void *data, size_t len, unsigned char *hash) {
  size_t hash_len = 0;
  if (psa_crypto_init() != PSA_SUCCESS ||
      psa_hash_compute(PSA_ALG_SHA_256, data, len, hash,
                       CRYPTO_SHA256_DIGEST_LENGTH, &hash_len) != PSA_SUCCESS) {
    memset(hash, 0, CRYPTO_SHA256_DIGEST_LENGTH);
  }
}

void crypto_hmac_sha256(const void *key, size_t key_len, const void *data,
                        size_t data_len, unsigned char *out) {
  const psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id = 0;
  size_t mac_len = 0;

  psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attr, alg);

  if (psa_crypto_init() != PSA_SUCCESS ||
      psa_import_key(&attr, key, key_len, &key_id) != PSA_SUCCESS) {
    memset(out, 0, CRYPTO_SHA256_DIGEST_LENGTH);
    return;
  }

  if (psa_mac_compute(key_id, alg, data, data_len, out,
                      CRYPTO_SHA256_DIGEST_LENGTH, &mac_len) != PSA_SUCCESS) {
    memset(out, 0, CRYPTO_SHA256_DIGEST_LENGTH);
  }
  psa_destroy_key(key_id);
}
