/*
 * AWS Signature Version 4 Signing Utilities
 *
 * This module provides the cryptographic building blocks for AWS SigV4 signing.
 * It's designed to be testable in isolation using AWS's published test vectors.
 *
 * Reference:
 * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
 */

#ifndef SIGV4_H
#define SIGV4_H

#include <stddef.h>
#include <stdint.h>

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic Primitives
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Encode bytes as lowercase hexadecimal string.
 *
 * @param input  Input bytes to encode
 * @param len    Number of bytes in input
 * @param output Output buffer (must be at least len*2 + 1 bytes)
 */
void sigv4_hex_encode(const unsigned char *input, size_t len, char *output);

/*
 * Compute SHA-256 hash.
 *
 * @param data  Input data to hash
 * @param len   Length of input data
 * @param hash  Output buffer (must be 32 bytes)
 */
void sigv4_sha256(const void *data, size_t len, unsigned char *hash);

/*
 * Compute HMAC-SHA256.
 *
 * @param key       Key for HMAC
 * @param key_len   Length of key
 * @param data      Data to authenticate
 * @param data_len  Length of data
 * @param out       Output buffer (must be 32 bytes)
 */
void sigv4_hmac_sha256(const void *key, size_t key_len, const void *data,
                       size_t data_len, unsigned char *out);

// ─────────────────────────────────────────────────────────────────────────────
// AWS SigV4 Key Derivation
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Derive the signing key for AWS SigV4.
 *
 * The key is derived as:
 *   kDate    = HMAC("AWS4" + secret_key, date_stamp)
 *   kRegion  = HMAC(kDate, region)
 *   kService = HMAC(kRegion, service)
 *   kSigning = HMAC(kService, "aws4_request")
 *
 * @param secret_key  AWS secret access key
 * @param date_stamp  Date in YYYYMMDD format
 * @param region      AWS region (e.g., "us-east-1")
 * @param service     AWS service (e.g., "s3")
 * @param out_key     Output buffer (must be 32 bytes)
 */
void sigv4_get_signing_key(const char *secret_key, const char *date_stamp,
                           const char *region, const char *service,
                           unsigned char *out_key);

// ─────────────────────────────────────────────────────────────────────────────
// URL Parsing
// ─────────────────────────────────────────────────────────────────────────────

/*
 * Parse a URL into its components for SigV4 signing.
 *
 * @param url        Full URL (e.g.,
 * "https://bucket.s3.amazonaws.com/key?uploads")
 * @param host       Output buffer for host (e.g., "bucket.s3.amazonaws.com")
 * @param host_len   Size of host buffer
 * @param path       Output buffer for path (e.g., "/key")
 * @param path_len   Size of path buffer
 * @param query      Output buffer for canonical query string
 * @param query_len  Size of query buffer
 * @return 0 on success, -1 on error
 */
int sigv4_parse_url(const char *url, char *host, size_t host_len, char *path,
                    size_t path_len, char *query, size_t query_len);

/*
 * Canonicalize a query string for AWS SigV4.
 *
 * AWS requires:
 * - Parameters sorted by name
 * - Empty values represented as "name=" (trailing equals)
 * - URL encoding for special characters
 *
 * @param query_in   Raw query string (without leading '?')
 * @param query_out  Output buffer for canonical query string
 * @param out_len    Size of output buffer
 * @return 0 on success, -1 on error
 */
int sigv4_canonicalize_query(const char *query_in, char *query_out,
                             size_t out_len);

#endif /* SIGV4_H */
