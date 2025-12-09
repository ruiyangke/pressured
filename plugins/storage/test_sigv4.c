/*
 * AWS Signature V4 Unit Tests
 *
 * Tests the SigV4 signing utilities using known test vectors from AWS
 * documentation. Reference:
 * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
 */

#include "sigv4.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name)                                                         \
  do {                                                                         \
    printf("  %-50s", #name);                                                  \
    test_##name();                                                             \
    printf(" OK\n");                                                           \
    tests_passed++;                                                            \
  } while (0)

#define ASSERT_STR_EQ(expected, actual)                                        \
  do {                                                                         \
    if (strcmp((expected), (actual)) != 0) {                                   \
      printf(" FAILED\n    Expected: %s\n    Actual:   %s\n", (expected),      \
             (actual));                                                        \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_MEM_EQ(expected, actual, len)                                   \
  do {                                                                         \
    if (memcmp((expected), (actual), (len)) != 0) {                            \
      printf(" FAILED\n    Memory mismatch at line %d\n", __LINE__);           \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_INT_EQ(expected, actual)                                        \
  do {                                                                         \
    if ((expected) != (actual)) {                                              \
      printf(" FAILED\n    Expected: %d, Actual: %d\n", (expected), (actual)); \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

// ─────────────────────────────────────────────────────────────────────────────
// Hex Encoding Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(hex_encode_empty) {
  const unsigned char input[1] = {0}; // Dummy byte, but we pass len=0
  char output[1] = {0};
  sigv4_hex_encode(input, 0, output);
  ASSERT_STR_EQ("", output);
}

TEST(hex_encode_single_byte) {
  const unsigned char input[] = {0xab};
  char output[3] = {0};
  sigv4_hex_encode(input, 1, output);
  ASSERT_STR_EQ("ab", output);
}

TEST(hex_encode_multiple_bytes) {
  const unsigned char input[] = {0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
  char output[17] = {0};
  sigv4_hex_encode(input, 8, output);
  ASSERT_STR_EQ("0123456789abcdef", output);
}

TEST(hex_encode_all_zeros) {
  const unsigned char input[] = {0x00, 0x00, 0x00, 0x00};
  char output[9] = {0};
  sigv4_hex_encode(input, 4, output);
  ASSERT_STR_EQ("00000000", output);
}

TEST(hex_encode_all_ff) {
  const unsigned char input[] = {0xff, 0xff, 0xff, 0xff};
  char output[9] = {0};
  sigv4_hex_encode(input, 4, output);
  ASSERT_STR_EQ("ffffffff", output);
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 Tests (using NIST test vectors)
// ─────────────────────────────────────────────────────────────────────────────

TEST(sha256_empty) {
  // SHA-256("") =
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  unsigned char hash[32];
  sigv4_sha256("", 0, hash);

  char hex[65];
  sigv4_hex_encode(hash, 32, hex);
  ASSERT_STR_EQ(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

TEST(sha256_abc) {
  // SHA-256("abc") =
  // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  unsigned char hash[32];
  sigv4_sha256("abc", 3, hash);

  char hex[65];
  sigv4_hex_encode(hash, 32, hex);
  ASSERT_STR_EQ(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
}

TEST(sha256_aws_example) {
  // SHA-256 of empty request body (common in S3 GET requests)
  const char *empty_body = "";
  unsigned char hash[32];
  sigv4_sha256(empty_body, 0, hash);

  char hex[65];
  sigv4_hex_encode(hash, 32, hex);
  ASSERT_STR_EQ(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 Tests (using RFC 4231 test vectors)
// ─────────────────────────────────────────────────────────────────────────────

TEST(hmac_sha256_rfc4231_test1) {
  // Test Case 1 from RFC 4231
  // Key = 0x0b repeated 20 times
  // Data = "Hi There"
  // HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  unsigned char key[20];
  memset(key, 0x0b, 20);

  unsigned char hmac[32];
  sigv4_hmac_sha256(key, 20, "Hi There", 8, hmac);

  char hex[65];
  sigv4_hex_encode(hmac, 32, hex);
  ASSERT_STR_EQ(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hex);
}

TEST(hmac_sha256_rfc4231_test2) {
  // Test Case 2 from RFC 4231
  // Key = "Jefe"
  // Data = "what do ya want for nothing?"
  // HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  unsigned char hmac[32];
  sigv4_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, hmac);

  char hex[65];
  sigv4_hex_encode(hmac, 32, hex);
  ASSERT_STR_EQ(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hex);
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS SigV4 Signing Key Derivation Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(signing_key_aws_example) {
  /*
   * AWS Example from documentation:
   * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
   *
   * Secret Key: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
   * Date: 20120215
   * Region: us-east-1
   * Service: iam
   *
   * Expected signing key (hex):
   * f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d
   */
  unsigned char key[32];
  sigv4_get_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215",
                        "us-east-1", "iam", key);

  char hex[65];
  sigv4_hex_encode(key, 32, hex);
  ASSERT_STR_EQ(
      "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d", hex);
}

TEST(signing_key_s3_service) {
  /*
   * Test signing key derivation for S3 service
   * Using the same secret key but different service
   */
  unsigned char key[32];
  sigv4_get_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524",
                        "us-east-1", "s3", key);

  // Verify key is 32 bytes and non-zero
  int nonzero = 0;
  for (int i = 0; i < 32; i++) {
    if (key[i] != 0)
      nonzero++;
  }
  ASSERT_INT_EQ(1, nonzero > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Parsing Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(parse_url_simple_s3) {
  char host[256], path[1024], query[1024];
  int rc =
      sigv4_parse_url("https://bucket.s3.amazonaws.com/key", host, sizeof(host),
                      path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("bucket.s3.amazonaws.com", host);
  ASSERT_STR_EQ("/key", path);
  ASSERT_STR_EQ("", query);
}

TEST(parse_url_with_query) {
  char host[256], path[1024], query[1024];
  int rc =
      sigv4_parse_url("https://bucket.s3.amazonaws.com/key?uploads", host,
                      sizeof(host), path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("bucket.s3.amazonaws.com", host);
  ASSERT_STR_EQ("/key", path);
  ASSERT_STR_EQ("uploads", query);
}

TEST(parse_url_with_query_params) {
  char host[256], path[1024], query[1024];
  int rc = sigv4_parse_url(
      "https://bucket.s3.amazonaws.com/key?partNumber=1&uploadId=abc123", host,
      sizeof(host), path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("bucket.s3.amazonaws.com", host);
  ASSERT_STR_EQ("/key", path);
  ASSERT_STR_EQ("partNumber=1&uploadId=abc123", query);
}

TEST(parse_url_deep_path) {
  char host[256], path[1024], query[1024];
  int rc = sigv4_parse_url(
      "https://bucket.s3.us-west-2.amazonaws.com/prefix/folder/deep/key.txt",
      host, sizeof(host), path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("bucket.s3.us-west-2.amazonaws.com", host);
  ASSERT_STR_EQ("/prefix/folder/deep/key.txt", path);
  ASSERT_STR_EQ("", query);
}

TEST(parse_url_path_style) {
  // Path-style S3 URL
  char host[256], path[1024], query[1024];
  int rc =
      sigv4_parse_url("https://s3.us-west-2.amazonaws.com/mybucket/mykey", host,
                      sizeof(host), path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("s3.us-west-2.amazonaws.com", host);
  ASSERT_STR_EQ("/mybucket/mykey", path);
  ASSERT_STR_EQ("", query);
}

TEST(parse_url_localstack) {
  // LocalStack endpoint
  char host[256], path[1024], query[1024];
  int rc =
      sigv4_parse_url("http://localhost:4566/bucket/key?uploads", host,
                      sizeof(host), path, sizeof(path), query, sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("localhost:4566", host);
  ASSERT_STR_EQ("/bucket/key", path);
  ASSERT_STR_EQ("uploads", query);
}

// ─────────────────────────────────────────────────────────────────────────────
// Query String Canonicalization Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(canonicalize_query_empty) {
  char out[1024];
  int rc = sigv4_canonicalize_query("", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("", out);
}

TEST(canonicalize_query_null) {
  char out[1024];
  int rc = sigv4_canonicalize_query(NULL, out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("", out);
}

TEST(canonicalize_query_uploads_no_value) {
  /*
   * Critical test for S3 multipart upload!
   * AWS requires "uploads=" (with trailing equals) not just "uploads"
   * This was the root cause of SignatureDoesNotMatch errors.
   */
  char out[1024];
  int rc = sigv4_canonicalize_query("uploads", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("uploads=", out);
}

TEST(canonicalize_query_single_param) {
  char out[1024];
  int rc = sigv4_canonicalize_query("partNumber=1", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("partNumber=1", out);
}

TEST(canonicalize_query_multiple_params_sorted) {
  /*
   * AWS requires query parameters to be sorted alphabetically
   * Input: b=2&a=1
   * Output: a=1&b=2 (sorted)
   */
  char out[1024];
  int rc = sigv4_canonicalize_query("b=2&a=1", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("a=1&b=2", out);
}

TEST(canonicalize_query_s3_multipart_upload) {
  /*
   * Test case for S3 UploadPart request:
   * ?partNumber=1&uploadId=abc123
   * Should be sorted: partNumber, uploadId (alphabetical)
   */
  char out[1024];
  int rc = sigv4_canonicalize_query("uploadId=abc123&partNumber=1", out,
                                    sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("partNumber=1&uploadId=abc123", out);
}

TEST(canonicalize_query_mixed_values_and_no_values) {
  /*
   * Mix of params with values and without values
   * No value params get trailing "="
   */
  char out[1024];
  int rc =
      sigv4_canonicalize_query("uploads&bucket=mybucket", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("bucket=mybucket&uploads=", out);
}

TEST(canonicalize_query_empty_value) {
  // Param with explicit empty value: key=
  char out[1024];
  int rc = sigv4_canonicalize_query("key=", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("key=", out);
}

TEST(canonicalize_query_url_encoding) {
  /*
   * Test URL encoding of special characters
   * AWS requires uppercase hex codes
   */
  char out[1024];
  int rc = sigv4_canonicalize_query("key=hello world", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("key=hello%20world", out);
}

TEST(canonicalize_query_special_chars) {
  // Test various special characters that need encoding
  char out[1024];
  int rc = sigv4_canonicalize_query("key=a+b", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  // '+' should be encoded as %2B
  ASSERT_STR_EQ("key=a%2Bb", out);
}

TEST(canonicalize_query_unreserved_chars) {
  // Unreserved chars should NOT be encoded: A-Z a-z 0-9 - . _ ~
  char out[1024];
  int rc = sigv4_canonicalize_query("key=AZaz09-._~", out, sizeof(out));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("key=AZaz09-._~", out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests
// ─────────────────────────────────────────────────────────────────────────────

TEST(full_signing_workflow) {
  /*
   * Test the full signing workflow:
   * 1. Parse URL
   * 2. Canonicalize query
   * 3. Hash payload
   * 4. Derive signing key
   * 5. Sign (though we don't test the full signature here, just the pieces)
   */

  // 1. Parse URL
  const char *url = "https://examplebucket.s3.amazonaws.com/test.txt?uploads";
  char host[256], path[1024], query[1024];
  int rc = sigv4_parse_url(url, host, sizeof(host), path, sizeof(path), query,
                           sizeof(query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("examplebucket.s3.amazonaws.com", host);
  ASSERT_STR_EQ("/test.txt", path);
  ASSERT_STR_EQ("uploads", query);

  // 2. Canonicalize query
  char canonical_query[1024];
  rc =
      sigv4_canonicalize_query(query, canonical_query, sizeof(canonical_query));
  ASSERT_INT_EQ(0, rc);
  ASSERT_STR_EQ("uploads=", canonical_query); // Key test: trailing =

  // 3. Hash empty payload
  unsigned char payload_hash[32];
  sigv4_sha256("", 0, payload_hash);
  char payload_hash_hex[65];
  sigv4_hex_encode(payload_hash, 32, payload_hash_hex);
  ASSERT_STR_EQ(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      payload_hash_hex);

  // 4. Derive signing key
  unsigned char signing_key[32];
  sigv4_get_signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524",
                        "us-east-1", "s3", signing_key);
  // Verify non-zero
  int nonzero = 0;
  for (int i = 0; i < 32; i++) {
    if (signing_key[i] != 0)
      nonzero++;
  }
  ASSERT_INT_EQ(1, nonzero > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

int main(void) {
  printf("test_sigv4: AWS Signature V4 Unit Tests\n");
  printf("========================================\n\n");

  printf("Hex Encoding:\n");
  RUN_TEST(hex_encode_empty);
  RUN_TEST(hex_encode_single_byte);
  RUN_TEST(hex_encode_multiple_bytes);
  RUN_TEST(hex_encode_all_zeros);
  RUN_TEST(hex_encode_all_ff);

  printf("\nSHA-256:\n");
  RUN_TEST(sha256_empty);
  RUN_TEST(sha256_abc);
  RUN_TEST(sha256_aws_example);

  printf("\nHMAC-SHA256 (RFC 4231):\n");
  RUN_TEST(hmac_sha256_rfc4231_test1);
  RUN_TEST(hmac_sha256_rfc4231_test2);

  printf("\nAWS SigV4 Signing Key:\n");
  RUN_TEST(signing_key_aws_example);
  RUN_TEST(signing_key_s3_service);

  printf("\nURL Parsing:\n");
  RUN_TEST(parse_url_simple_s3);
  RUN_TEST(parse_url_with_query);
  RUN_TEST(parse_url_with_query_params);
  RUN_TEST(parse_url_deep_path);
  RUN_TEST(parse_url_path_style);
  RUN_TEST(parse_url_localstack);

  printf("\nQuery String Canonicalization:\n");
  RUN_TEST(canonicalize_query_empty);
  RUN_TEST(canonicalize_query_null);
  RUN_TEST(canonicalize_query_uploads_no_value);
  RUN_TEST(canonicalize_query_single_param);
  RUN_TEST(canonicalize_query_multiple_params_sorted);
  RUN_TEST(canonicalize_query_s3_multipart_upload);
  RUN_TEST(canonicalize_query_mixed_values_and_no_values);
  RUN_TEST(canonicalize_query_empty_value);
  RUN_TEST(canonicalize_query_url_encoding);
  RUN_TEST(canonicalize_query_special_chars);
  RUN_TEST(canonicalize_query_unreserved_chars);

  printf("\nIntegration:\n");
  RUN_TEST(full_signing_workflow);

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

  if (tests_failed > 0) {
    printf("test_sigv4: FAILED\n");
    return 1;
  }

  printf("test_sigv4: PASSED\n");
  return 0;
}
