/*
 * S3 credential and config parsing unit tests
 *
 * Exercises the production parsers (parse_credentials, parse_s3_config) by
 * including s3_storage.c directly, so the JSON reading code under test is the
 * same code the plugin ships.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "s3_storage.c"

// Reset a context to the state pressured_plugin_load starts from (zeroed
// fields, default region) so config parsing can be tested in isolation.
static void reset_ctx(pressured_plugin_ctx_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  strncpy(ctx->region, "us-east-1", sizeof(ctx->region) - 1);
}

static void test_credentials(void) {
  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(*ctx));
  assert(ctx);

  memset(ctx->access_key, 'a', sizeof(ctx->access_key));
  memset(ctx->secret_key, 's', sizeof(ctx->secret_key));
  memset(ctx->session_token, 't', sizeof(ctx->session_token));

  const char *full =
      "{\"AccessKeyId\":\"AK\",\"SecretAccessKey\":\"SK\","
      "\"Token\":\"TK\",\"Expiration\":\"2030-01-01T00:00:00Z\"}";
  int rc = parse_credentials(ctx, full);
  assert(rc == 0);
  assert(strcmp(ctx->access_key, "AK") == 0);
  assert(strcmp(ctx->secret_key, "SK") == 0);
  assert(strcmp(ctx->session_token, "TK") == 0);
  assert(ctx->cred_expiration == parse_iso8601("2030-01-01T00:00:00Z") - 300);

  // A token from an earlier refresh is cleared when the new response omits it.
  strcpy(ctx->session_token, "OLD");
  time_t now = time(NULL);
  rc = parse_credentials(ctx, "{\"AccessKeyId\":\"AK2\","
                              "\"SecretAccessKey\":\"SK2\"}");
  assert(rc == 0);
  assert(strcmp(ctx->access_key, "AK2") == 0);
  assert(strcmp(ctx->secret_key, "SK2") == 0);
  assert(ctx->session_token[0] == '\0');
  assert(ctx->cred_expiration >= now + 3300);
  assert(ctx->cred_expiration <= now + 3300 + 5);

  // Explicit null Token/Expiration behave like missing fields.
  strcpy(ctx->session_token, "OLD");
  now = time(NULL);
  rc = parse_credentials(ctx, "{\"AccessKeyId\":\"AK3\","
                              "\"SecretAccessKey\":\"SK3\","
                              "\"Token\":null,\"Expiration\":null}");
  assert(rc == 0);
  assert(ctx->session_token[0] == '\0');
  assert(ctx->cred_expiration >= now + 3300);
  assert(ctx->cred_expiration <= now + 3300 + 5);

  rc = parse_credentials(ctx, "{\"AccessKeyId\":\"AK\"}");
  assert(rc == -1);
  rc = parse_credentials(ctx, "{\"AccessKeyId\":null,"
                              "\"SecretAccessKey\":\"SK\"}");
  assert(rc == -1);
  rc = parse_credentials(ctx, "not json");
  assert(rc == -1);

  free(ctx);
}

static void test_config(void) {
  pressured_plugin_ctx_t *ctx = calloc(1, sizeof(*ctx));
  assert(ctx);

  reset_ctx(ctx);
  parse_s3_config(
      ctx, "{\"storage\":{\"s3\":{\"bucket\":\"b\",\"region\":\"eu-west-1\","
           "\"prefix\":\"p/\",\"endpoint\":\"http://x:4566\"}}}");
  assert(strcmp(ctx->bucket, "b") == 0);
  assert(strcmp(ctx->region, "eu-west-1") == 0);
  assert(strcmp(ctx->prefix, "p/") == 0);
  assert(strcmp(ctx->endpoint, "http://x:4566") == 0);

  reset_ctx(ctx);
  parse_s3_config(ctx, "{\"bucket\":\"fb\",\"prefix\":\"fp\"}");
  assert(strcmp(ctx->bucket, "fb") == 0);
  assert(strcmp(ctx->prefix, "fp") == 0);
  assert(strcmp(ctx->region, "us-east-1") == 0);
  assert(ctx->endpoint[0] == '\0');

  reset_ctx(ctx);
  parse_s3_config(ctx, "{\"storage\":{\"s3\":{\"bucket\":\"cb\","
                       "/* comment */\"prefix\":\"cp/\",}}}");
  assert(strcmp(ctx->bucket, "cb") == 0);
  assert(strcmp(ctx->prefix, "cp/") == 0);

  reset_ctx(ctx);
  parse_s3_config(ctx, "{\"storage\":{\"s3\":{\"bucket\":null,\"region\":7}}}");
  assert(ctx->bucket[0] == '\0');
  assert(strcmp(ctx->region, "us-east-1") == 0);

  // storage.s3 that is not an object falls back to the flat form.
  reset_ctx(ctx);
  parse_s3_config(ctx, "{\"storage\":{\"s3\":null},\"bucket\":\"fb2\"}");
  assert(strcmp(ctx->bucket, "fb2") == 0);

  free(ctx);
}

int main(void) {
  test_credentials();
  test_config();
  printf("test_s3_credentials: PASSED\n");
  return 0;
}
