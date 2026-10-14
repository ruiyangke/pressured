/*
 * pjson Tests
 *
 * Covers what src/pjson.h adds on top of yyjson: the config and API read flag
 * sets, the nesting limit, and reading any JSON number as an integer.
 */

#include "pjson.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool parses(const char *text, yyjson_read_flag flags) {
  yyjson_doc *doc = pj_parse(text, strlen(text), flags, "test");
  yyjson_doc_free(doc);
  return doc != NULL;
}

static void test_config_syntax(void) {
  printf("  config flags accept hand-written syntax... ");
  static const char *lax[] = {
      "{\"v\":1,}",
      "{\"v\":[1,2,],}",
      "{\n// line\n\"v\":1 /* block */}",
      "{'v':'x'}",
      "{\"v\":NaN,\"w\":Infinity,\"x\":-Infinity}",
      "{\"v\":1.,\"w\":+1,\"x\":0x10,\"y\":.5}",
      "\xEF\xBB\xBF{\"v\":1}",
      "{\"v\":\"caf\xE9\"}",
      "{\"v\":\"a\nb\"}",
      "{\"v\":true} trailing bytes",
  };
  for (size_t i = 0; i < sizeof(lax) / sizeof(lax[0]); i++)
    assert(parses(lax[i], PJ_READ_CONFIG));
  printf("ok\n");
}

static void test_api_syntax(void) {
  printf("  API flags are strict except for bad UTF-8... ");
  assert(parses("{\"items\":[{\"a\":1}]}", PJ_READ_API));
  assert(parses("{\"v\":\"caf\xE9\"}", PJ_READ_API));
  assert(!parses("{\"v\":1,}", PJ_READ_API));
  assert(!parses("{\"v\":1} /* c */", PJ_READ_API));
  assert(!parses("{'v':1}", PJ_READ_API));
  assert(!parses("{\"v\":NaN}", PJ_READ_API));
  assert(!parses("{\"v\":1} trailing", PJ_READ_API));
  printf("ok\n");
}

static void test_invalid(void) {
  printf("  invalid documents return NULL... ");
  static const char *bad[] = {"", "{", "[1,2", "not json", "{\"a\":}", "tru"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    assert(!parses(bad[i], PJ_READ_CONFIG));
    assert(!parses(bad[i], PJ_READ_API));
  }
  printf("ok\n");
}

static void test_depth_limit(void) {
  printf("  nesting is limited to 64 levels... ");
  char text[2 * 65 + 1];
  for (int depth = 64; depth <= 65; depth++) {
    memset(text, '[', depth);
    memset(text + depth, ']', depth);
    text[2 * depth] = '\0';
    assert(parses(text, PJ_READ_API) == (depth == 64));
  }
  printf("ok\n");
}

// Parse {"v":<literal>} and read v with pj_int64.
static bool int64_of(const char *literal, int64_t *out) {
  char text[128];
  snprintf(text, sizeof(text), "{\"v\":%s}", literal);
  yyjson_doc *doc = pj_parse(text, strlen(text), PJ_READ_CONFIG, "test");
  assert(doc);
  bool ok = pj_int64(yyjson_obj_get(yyjson_doc_get_root(doc), "v"), out);
  yyjson_doc_free(doc);
  return ok;
}

static void test_int64(void) {
  printf("  pj_int64 reads every JSON number kind... ");
  static const struct {
    const char *literal;
    int64_t expected;
  } numbers[] = {
      {"0", 0},
      {"-7", -7},
      {"9223372036854775807", INT64_MAX},
      {"-9223372036854775808", INT64_MIN},
      {"9223372036854775808", INT64_MAX},
      {"18446744073709551615", INT64_MAX},
      {"1500.7", 1500},
      {"-1.9", -1},
      {"1e300", INT64_MAX},
      {"-1e300", INT64_MIN},
      {"1e400", INT64_MAX},
      {"Infinity", INT64_MAX},
      {"-Infinity", INT64_MIN},
      {"99999999999999999999", INT64_MAX},
  };
  for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
    int64_t n = 42;
    assert(int64_of(numbers[i].literal, &n));
    assert(n == numbers[i].expected);
  }

  static const char *not_numbers[] = {"NaN",  "\"5\"", "\"5000ms\"", "true",
                                      "null", "{}",    "[1]"};
  for (size_t i = 0; i < sizeof(not_numbers) / sizeof(not_numbers[0]); i++) {
    int64_t n = 42;
    assert(!int64_of(not_numbers[i], &n));
    assert(n == 42);
  }
  int64_t n = 42;
  assert(!pj_int64(NULL, &n));
  assert(n == 42);
  printf("ok\n");
}

// Read key from root with pj_int, starting from `start`; returns the result
// and stores whether pj_int succeeded in *ok.
static int int_at(yyjson_val *root, const char *key, int start, bool *ok) {
  int n = start;
  *ok = pj_int(yyjson_obj_get(root, key), &n);
  return n;
}

static void test_int(void) {
  printf("  pj_int clamps to the int range... ");
  const char *text = "{\"a\":1e10,\"b\":-1e10,\"c\":2500,\"d\":\"1\"}";
  yyjson_doc *doc = pj_parse(text, strlen(text), PJ_READ_CONFIG, "test");
  assert(doc);
  yyjson_val *root = yyjson_doc_get_root(doc);
  bool ok = false;
  int n = int_at(root, "a", 0, &ok);
  assert(ok && n == INT_MAX);
  n = int_at(root, "b", 0, &ok);
  assert(ok && n == INT_MIN);
  n = int_at(root, "c", 0, &ok);
  assert(ok && n == 2500);
  n = int_at(root, "d", 7, &ok);
  assert(!ok && n == 7);
  n = int_at(root, "missing", 7, &ok);
  assert(!ok && n == 7);
  yyjson_doc_free(doc);
  printf("ok\n");
}

int main(void) {
  log_init(LOG_ERROR);
  printf("=== pjson Tests ===\n\n");

  test_config_syntax();
  test_api_syntax();
  test_invalid();
  test_depth_limit();
  test_int64();
  test_int();

  printf("\nAll pjson tests passed\n");
  return 0;
}
