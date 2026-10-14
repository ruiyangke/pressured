/*
 * Config Corpus Characterization Tests
 *
 * Pins the CURRENT behavior of pressured_config_load() (json-c based) and of
 * plugin enable/disable parsing (plugin_is_disabled()) so a later JSON-library
 * swap can be diffed against it. Assertions describe what happens today, not
 * what the JSON spec says.
 *
 * Every case below parses without crashing under json-c 0.18. No case is
 * omitted for crashing.
 *
 * plugin_is_disabled() is static, so include the production file to call it
 * directly (same approach as test_kubelet.c including kubelet.c).
 */

#include "pressured.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "plugin.c"
#pragma GCC diagnostic pop

static char test_dir[64];

// Write the JSON to a temp file, load it, then remove the file.
static pressured_config_t *load_json(const char *name, const char *json) {
  char path[256];
  int n = snprintf(path, sizeof(path), "%s/%s", test_dir, name);
  assert(n > 0 && (size_t)n < sizeof(path));

  FILE *file = fopen(path, "wb");
  assert(file);
  size_t length = strlen(json);
  size_t written = fwrite(json, 1, length, file);
  assert(written == length);
  int closed = fclose(file);
  assert(closed == 0);

  pressured_config_t *config = pressured_config_load(path);
  int removed = unlink(path);
  assert(removed == 0);
  return config;
}

// ─────────────────────────────────────────────────────────────────────────────
// Well-formed and lax syntax
// ─────────────────────────────────────────────────────────────────────────────

static void test_normal_config(void) {
  pressured_config_t *config =
      load_json("normal.json",
                "{\"thresholds\":{\"warn_percent\":80,\"critical_percent\":90,"
                "\"hysteresis_percent\":5,\"cooldown_seconds\":30},"
                "\"source\":{\"mode\":\"kubelet\",\"poll_interval_ms\":2500,"
                "\"cgroup\":{\"path\":\"/my/cgroup\"},"
                "\"kubelet\":{\"namespace_filter\":\"a,b\","
                "\"label_selector\":\"app=x\"}},"
                "\"dry_run\":true,\"log_level\":\"debug\"}");
  assert(config);
  assert(config->source_mode == SOURCE_MODE_KUBELET);
  assert(config->warn_percent == 0.80);
  assert(config->critical_percent == 0.90);
  assert(config->hysteresis_percent == 0.05);
  assert(config->cooldown_seconds == 30);
  assert(strcmp(config->cgroup_path, "/my/cgroup") == 0);
  assert(config->poll_interval_ms == 2500);
  assert(config->namespace_filter &&
         strcmp(config->namespace_filter, "a,b") == 0);
  assert(config->label_selector &&
         strcmp(config->label_selector, "app=x") == 0);
  assert(config->dry_run == true);
  assert(config->log_level && strcmp(config->log_level, "debug") == 0);
  pressured_config_free(config);
}

static void test_comments(void) {
  // json-c accepts // and /* */ comments by default.
  pressured_config_t *config =
      load_json("comments.json",
                "{\n// line comment\n\"thresholds\":{\"warn_percent\":80},\n"
                "/* block */\"dry_run\":true\n}");
  assert(config);
  assert(config->warn_percent == 0.80);
  assert(config->critical_percent == 0.85); // untouched default
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_trailing_comma(void) {
  // json-c accepts trailing commas in objects.
  pressured_config_t *config =
      load_json("trailing_comma.json",
                "{\"thresholds\":{\"warn_percent\":80,},\"dry_run\":true,}");
  assert(config);
  assert(config->warn_percent == 0.80);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_single_quotes(void) {
  // json-c accepts single-quoted strings by default.
  pressured_config_t *config =
      load_json("single_quotes.json",
                "{'thresholds':{'warn_percent':80},'dry_run':true}");
  assert(config);
  assert(config->warn_percent == 0.80);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_raw_newline_in_string(void) {
  // json-c accepts a literal newline inside a string.
  pressured_config_t *config = load_json(
      "raw_newline.json", "{\"source\":{\"cgroup\":{\"path\":\"/a\nb\"}}}");
  assert(config);
  assert(strcmp(config->cgroup_path, "/a\nb") == 0);
  assert(config->warn_percent == 0.70); // untouched default
  assert(config->dry_run == false);     // untouched default
  pressured_config_free(config);
}

static void test_latin1_byte_in_string(void) {
  // A raw Latin-1 byte (0xE9) is passed through unvalidated.
  pressured_config_t *config = load_json(
      "latin1.json", "{\"source\":{\"cgroup\":{\"path\":\"/caf\xE9\"}}}");
  assert(config);
  assert(strcmp(config->cgroup_path, "/caf\xE9") == 0);
  pressured_config_free(config);
}

static void test_trailing_garbage(void) {
  // json-c stops after the first value and ignores trailing bytes.
  pressured_config_t *config =
      load_json("trailing_garbage.json", "{\"dry_run\":true} garbage");
  assert(config);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

// ─────────────────────────────────────────────────────────────────────────────
// Type coercion
// ─────────────────────────────────────────────────────────────────────────────

static void test_numbers_written_as_strings(void) {
  // json-c converts numeric strings; digits are read until a non-digit.
  pressured_config_t *config = load_json(
      "number_strings.json", "{\"thresholds\":{\"warn_percent\":\"80\"},"
                             "\"source\":{\"poll_interval_ms\":\"5000ms\"}}");
  assert(config);
  assert(config->warn_percent == 0.80);
  assert(config->poll_interval_ms == 5000);
  pressured_config_free(config);
}

static void test_float_where_int_expected(void) {
  // json_object_get_int() truncates toward zero.
  pressured_config_t *config =
      load_json("float_int.json", "{\"source\":{\"poll_interval_ms\":1500.7}}");
  assert(config);
  assert(config->poll_interval_ms == 1500);
  pressured_config_free(config);
}

static void test_dry_run_true(void) {
  pressured_config_t *config = load_json("dry_true.json", "{\"dry_run\":true}");
  assert(config);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_dry_run_int_one(void) {
  pressured_config_t *config = load_json("dry_one.json", "{\"dry_run\":1}");
  assert(config);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_dry_run_string_false(void) {
  // The string "false" is truthy: dry_run becomes true.
  pressured_config_t *config =
      load_json("dry_str_false.json", "{\"dry_run\":\"false\"}");
  assert(config);
  assert(config->dry_run == true);
  pressured_config_free(config);
}

static void test_dry_run_null(void) {
  // null is falsy: dry_run stays false.
  pressured_config_t *config = load_json("dry_null.json", "{\"dry_run\":null}");
  assert(config);
  assert(config->dry_run == false);
  pressured_config_free(config);
}

static void test_digit_string_written_as_number(void) {
  // String fields read via json_object_get_string() accept a JSON number and
  // get its serialized digits.
  pressured_config_t *config = load_json(
      "digit_number.json", "{\"source\":{\"cgroup\":{\"path\":123456789012}},"
                           "\"log_level\":123456789012}");
  assert(config);
  assert(strcmp(config->cgroup_path, "123456789012") == 0);
  assert(config->log_level && strcmp(config->log_level, "123456789012") == 0);
  pressured_config_free(config);
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin enable/disable parsing (plugin_is_disabled)
// ─────────────────────────────────────────────────────────────────────────────

static void test_plugin_enabled_values(void) {
  // Only an explicit boolean false (or a falsy JSON value) disables a plugin.
  assert(plugin_is_disabled(
             "lua", "{\"plugins\":{\"lua\":{\"enabled\":false}}}") == 1);
  assert(plugin_is_disabled("lua", "{\"plugins\":{\"lua\":{\"enabled\":0}}}") ==
         1);
  assert(plugin_is_disabled("lua", "{\"plugins\":{\"lua\":{\"enabled\":1}}}") ==
         0);
  // A non-empty string is truthy, even "false".
  assert(plugin_is_disabled(
             "lua", "{\"plugins\":{\"lua\":{\"enabled\":\"false\"}}}") == 0);
  assert(plugin_is_disabled(
             "lua", "{\"plugins\":{\"lua\":{\"enabled\":\"true\"}}}") == 0);
  // null is falsy and therefore disables.
  assert(plugin_is_disabled("lua",
                            "{\"plugins\":{\"lua\":{\"enabled\":null}}}") == 1);
  // Absent field (and absent section) leave the plugin enabled.
  assert(plugin_is_disabled("lua", "{\"plugins\":{\"lua\":{}}}") == 0);
  assert(plugin_is_disabled("lua", "{\"plugins\":{}}") == 0);
  assert(plugin_is_disabled("lua", "{}") == 0);
  // No config at all means enabled.
  assert(plugin_is_disabled("lua", NULL) == 0);
}

int main(void) {
  int n =
      snprintf(test_dir, sizeof(test_dir), "/tmp/test_config_corpus_XXXXXX");
  assert(n > 0 && (size_t)n < sizeof(test_dir));
  char *created = mkdtemp(test_dir);
  assert(created != NULL);

  test_normal_config();
  test_comments();
  test_trailing_comma();
  test_single_quotes();
  test_raw_newline_in_string();
  test_latin1_byte_in_string();
  test_trailing_garbage();
  test_numbers_written_as_strings();
  test_float_where_int_expected();
  test_dry_run_true();
  test_dry_run_int_one();
  test_dry_run_string_false();
  test_dry_run_null();
  test_digit_string_written_as_number();
  test_plugin_enabled_values();

  int removed = rmdir(test_dir);
  assert(removed == 0);
  printf("test_config_corpus: PASSED\n");
  return 0;
}
