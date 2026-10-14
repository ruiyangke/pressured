#include "log.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void) {
  struct timespec ts;
  assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

typedef struct {
  int listener;
  unsigned port;
  const char *mode;
  pthread_t thread;
  char recorded[8192];
  size_t recorded_len;
} server_t;

static void send_all(int fd, const void *data, size_t len) {
  const char *p = data;
  while (len) {
    ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
    assert(n > 0);
    p += n;
    len -= n;
  }
}

static void *serve(void *arg) {
  server_t *s = arg;
  int timeout_ms = -1; // Block for the first connection.
  while (1) {
    struct pollfd lfd = {.fd = s->listener, .events = POLLIN};
    if (poll(&lfd, 1, timeout_ms) <= 0)
      break;
    int fd = accept(s->listener, NULL, NULL);
    assert(fd >= 0);
    char request[4096] = {0};
    size_t used = 0;
    char *body = NULL;
    while (!body) {
      ssize_t n = recv(fd, request + used, sizeof(request) - used - 1, 0);
      assert(n > 0);
      used += n;
      body = strstr(request, "\r\n\r\n");
    }
    body += 4;
    // Record the request line and headers for assertions after the server
    // stops.
    size_t req_len = (size_t)(body - request);
    if (s->recorded_len + req_len < sizeof(s->recorded)) {
      memcpy(s->recorded + s->recorded_len, request, req_len);
      s->recorded_len += req_len;
      s->recorded[s->recorded_len] = '\0';
    }
    if (strcmp(s->mode, "binary") == 0) {
      const char expected[] = {'a', '\0', 'b', '\0', 'c'};
      char *length = strstr(request, "Content-Length:");
      assert(length);
      unsigned long content_length =
          strtoul(length + strlen("Content-Length:"), NULL, 10);
      assert(content_length == sizeof(expected));
      size_t header_len = (size_t)(body - request);
      while (used - header_len < sizeof(expected)) {
        ssize_t n = recv(fd, request + used, sizeof(request) - used, 0);
        assert(n > 0);
        used += n;
      }
      assert(used - header_len == sizeof(expected));
      assert(memcmp(body, expected, sizeof(expected)) == 0);
      const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                              "Connection: close\r\n\r\n";
      send_all(fd, response, sizeof(response) - 1);
      send_all(fd, expected, sizeof(expected));
    } else if (strcmp(s->mode, "headers") == 0) {
      const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                              "Connection: close\r\n\r\nok";
      send_all(fd, response, sizeof(response) - 1);
    } else {
      if (strcmp(s->mode, "stream") == 0) {
        const char response[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            "\r\n4\r\ndata\r\n";
        send_all(fd, response, sizeof(response) - 1);
      }
      // Keep the connection open until the client aborts its request.
      struct pollfd pfd = {.fd = fd, .events = POLLIN};
      assert(poll(&pfd, 1, 2000) > 0);
      char byte;
      assert(recv(fd, &byte, 1, 0) <= 0);
    }
    close(fd);
    // The "headers" case opens several connections; the rest open one.
    if (strcmp(s->mode, "headers") != 0)
      break;
    timeout_ms = 100; // Briefly wait for the next connection.
  }
  return NULL;
}

static void start_server(server_t *s, const char *mode) {
  s->mode = mode;
  s->listener = socket(AF_INET, SOCK_STREAM, 0);
  assert(s->listener >= 0);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  assert(bind(s->listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  assert(getsockname(s->listener, (struct sockaddr *)&addr, &len) == 0);
  s->port = ntohs(addr.sin_port);
  assert(listen(s->listener, 1) == 0);
  assert(pthread_create(&s->thread, NULL, serve, s) == 0);
}

static void stop_server(server_t *s) {
  assert(pthread_join(s->thread, NULL) == 0);
  close(s->listener);
}

static void write_script(const char *dir, const char *name, const char *code) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", dir, name);
  FILE *f = fopen(path, "w");
  assert(f);
  int rc = fputs(code, f);
  assert(rc >= 0);
  rc = fclose(f);
  assert(rc == 0);
}

static void clean_dir(const char *path) {
  DIR *dir = opendir(path);
  assert(dir);
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    if (entry->d_name[0] == '.')
      continue;
    char file[512];
    snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
    assert(unlink(file) == 0);
  }
  closedir(dir);
  assert(rmdir(path) == 0);
}

// Append `value` to `buf` at *off as the body of a JSON string (no surrounding
// quotes), escaping '"', '\\' and bytes below 0x20 as \u00XX. The caller must
// leave enough room: `size` bounds every write.
static void json_escape(char *buf, size_t size, size_t *off,
                        const char *value) {
  for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
    char piece[8];
    if (*p == '"' || *p == '\\') {
      piece[0] = '\\';
      piece[1] = (char)*p;
      piece[2] = '\0';
    } else if (*p < 0x20) {
      snprintf(piece, sizeof(piece), "\\u%04x", *p);
    } else {
      piece[0] = (char)*p;
      piece[1] = '\0';
    }
    int n = snprintf(buf + *off, size - *off, "%s", piece);
    assert(n > 0 && (size_t)n < size - *off);
    *off += (size_t)n;
  }
}

int main(int argc, char **argv) {
  assert(argc == 2);
  alarm(3);
  log_init(LOG_DEBUG);
  const char *test = argv[1];
  char log_path[128];
  snprintf(log_path, sizeof(log_path), "lua-timeout-%s.log", test);
  FILE *logs = fopen(log_path, "w+");
  assert(logs);
  int saved_stderr = dup(STDERR_FILENO);
  assert(saved_stderr >= 0);
  assert(dup2(fileno(logs), STDERR_FILENO) >= 0);

  char dir[] = "./lua-timeout-XXXXXX";
  assert(mkdtemp(dir));
  char code[4096];
  const char *key = "inline_script";
  const char *value = code;
  server_t server = {0};
  int has_server = 0;
  int load_timeout = strncmp(test, "load_", 5) == 0;
  if (strcmp(test, "handler") == 0) {
    snprintf(code, sizeof(code),
             "local first = true; function on_event(e,c) "
             "if first then first=false; while true do end end "
             "assert(e.pod_name=='timeout-test' and c.dry_run); "
             "log.info('FAST_OK'); return 'ok' end");
  } else if (strcmp(test, "dispatch") == 0) {
    key = "scripts_dir";
    value = dir;
    write_script(dir, "a.lua",
                 "function on_event(e,c) e.shared=42; "
                 "c.shared=43; while true do end end");
    write_script(dir, "b.lua",
                 "function on_event(e,c) "
                 "assert(e.shared==42 and c.shared==43); "
                 "local t=os.clock(); "
                 "while os.clock()-t < 0.05 do end; "
                 "log.info('SECOND_OK'); return 'ok' end");
  } else if (strcmp(test, "unlimited") == 0) {
    snprintf(code, sizeof(code),
             "function on_event(e,c) local t=os.clock(); "
             "while os.clock()-t < 0.05 do end; "
             "log.info('UNLIMITED_OK'); return 'ok' end");
  } else if (strcmp(test, "order") == 0) {
    key = "scripts_dir";
    value = dir;
    for (int i = 11; i >= 0; i--) {
      char name[32];
      snprintf(name, sizeof(name), "%02d.lua", i);
      snprintf(code, sizeof(code),
               "assert((loaded or 0)==%d); loaded=%d; "
               "function on_event(e,c) assert((e.order or 0)==%d); "
               "e.order=%d; if e.order==12 then log.info('ORDER_OK') end end",
               i, i + 1, i, i + 1);
      write_script(dir, name, code);
    }
  } else if (strncmp(test, "handlers_", 9) == 0) {
    key = "scripts_dir";
    value = dir;
    write_script(dir, "a.lua",
                 "function on_event(e,c) "
                 "assert(e.order==nil); e.order=1; "
                 "_pressured_handlers=42; return 'FIRST_OK' end");
    if (strcmp(test, "handlers_reassigned") == 0) {
      write_script(dir, "b.lua",
                   "_pressured_handlers=42; "
                   "function on_event(e,c) assert(e.order==1); "
                   "return 'SECOND_OK' end");
    } else if (strcmp(test, "handlers_reassigned_after_load") == 0) {
      write_script(dir, "b.lua",
                   "function on_event(e,c) assert(e.order==1); "
                   "return 'SECOND_OK' end");
    } else {
      assert(strcmp(test, "handlers_junk") == 0);
      write_script(dir, "b.lua",
                   "table.insert(_pressured_handlers,42); "
                   "table.insert(_pressured_handlers,{name='bad.lua',"
                   "func=setmetatable({}, {__call=function() "
                   "log.info('BAD_CALLED') end})}); "
                   "function on_event(e,c) assert(e.order==1); "
                   "return 'SECOND_OK' end");
    }
  } else if (strcmp(test, "config_types") == 0) {
    // Pins json_to_lua(): the Lua type each JSON value becomes.
    // JSON null becomes nil, and empty arrays/objects both become empty tables.
    snprintf(
        code, sizeof(code),
        "local cfg = config.plugins.lua; "
        "assert(type(cfg.int)=='number' and math.type(cfg.int)=='integer' "
        "and cfg.int==42); "
        "assert(type(cfg.big)=='number' and math.type(cfg.big)=='integer' "
        "and cfg.big==9007199254740993); "
        "assert(type(cfg.float)=='number' and math.type(cfg.float)=='float' "
        "and cfg.float==1.5); "
        "assert(type(cfg.float_zero)=='number' "
        "and math.type(cfg.float_zero)=='float' and cfg.float_zero==2.0); "
        "assert(type(cfg.bool_true)=='boolean' and cfg.bool_true==true); "
        "assert(type(cfg.bool_false)=='boolean' and cfg.bool_false==false); "
        "assert(type(cfg.null_val)=='nil' and cfg.null_val==nil); "
        "assert(type(cfg.nested)=='table' and cfg.nested.inner=='x' "
        "and cfg.nested.num==7 and math.type(cfg.nested.num)=='integer'); "
        "assert(type(cfg.mixed)=='table' and #cfg.mixed==4 "
        "and cfg.mixed[1]==1 and math.type(cfg.mixed[1])=='integer' "
        "and cfg.mixed[2]==2.5 and math.type(cfg.mixed[2])=='float' "
        "and cfg.mixed[3]=='three' and cfg.mixed[4]==true); "
        "assert(type(cfg.empty_obj)=='table' and next(cfg.empty_obj)==nil); "
        "assert(type(cfg.empty_arr)=='table' and #cfg.empty_arr==0); "
        "assert(type(cfg.unicode)=='string' and cfg.unicode=='\\xc3\\xa9'); "
        "assert(cfg['k\\0ey']==7); "
        "assert(type(cfg.huge)=='number' and math.type(cfg.huge)=='integer' "
        "and cfg.huge==math.maxinteger); "
        "assert(type(cfg.nul)=='string' and #cfg.nul==3); "
        "assert(cfg.dup==2); "
        "local d=cfg.deep; for i=1,60 do d=d.d end; assert(d==1); "
        "log.info('CONFIG_TYPES_OK'); "
        "function on_event(e,c) return 'ok' end");
  } else if (load_timeout) {
    snprintf(code, sizeof(code), "while true do end");
    if (strcmp(test, "load_file") == 0) {
      write_script(dir, "loop.lua", code);
      snprintf(code, sizeof(code), "%s/loop.lua", dir);
      key = "script";
    } else if (strcmp(test, "load_dir") == 0) {
      write_script(dir, "loop.lua", code);
      key = "scripts_dir";
      value = dir;
    } else {
      assert(strcmp(test, "load_inline") == 0);
    }
  } else {
    const char *mode = strcmp(test, "stream") == 0       ? "stream"
                       : strcmp(test, "headers") == 0    ? "headers"
                       : strncmp(test, "binary", 6) == 0 ? "binary"
                                                         : "fetch";
    start_server(&server, mode);
    has_server = 1;
    char call[2048];
    if (strcmp(test, "fetch") == 0) {
      snprintf(call, sizeof(call),
               "local r=http.fetch('GET',url); assert(r.error); "
               "log.info('FETCH_OK')");
    } else if (strcmp(test, "headers") == 0) {
      snprintf(call, sizeof(call),
               "local many={} for i=1,65 do many[i]='X-H'..i..': v' end; "
               "local r=http.fetch('GET',url,{headers=many}); "
               "assert(r.error and r.error:find('too many headers')); "
               "local s=http.stream(url,function() return true end,"
               "{headers=many}); "
               "assert(s.ok==false and s.error:find('too many headers')); "
               "local n=http.fetch('GET',url,{headers={'X-A: 1',42}}); "
               "assert(n.error and n.error:find('not a string')); "
               "local ns=http.stream(url,function() return true end,"
               "{headers={'X-A: 1',42}}); "
               "assert(ns.ok==false and ns.error:find('not a string')); "
               "local b=http.fetch('POST',url,{body=12345}); "
               "assert(b.error and b.error:find('body must be a string')); "
               "local ok={} for i=1,64 do ok[i]='X-H'..i..': v' end; "
               "local f=http.fetch('GET',url,{headers=ok}); "
               "assert(not f.error and f.status==200); "
               "local r2=http.fetch('GET',url,"
               "{headers={'X-A: 1','X-B: 2'}}); "
               "assert(not r2.error and r2.status==200); "
               "log.info('HEADERS_OK')");
    } else if (strcmp(test, "download") == 0) {
      snprintf(call, sizeof(call),
               "local r=http.download(url,'%s/download'); "
               "assert(not r.ok and r.error); log.info('DOWNLOAD_OK')",
               dir);
    } else if (strcmp(test, "stream") == 0) {
      snprintf(call, sizeof(call),
               "local r=http.stream(url,function(chunk) "
               "assert(chunk=='data'); while true do end end); "
               "assert(r.ok==false and r.error:find('timeout after 200 ms')); "
               "local f=http.fetch('GET',url); "
               "assert(f.error:find('timeout after 200 ms')); "
               "local s=http.stream(url,function() return true end); "
               "assert(s.ok==false and s.error:find('timeout after 200 ms')); "
               "local d=http.download(url,'unused-download'); "
               "assert(d.ok==false and d.error:find('timeout after 200 ms')); "
               "log.info('STREAM_OK')");
    } else if (strcmp(test, "binary") == 0) {
      snprintf(call, sizeof(call),
               "local body='a'..string.char(0)..'b'..string.char(0)..'c'; "
               "local r=http.fetch('POST',url,{body=body}); "
               "assert(not r.error and r.status==200 and r.body==body); "
               "log.info('BINARY_OK')");
    } else {
      assert(strcmp(test, "binary_stream") == 0);
      snprintf(call, sizeof(call),
               "local body='a'..string.char(0)..'b'..string.char(0)..'c'; "
               "local got=''; local r=http.stream(url,function(chunk) "
               "got=got..chunk; return true end,{method='POST',body=body}); "
               "assert(r.ok and got==body); log.info('BINARY_STREAM_OK')");
    }
    snprintf(code, sizeof(code),
             "function on_event(e,c) "
             "local url='http://127.0.0.1:%u/'; %s; return 'ok' end",
             server.port, call);
  }

  // timeout_ms is written as a real so the plugin must read any JSON number
  // kind, not only integers.
  char config[16384];
  size_t off = 0;
  off +=
      (size_t)snprintf(config + off, sizeof(config) - off,
                       "{\"plugins\":{\"lua\":{\"timeout_ms\":%d.0,\"%s\":\"",
                       strcmp(test, "unlimited") == 0 ? 0 : 200, key);
  json_escape(config, sizeof(config), &off, value);
  off += (size_t)snprintf(config + off, sizeof(config) - off, "\"");
  if (strcmp(test, "config_types") == 0) {
    // Hand-written syntax: a comment and a trailing comma inside plugins.lua.
    off += (size_t)snprintf(config + off, sizeof(config) - off,
                            ",\"int\":42,\"big\":9007199254740993,"
                            "\"float\":1.5,\"float_zero\":2.0,"
                            "\"bool_true\":true,\"bool_false\":false,"
                            "\"null_val\":null,"
                            "\"nested\":{\"inner\":\"x\",\"num\":7},"
                            "\"mixed\":[1,2.5,\"three\",true],"
                            "\"empty_obj\":{},\"empty_arr\":[],"
                            "\"unicode\":\"\\u00e9\",\"k\\u0000ey\":7,"
                            "/* comment */"
                            "\"huge\":18446744073709551615,"
                            "\"nul\":\"a\\u0000b\","
                            "\"dup\":1,\"dup\":2,"
                            "\"deep\":");
    for (int i = 0; i < 60; i++)
      off += (size_t)snprintf(config + off, sizeof(config) - off, "{\"d\":");
    off += (size_t)snprintf(config + off, sizeof(config) - off, "1");
    for (int i = 0; i < 60; i++)
      off += (size_t)snprintf(config + off, sizeof(config) - off, "}");
    off += (size_t)snprintf(config + off, sizeof(config) - off, ",");
  }
  off += (size_t)snprintf(config + off, sizeof(config) - off, "}}}");
  service_registry_t *sr = service_registry_new();
  assert(sr);
  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm);
  assert(plugin_manager_load(pm, "./plugins/lua.so", config) == 0);
  double start = now_ms();
  service_registry_init_all(sr);
  service_ref_t ref = service_registry_acquire(sr, "action");
  if (load_timeout) {
    assert(!service_ref_valid(&ref));
    // The registry may retry the failed factory when explicitly acquired.
    assert(now_ms() - start < 850);
  } else {
    assert(service_ref_valid(&ref));
    action_t *action = ref.instance;
    pressured_event_t event = {.event_type = EVENT_TYPE_MEMORY_PRESSURE,
                               .sample = {.namespace = "test",
                                          .pod_name = "timeout-test",
                                          .container_name = "test"}};
    start = now_ms();
    int rc = action->on_event(action, &event, 1);
    double elapsed = now_ms() - start;
    printf("%s: %.1f ms\n", test, elapsed);
    assert(elapsed < 400);
    if (strcmp(test, "handler") == 0) {
      assert(rc == -1);
      start = now_ms();
      assert(action->on_event(action, &event, 1) == 0);
      assert(now_ms() - start < 100);
    } else {
      assert(rc == 0);
      if (strncmp(test, "handlers_", 9) == 0)
        assert(action->on_event(action, &event, 1) == 0);
    }
    service_ref_release(&ref);
  }
  if (has_server)
    stop_server(&server);
  // The "headers" case must have sent every header, including the last one.
  if (strcmp(test, "headers") == 0)
    assert(strstr(server.recorded, "X-H64: v"));
  service_registry_free(sr);
  plugin_manager_free(pm);
  fflush(stderr);
  assert(dup2(saved_stderr, STDERR_FILENO) >= 0);
  close(saved_stderr);
  rewind(logs);
  char output[32768] = {0};
  size_t read_count = fread(output, 1, sizeof(output) - 1, logs);
  assert(read_count > 0);
  fclose(logs);
  fputs(output, stderr);
  if (load_timeout || strcmp(test, "handler") == 0 ||
      strcmp(test, "dispatch") == 0)
    assert(strstr(output, "timeout after 200 ms"));
  if (strcmp(test, "handler") == 0)
    assert(strstr(output, "FAST_OK"));
  else if (strcmp(test, "dispatch") == 0) {
    assert(strstr(output, "[dispatcher] a.lua error:"));
    assert(strstr(output, "SECOND_OK"));
  } else if (strncmp(test, "handlers_", 9) == 0) {
    const char *first = output;
    for (int i = 0; i < 2; i++) {
      first = strstr(first, "[dispatcher] a.lua returned: FIRST_OK");
      assert(first);
      const char *second =
          strstr(first, "[dispatcher] b.lua returned: SECOND_OK");
      assert(second);
      first = second + 1;
    }
    if (strcmp(test, "handlers_junk") == 0) {
      const char *entry_error = output;
      const char *func_error = output;
      for (int i = 0; i < 2; i++) {
        entry_error = strstr(entry_error,
                             "[dispatcher] ? error: handler #2 is not a table");
        func_error = strstr(
            func_error, "[dispatcher] bad.lua error: func is not a function");
        assert(entry_error && func_error);
        entry_error++;
        func_error++;
      }
      assert(!strstr(entry_error,
                     "[dispatcher] ? error: handler #2 is not a table"));
      assert(!strstr(func_error,
                     "[dispatcher] bad.lua error: func is not a function"));
      assert(!strstr(output, "BAD_CALLED"));
    } else {
      assert(!strstr(output, "[dispatcher] ? error:"));
    }
  } else if (!load_timeout) {
    const char *marker = strcmp(test, "unlimited") == 0      ? "UNLIMITED_OK"
                         : strcmp(test, "order") == 0        ? "ORDER_OK"
                         : strcmp(test, "config_types") == 0 ? "CONFIG_TYPES_OK"
                         : strcmp(test, "fetch") == 0        ? "FETCH_OK"
                         : strcmp(test, "headers") == 0      ? "HEADERS_OK"
                         : strcmp(test, "download") == 0     ? "DOWNLOAD_OK"
                         : strcmp(test, "stream") == 0       ? "STREAM_OK"
                         : strcmp(test, "binary") == 0       ? "BINARY_OK"
                                                       : "BINARY_STREAM_OK";
    assert(strstr(output, marker));
  }
  clean_dir(dir);
  alarm(0);
  return 0;
}
