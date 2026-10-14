#include "log.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <json-c/json.h>
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

  struct json_object *root = json_object_new_object();
  struct json_object *plugins = json_object_new_object();
  struct json_object *lua = json_object_new_object();
  json_object_object_add(root, "plugins", plugins);
  json_object_object_add(plugins, "lua", lua);
  // timeout_ms 0 disables the limit
  json_object_object_add(
      lua, "timeout_ms",
      json_object_new_int(strcmp(test, "unlimited") == 0 ? 0 : 200));
  json_object_object_add(lua, key, json_object_new_string(value));
  service_registry_t *sr = service_registry_new();
  assert(sr);
  plugin_manager_t *pm = plugin_manager_new(sr);
  assert(pm);
  assert(plugin_manager_load(pm, "./plugins/lua.so",
                             json_object_to_json_string(root)) == 0);
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
  service_registry_free(sr);
  plugin_manager_free(pm);
  json_object_put(root);
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
    const char *marker = strcmp(test, "unlimited") == 0  ? "UNLIMITED_OK"
                         : strcmp(test, "order") == 0    ? "ORDER_OK"
                         : strcmp(test, "fetch") == 0    ? "FETCH_OK"
                         : strcmp(test, "headers") == 0  ? "HEADERS_OK"
                         : strcmp(test, "download") == 0 ? "DOWNLOAD_OK"
                         : strcmp(test, "stream") == 0   ? "STREAM_OK"
                         : strcmp(test, "binary") == 0   ? "BINARY_OK"
                                                         : "BINARY_STREAM_OK";
    assert(strstr(output, marker));
  }
  clean_dir(dir);
  alarm(0);
  return 0;
}
