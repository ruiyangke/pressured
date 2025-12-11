#include "internal.h"
#include "log.h"
#include "plugin.h"
#include "plugin_manager.h"
#include "pressured.h"
#include "service_registry.h"
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int running = 1;

static void signal_handler(int sig) {
  (void)sig;
  running = 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s [options]\n", program);
  printf("\nOptions:\n");
  printf("  -c, --config <path>     Config file path (JSON)\n");
  printf("  -l, --log-level <level> Log level (trace, debug, info, warn, "
         "error)\n");
  printf("  -d, --dry-run           Dry run mode\n");
  printf("  -h, --help              Show this help\n");
  printf("  -v, --version           Show version\n");
}

int main(int argc, char *argv[]) {
  const char *config_path = NULL;
  const char *log_level = "info";
  int dry_run = 0;

  static struct option long_options[] = {
      {"config", required_argument, 0, 'c'},
      {"log-level", required_argument, 0, 'l'},
      {"dry-run", no_argument, 0, 'd'},
      {"help", no_argument, 0, 'h'},
      {"version", no_argument, 0, 'v'},
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "c:l:dhv", long_options, NULL)) != -1) {
    switch (opt) {
    case 'c':
      config_path = optarg;
      break;
    case 'l':
      log_level = optarg;
      break;
    case 'd':
      dry_run = 1;
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    case 'v':
      printf("pressured %s\n", PRESSURED_VERSION);
      return 0;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  // Initialize logging
  log_set_level_str(log_level);
  log_info("pressured %s starting", PRESSURED_VERSION);

  // Load configuration
  pressured_config_t *config = pressured_config_load(config_path);
  if (!config) {
    log_error("failed to load configuration");
    return 1;
  }

  if (dry_run) {
    config->dry_run = true;
  }

  // Set up signal handlers
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Initialize source based on mode
  cgroup_source_t *cgroup_source = NULL;
  kubelet_source_t *kubelet_source = NULL;

  if (config->source_mode == SOURCE_MODE_KUBELET) {
    log_info("using kubelet source (cluster mode)");
    kubelet_source = kubelet_source_new();
    if (!kubelet_source) {
      log_error("failed to create kubelet source");
      pressured_config_free(config);
      return 1;
    }

    // Apply filters
    if (config->namespace_filter) {
      kubelet_set_namespace_filter(kubelet_source, config->namespace_filter);
    }
    if (config->label_selector) {
      kubelet_set_label_selector(kubelet_source, config->label_selector);
    }

    // Initialize (discover nodes, cache pod limits)
    if (kubelet_source_init(kubelet_source) != 0) {
      log_error("failed to initialize kubelet source");
      kubelet_source_free(kubelet_source);
      pressured_config_free(config);
      return 1;
    }
  } else {
    log_info("using cgroup source (sidecar mode)");
    cgroup_source = cgroup_source_new(config->cgroup_path);
    if (!cgroup_source) {
      log_error("failed to create cgroup source");
      pressured_config_free(config);
      return 1;
    }
  }

  event_generator_t *event_gen =
      event_generator_new(config->warn_percent, config->critical_percent,
                          config->hysteresis_percent, config->cooldown_seconds);
  if (!event_gen) {
    log_error("failed to create event generator");
    if (cgroup_source)
      cgroup_source_free(cgroup_source);
    if (kubelet_source)
      kubelet_source_free(kubelet_source);
    pressured_config_free(config);
    return 1;
  }

  // Create service registry
  service_registry_t *registry = service_registry_new();
  if (!registry) {
    log_error("failed to create service registry");
    event_generator_free(event_gen);
    if (cgroup_source)
      cgroup_source_free(cgroup_source);
    if (kubelet_source)
      kubelet_source_free(kubelet_source);
    pressured_config_free(config);
    return 1;
  }

  // Create plugin manager with service registry
  plugin_manager_t *plugin_mgr = plugin_manager_new(registry);
  if (!plugin_mgr) {
    log_error("failed to create plugin manager");
    service_registry_free(registry);
    event_generator_free(event_gen);
    if (cgroup_source)
      cgroup_source_free(cgroup_source);
    if (kubelet_source)
      kubelet_source_free(kubelet_source);
    pressured_config_free(config);
    return 1;
  }

  char *config_json = NULL;
  const char *plugin_dir = getenv("PRESSURED_PLUGIN_DIR");
  if (plugin_dir) {
    // Load raw config JSON for plugins
    config_json = pressured_config_load_json(config_path);
    // Load and initialize all plugins with config
    plugin_manager_load_dir(plugin_mgr, plugin_dir, config_json);
  }

  // Initialize all singleton services (lock-free after this)
  if (service_registry_init_all(registry) != 0) {
    log_warn("some services failed to initialize");
  }

  log_info("starting main loop poll_interval=%dms dry_run=%s mode=%s",
           config->poll_interval_ms, config->dry_run ? "true" : "false",
           config->source_mode == SOURCE_MODE_KUBELET ? "kubelet" : "cgroup");

  // Main loop
  while (running) {
    // Collect samples from appropriate source
    int sample_count = 0;
    pressured_memory_sample_t *samples = NULL;

    if (config->source_mode == SOURCE_MODE_KUBELET) {
      samples = kubelet_collect(kubelet_source, &sample_count);
    } else {
      samples = cgroup_collect(cgroup_source, &sample_count);
    }

    if (samples && sample_count > 0) {
      // Analyze samples
      int event_count = 0;
      pressured_event_t *events = event_generator_process(
          event_gen, samples, sample_count, &event_count);

      // Process events
      for (int i = 0; i < event_count; i++) {
        const pressured_event_t *event = &events[i];

        // Log event as JSON
        log_event_json(event->sample.namespace, event->sample.pod_name,
                       event->sample.container_name, event->sample.pod_ip,
                       pressured_severity_str(event->severity),
                       event->sample.usage_percent, event->sample.usage_bytes,
                       event->sample.limit_bytes);

        // Dispatch to ALL action services
        size_t action_count = service_registry_count(registry, "action");
        if (action_count > 0) {
          service_ref_t *refs = calloc(action_count, sizeof(service_ref_t));
          if (refs) {
            size_t acquired = service_registry_acquire_all(registry, "action",
                                                           refs, action_count);

            for (size_t j = 0; j < acquired; j++) {
              if (service_ref_valid(&refs[j])) {
                action_t *action = (action_t *)refs[j].instance;
                if (action && action->on_event) {
                  action->on_event(action, event, config->dry_run);
                }
                service_ref_release(&refs[j]);
              }
            }
            free(refs);
          }
        }
      }

      event_generator_events_free(events, event_count);
    }

    // Free samples (both sources return the same type)
    if (samples) {
      for (int i = 0; i < sample_count; i++) {
        pressured_memory_sample_free(&samples[i]);
      }
      free(samples);
    }

    // Sleep until next poll
    usleep(config->poll_interval_ms * 1000);
  }

  log_info("shutting down");

  // Cleanup - service registry must be freed before plugin manager
  // (service destructors need to run while plugin code is still loaded)
  service_registry_free(registry);
  plugin_manager_free(plugin_mgr);
  free(config_json);
  event_generator_free(event_gen);
  if (cgroup_source)
    cgroup_source_free(cgroup_source);
  if (kubelet_source)
    kubelet_source_free(kubelet_source);
  pressured_config_free(config);

  return 0;
}
