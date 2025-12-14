# pressured

A lightweight, pluggable pre-OOM watcher for Kubernetes. Monitors memory pressure in containers and triggers configurable actions before catastrophic OOM kills occur.

## Features

- **Predictive monitoring** - Configurable warn/critical thresholds with hysteresis
- **Dual-mode operation** - Sidecar (cgroup) or cluster-wide (kubelet) monitoring
- **Plugin architecture** - Extensible via dynamic shared libraries
- **Lua scripting** - Custom event handlers without recompilation
- **Cloud storage** - Stream heap dumps to S3 or local filesystem
- **pprof analysis** - Analyze Go heap profiles to identify memory hogs
- **Minimal footprint** - 3.4MB container image, low CPU/memory overhead

## Quick Start

### Sidecar Mode

Add pressured as a sidecar container:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
    - name: app
      image: my-app:latest
      resources:
        limits:
          memory: 512Mi
    - name: pressured
      image: ghcr.io/ruiyangke/pressured:latest
      args: ["-l", "info"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      resources:
        limits:
          cpu: 50m
          memory: 32Mi
        requests:
          cpu: 10m
          memory: 16Mi
      volumeMounts:
        - name: cgroup
          mountPath: /sys/fs/cgroup
          readOnly: true
  volumes:
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
        type: Directory
```

### Cluster Mode

Deploy with Helm for cluster-wide monitoring:

```bash
helm install pressured charts/pressured \
  --set mode=cluster \
  --set rbac.create=true
```

## Installation

### From Source

Prerequisites: CMake 3.16+, C11 compiler, libcurl, json-c, lua5.4, OpenSSL or mbedTLS

```bash
# Build
make build

# Run
./build/pressured -c config.json -l debug
```

### Docker

```bash
docker pull ghcr.io/ruiyangke/pressured:latest

# Image size: 3.4MB
docker images ghcr.io/ruiyangke/pressured:latest
```

### Helm

```bash
# From local chart
helm install pressured charts/pressured
```

## Configuration

Configuration is JSON-based. Create a `config.json`:

```json
{
  "source": {
    "mode": "cgroup",
    "poll_interval_ms": 1000,
    "cgroup": {
      "path": "/sys/fs/cgroup"
    }
  },
  "thresholds": {
    "warn_percent": 70,
    "critical_percent": 85,
    "hysteresis_percent": 5,
    "cooldown_seconds": 60
  },
  "dry_run": false,
  "log_level": "info"
}
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `source.mode` | `cgroup` | `cgroup` (sidecar) or `kubelet` (cluster) |
| `poll_interval_ms` | `1000` | Sampling interval in milliseconds |
| `warn_percent` | `70` | Warning threshold (% of memory limit) |
| `critical_percent` | `85` | Critical threshold (% of memory limit) |
| `hysteresis_percent` | `5` | Band to prevent event flapping |
| `cooldown_seconds` | `60` | Minimum seconds between events per container |
| `dry_run` | `false` | Log-only mode, no action dispatch |

### Command-line Options

```
pressured [options]
  -c, --config <path>     Config file path (JSON)
  -l, --log-level <level> Log level (trace, debug, info, warn, error)
  -d, --dry-run           Dry run mode
  -h, --help              Show help
  -v, --version           Show version
```

## Plugins

Plugins are loaded from `PRESSURED_PLUGIN_DIR`. Each plugin registers services with the service registry.

### Lua Action Plugin

Execute Lua scripts on memory pressure events:

```lua
function on_event(event, ctx)
  if event.severity == "critical" then
    log.warn("CRITICAL: " .. event.namespace .. "/" .. event.pod_name)
    -- Trigger heap dump, send alert, etc.
  end
end
```

**Lua API:**
- `log.trace/debug/info/warn/error(msg)` - Logging
- `http.fetch(url, opts)` - HTTP requests
- `storage.write/read/remove/exists(key)` - Storage operations
- `event` - Current memory event data
- `config` - Full configuration

### Storage Plugins

Stream data to cloud storage with minimal memory footprint:

| Backend | Plugin | Priority | Auth |
|---------|--------|----------|------|
| AWS S3 | `s3-storage.so` | 100 | IAM, IRSA, static credentials |
| Local | `local-storage.so` | 50 | Filesystem |

S3 configuration example:

```yaml
storage:
  enabled: true
  backend: s3
  s3:
    bucket: "my-bucket"
    region: "us-west-2"
    prefix: "oom-dumps/"
```

### pprof Analyzer Plugin

The pprof plugin provides a C service for parsing Go heap profiles. It reads gzip-compressed pprof data from storage and identifies top memory-consuming functions. This is used internally for heap profile analysis after profiles are captured via HTTP.

## Kubernetes Deployment

### Pod Annotations

Pressured supports per-pod threshold overrides via annotations. These are evaluated by the core event generator:

| Annotation | Description | Example |
|------------|-------------|---------|
| `pressured.io/warn-percent` | Override warn threshold (% of memory limit) | `"70"` |
| `pressured.io/critical-percent` | Override critical threshold (% of memory limit) | `"85"` |
| `pressured.io/cooldown-seconds` | Override cooldown between events | `"120"` |

Example pod with custom thresholds:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-hungry-app
  annotations:
    # This pod needs higher thresholds due to its memory pattern
    pressured.io/warn-percent: "80"
    pressured.io/critical-percent: "95"
    pressured.io/cooldown-seconds: "30"
spec:
  containers:
    - name: app
      image: my-app:latest
      resources:
        limits:
          memory: 2Gi
```

The bundled pprof example script also uses these annotations:

| Annotation | Description | Example |
|------------|-------------|---------|
| `pressured.io/pprof-enabled` | Enable/disable pprof collection for this pod | `"true"`, `"false"` |
| `pressured.io/pprof-port` | Override pprof port (default: 6060) | `"8080"` |
| `pressured.io/pprof-path` | Override pprof heap path | `"/debug/pprof/heap"` |

Custom annotations can be read in Lua scripts:

```lua
function on_event(event, ctx)
  -- Read custom annotation (annotations are a table keyed by name)
  local custom_action = event.annotations and event.annotations["myapp.io/oom-action"]

  if custom_action == "restart" then
    -- Custom logic
  end
end
```

### Cluster Mode with IRSA (AWS EKS)

For S3 storage with IAM Roles for Service Accounts:

```yaml
# values.yaml
mode: cluster
replicaCount: 1

serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/pressured-s3-role

rbac:
  create: true

storage:
  enabled: true
  backend: s3
  s3:
    bucket: "heap-dumps"
    region: "us-west-2"
    prefix: "oom-dumps/"
```

### Complete Helm Values Example

```yaml
mode: cluster
replicaCount: 1

image:
  repository: ghcr.io/ruiyangke/pressured
  # tag defaults to chart appVersion if not set
  pullPolicy: IfNotPresent

serviceAccount:
  create: true
  annotations:
    # For AWS IRSA (S3 storage)
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/pressured-role

rbac:
  create: true

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]

resources:
  limits:
    cpu: 200m
    memory: 256Mi
  requests:
    cpu: 50m
    memory: 64Mi

config:
  source:
    kubelet:
      poll_interval_ms: 5000
      namespace_filter: "default,production"
      label_selector: "app.kubernetes.io/managed-by=pressured"
  thresholds:
    warn_percent: 70
    critical_percent: 85
    hysteresis_percent: 5
    cooldown_seconds: 60
  log_level: info

lua:
  enabled: true
  scripts:
    alert.lua: |
      function on_event(event, ctx)
        if event.severity == "critical" then
          log.error(string.format("CRITICAL: %s/%s at %.0f%%",
            event.namespace, event.pod_name, event.usage_percent))

          -- Trigger heap dump for Go applications (requires pod_ip and pprof port)
          if event.pod_ip then
            local pprof_url = "http://" .. event.pod_ip .. ":6060/debug/pprof/heap"
            local resp = http.fetch(pprof_url, {
              method = "GET",
              timeout_ms = 5000
            })
            if resp.status == 200 then
              storage.write(event.pod_name .. "/heap-" .. os.time() .. ".pb.gz", resp.body)
            end
          end
        end
        return "ok"
      end

storage:
  enabled: true
  backend: s3
  s3:
    bucket: "heap-dumps"
    region: "us-west-2"
    prefix: "oom-dumps/"

podDisruptionBudget:
  enabled: true
  minAvailable: 1

topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: pressured
```

### RBAC Requirements (Cluster Mode)

```yaml
rules:
- apiGroups: [""]
  resources: ["nodes", "pods", "events"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get"]
```

## Development

### Prerequisites

- CMake 3.16+
- C11 compiler
- libcurl, json-c, lua5.4, zlib
- OpenSSL or mbedTLS (for S3 signing)

### Build

```bash
make build          # Debug build
make build-release  # Release build
make test           # Run tests
make test-valgrind  # Memory leak testing
make lint           # Static analysis
make format         # Format code
make docker         # Build Docker image
```

### Project Structure

```
pressured/
├── src/                  # Core source
│   ├── main.c           # Entry point, event loop
│   ├── config.c         # Configuration parsing
│   ├── cgroup.c         # Cgroup v1/v2 monitoring
│   ├── kubelet.c        # Kubernetes API integration
│   ├── event_generator.c # Threshold logic
│   └── service_registry.c # Plugin service management
├── include/             # Public headers
├── plugins/
│   ├── lua/            # Lua scripting plugin
│   ├── storage/        # Storage backends (local, S3)
│   └── pprof/          # Heap profile analyzer
├── charts/pressured/   # Helm chart
└── scripts/            # Build and test scripts
```

### Docker Image

The production image uses a multi-stage build with:
- **mbedTLS** instead of OpenSSL for smaller crypto footprint
- **Minimal curl** built from source with only HTTP/HTTPS
- **Scratch base** for minimal attack surface
- **Final size: 3.4MB**

```bash
# Build locally
make docker

# Verify size
docker images ghcr.io/ruiyangke/pressured:latest
```

## License

MIT
