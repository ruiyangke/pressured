-- pprof_dump.lua - Stream pprof heap directly to storage
-- Uses http.stream + storage.open for true streaming (no full buffering)
--
-- This script supports both sidecar and cluster modes:
--   - Sidecar mode: connects to 127.0.0.1 (same pod)
--   - Cluster mode: connects to pod_ip from event (requires pprof port exposed)
--
-- Storage path format:
--   events/{event_type}/{timestamp}-{pod_name}-event.json
--   heaps/{event_type}/{timestamp}-{pod_name}-heap.pb.gz
--   goroutines/{event_type}/{timestamp}-{pod_name}-goroutine.txt
--
-- Configuration (via pod annotations, environment variables, or defaults):
--   Pod annotations (highest priority):
--     pressured.io/pprof-enabled: "true" | "false"
--     pressured.io/pprof-port: "6060"
--     pressured.io/pprof-path: "/debug/pprof/heap"
--
--   Environment variables (fallback):
--     PPROF_PORT - pprof endpoint port (default: 8080)
--     PPROF_MODE - "sidecar" or "cluster" (default: cluster)
--
-- Event types handled:
--   memory_pressure - High memory usage detected, captures pprof data
--   oom_killed      - Container was OOM killed, logs event only (process is dead)

-- Default configuration from environment
local DEFAULT_PPROF_PORT = tonumber(ctx.getenv("PPROF_PORT")) or 8080
local DEFAULT_PPROF_PATH = "/debug/pprof/heap"
local PPROF_MODE = ctx.getenv("PPROF_MODE") or "cluster"

-- Helper to safely get annotation value
local function get_annotation(event, key)
    if event.annotations and event.annotations[key] then
        return event.annotations[key]
    end
    return nil
end

-- Get pprof configuration from annotations (with fallback to defaults)
local function get_pprof_config(event)
    local config = {
        enabled = false,  -- Default to disabled; require explicit opt-in
        port = DEFAULT_PPROF_PORT,
        path = DEFAULT_PPROF_PATH,
    }

    -- Only enable pprof if explicitly set to "true"
    local enabled_ann = get_annotation(event, "pressured.io/pprof-enabled")
    if enabled_ann ~= "true" then
        return config
    end
    config.enabled = true

    -- Get port from annotation
    local port_ann = get_annotation(event, "pressured.io/pprof-port")
    if port_ann then
        local port_num = tonumber(port_ann)
        if port_num and port_num > 0 and port_num < 65536 then
            config.port = port_num
        end
    end

    -- Get path from annotation
    local path_ann = get_annotation(event, "pressured.io/pprof-path")
    if path_ann and path_ann ~= "" then
        config.path = path_ann
    end

    return config
end

-- Stream HTTP response directly to storage using atomic writes
-- Writes to ${key}.part first, then renames on success
-- Returns: total_bytes, error
local function stream_to_storage(url, storage_key)
    local part_key = storage_key .. ".part"
    log.info(string.format("Opening storage for streaming: %s (via %s)", storage_key, part_key))

    -- Open .part file for writing
    local file, err = storage.open(part_key, "w")
    if not file then
        return 0, string.format("failed to open storage: %s", err or "unknown")
    end

    local total_bytes = 0
    local stream_error = nil

    -- Stream HTTP response, writing chunks directly to storage
    log.info(string.format("Starting HTTP stream from: %s", url))
    local result = http.stream(url, function(chunk, info)
        local written, write_err = file:write(chunk)
        if not written then
            stream_error = string.format("storage write failed: %s", write_err or "unknown")
            return false  -- stop streaming
        end
        total_bytes = total_bytes + #chunk
        log.debug(string.format("Streamed chunk: %d bytes (total: %d)", #chunk, total_bytes))
        return true  -- continue streaming
    end)

    -- Close the .part file (finalizes multipart upload for cloud storage)
    local close_ok = file:close()

    if stream_error then
        storage.remove(part_key)  -- Clean up failed .part file
        return total_bytes, stream_error
    end

    if not result.ok then
        storage.remove(part_key)  -- Clean up failed .part file
        return total_bytes, string.format("HTTP stream failed: %s", result.error or "unknown")
    end

    if not close_ok then
        storage.remove(part_key)  -- Clean up failed .part file
        return total_bytes, "storage close failed"
    end

    -- Atomic rename: .part -> final name
    local rename_result = storage.rename(part_key, storage_key)
    if not rename_result.ok then
        storage.remove(part_key)  -- Clean up orphaned .part file
        return total_bytes, string.format("rename failed: %s", rename_result.error or "unknown")
    end

    log.info(string.format("Renamed %s -> %s", part_key, storage_key))
    return total_bytes, nil
end

-- Determine pprof host based on mode and event
local function get_pprof_host(event)
    if PPROF_MODE == "sidecar" then
        return "127.0.0.1"
    end
    -- Cluster mode: use pod IP from event
    if event.pod_ip and event.pod_ip ~= "" then
        return event.pod_ip
    end
    log.warn("Cluster mode but no pod_ip in event, falling back to 127.0.0.1")
    return "127.0.0.1"
end

function on_event(event, ctx_arg)
    log.info(string.format("[pprof] Event Type: %s", event.event_type or "unknown"))
    log.info(string.format("[pprof] Event: ns=%s pod=%s container=%s severity=%s",
        event.namespace or "?", event.pod_name or "?", event.container_name or "?", event.severity or "?"))
    log.info(string.format("[pprof] Memory: %.1f%% (%.1f MB / %.1f MB)",
        event.usage_percent or 0,
        (event.usage_bytes or 0) / (1024 * 1024),
        (event.limit_bytes or 0) / (1024 * 1024)))
    log.info(string.format("[pprof] Pod IP: %s, Mode: %s", event.pod_ip or "N/A", PPROF_MODE))

    if ctx_arg and ctx_arg.dry_run then
        log.info("[pprof] Dry run mode - skipping uploads")
        return "dry_run"
    end

    local ts = tostring(os.time() * 1000)
    local event_type = event.event_type or "unknown"

    -- Upload event metadata (for both event types)
    local meta_key = string.format("events/%s/%s-%s-event.json", event_type, ts, event.pod_name or "unknown")
    local meta_data = string.format(
        '{"timestamp":"%s","event_type":"%s","namespace":"%s","pod":"%s","container":"%s","severity":"%s","usage_percent":%.2f,"usage_bytes":%d,"limit_bytes":%d,"oom_kill_count":%d,"pod_ip":"%s"}',
        ts, event_type, event.namespace or "", event.pod_name or "", event.container_name or "", event.severity or "",
        event.usage_percent or 0, event.usage_bytes or 0, event.limit_bytes or 0, event.oom_kill_count or 0, event.pod_ip or "")

    local w = storage.write(meta_key, meta_data)
    if w.ok then
        log.info(string.format("[pprof] SUCCESS: Uploaded event metadata (%d bytes)", #meta_data))
    else
        log.error(string.format("[pprof] FAILED: Metadata upload error: %s", w.error or "unknown"))
    end

    -- For OOM killed events, log but skip pprof (process is dead)
    if event_type == "oom_killed" then
        log.warn("[pprof] OOM KILLED: Container was terminated by kernel OOM killer!")
        log.warn("[pprof] Skipping pprof capture - process is dead")
        return "oom_killed_logged"
    end

    -- Get pprof configuration from annotations (with fallback to defaults)
    local pprof_cfg = get_pprof_config(event)

    -- Check if pprof is disabled for this pod
    if not pprof_cfg.enabled then
        log.info("[pprof] pprof disabled for this pod via annotation (pressured.io/pprof-enabled=false)")
        return "pprof_disabled"
    end

    -- Get pprof host (pod IP in cluster mode, localhost in sidecar mode)
    local pprof_host = get_pprof_host(event)
    log.info(string.format("[pprof] Using pprof endpoint: %s:%d%s (from %s)",
        pprof_host, pprof_cfg.port, pprof_cfg.path,
        get_annotation(event, "pressured.io/pprof-port") and "annotation" or "default"))

    -- For memory pressure events, capture pprof data
    log.info("[pprof] Streaming heap profile...")
    local heap_url = string.format("http://%s:%d%s", pprof_host, pprof_cfg.port, pprof_cfg.path)
    local heap_key = string.format("heaps/%s/%s-%s-heap.pb.gz", event_type, ts, event.pod_name or "unknown")

    local heap_bytes, heap_err = stream_to_storage(heap_url, heap_key)
    if heap_err then
        log.error(string.format("[pprof] FAILED: Heap stream error: %s (got %d bytes)", heap_err, heap_bytes))
        return "heap_stream_error"
    end
    log.info(string.format("[pprof] SUCCESS: Streamed heap profile (%d bytes)", heap_bytes))

    -- Stream goroutine profile (only for Go standard pprof path)
    -- If custom path is set, skip goroutine as it may not be available
    if pprof_cfg.path == DEFAULT_PPROF_PATH then
        log.info("[pprof] Streaming goroutine profile...")
        local goroutine_url = string.format("http://%s:%d/debug/pprof/goroutine?debug=2", pprof_host, pprof_cfg.port)
        local goroutine_key = string.format("goroutines/%s/%s-%s-goroutine.txt", event_type, ts, event.pod_name or "unknown")

        local goroutine_bytes, goroutine_err = stream_to_storage(goroutine_url, goroutine_key)
        if goroutine_err then
            log.error(string.format("[pprof] FAILED: Goroutine stream error: %s (got %d bytes)", goroutine_err, goroutine_bytes))
        else
            log.info(string.format("[pprof] SUCCESS: Streamed goroutine profile (%d bytes)", goroutine_bytes))
        end
    else
        log.info("[pprof] Skipping goroutine profile (custom pprof path set)")
    end

    return "success"
end
