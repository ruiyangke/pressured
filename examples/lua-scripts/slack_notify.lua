-- slack_notify.lua - Send OOM event notifications to Slack
--
-- Sends formatted messages to Slack using the Bot Token API.
-- Supports both memory_pressure (warning) and oom_killed (critical) events.
--
-- Configuration (via plugins.lua.slack in config.json):
--   plugins.lua.slack.bot_token   - Slack bot token (xoxb-...)
--   plugins.lua.slack.channels    - Channels to post to (comma-separated string or array)
--   plugins.lua.slack.username    - Bot username (default: "Pressured")
--   plugins.lua.slack.template    - Custom message template (see below)
--
-- Example config.json:
--   {
--     "plugins": {
--       "lua": {
--         "script": "/path/to/slack_notify.lua",
--         "slack": {
--           "bot_token": "xoxb-...",
--           "channels": ["#alerts", "#ops"],
--           "username": "Pressured"
--         }
--       }
--     }
--   }
--
-- Template variables:
--   ${event_type}     - "memory_pressure" or "oom_killed"
--   ${namespace}      - Kubernetes namespace
--   ${pod_name}       - Pod name
--   ${container_name} - Container name
--   ${severity}       - Event severity (warn, critical)
--   ${usage_bytes}    - Memory usage in bytes
--   ${limit_bytes}    - Memory limit in bytes
--   ${usage_percent}  - Memory usage percentage
--   ${usage_human}    - Human-readable usage (e.g., "64.0 MB")
--   ${limit_human}    - Human-readable limit (e.g., "128.0 MB")
--   ${oom_kill_count} - Number of OOM kills
--   ${node_name}      - Node name
--   ${emoji}          - Event emoji
--   ${color}          - Severity color hex code
--
-- Example plugins.lua.slack.template:
--   "${emoji} *${event_type}* in `${namespace}/${pod_name}`\nMemory: ${usage_human}/${limit_human} (${usage_percent}%)"

-- Get Slack config from plugins.lua.slack section
local slack_cfg = config and config.plugins and config.plugins.lua and config.plugins.lua.slack or {}

-- Bot token can come from config or environment variable (for secrets)
local BOT_TOKEN = slack_cfg.bot_token or ctx.getenv("SLACK_BOT_TOKEN")
-- Channels can come from config or environment variable
local CHANNELS_STR = slack_cfg.channels or ctx.getenv("SLACK_CHANNELS")
local USERNAME = slack_cfg.username or "Pressured"
local TEMPLATE = slack_cfg.template

local SLACK_API_URL = "https://slack.com/api/chat.postMessage"

-- Severity to Slack color mapping
local SEVERITY_COLORS = {
    warn = "#ffcc00",
    warning = "#ffcc00",
    critical = "#ff0000",
}

-- Event type to emoji mapping
local EVENT_EMOJI = {
    memory_pressure = ":warning:",
    oom_killed = ":skull:",
}

-- Parse channels string into array
local function parse_channels(channels_input)
    if not channels_input then
        return {}
    end

    -- If already a table (from config), return as-is
    if type(channels_input) == "table" then
        return channels_input
    end

    -- Parse comma-separated string
    local channels = {}
    for channel in string.gmatch(channels_input, "[^,]+") do
        local trimmed = channel:match("^%s*(.-)%s*$")
        if trimmed and trimmed ~= "" then
            table.insert(channels, trimmed)
        end
    end
    return channels
end

-- Format bytes to human readable
local function format_bytes(bytes)
    if bytes >= 1024 * 1024 * 1024 then
        return string.format("%.1f GB", bytes / (1024 * 1024 * 1024))
    elseif bytes >= 1024 * 1024 then
        return string.format("%.1f MB", bytes / (1024 * 1024))
    elseif bytes >= 1024 then
        return string.format("%.1f KB", bytes / 1024)
    else
        return string.format("%d B", bytes)
    end
end

-- Build template variables from event
local function build_vars(event)
    local event_type = event.event_type or "unknown"
    return {
        event_type = event_type,
        namespace = event.namespace or "unknown",
        pod_name = event.pod_name or "unknown",
        container_name = event.container_name or "unknown",
        severity = event.severity or "unknown",
        usage_bytes = tostring(event.usage_bytes or 0),
        limit_bytes = tostring(event.limit_bytes or 0),
        usage_percent = string.format("%.1f", event.usage_percent or 0),
        usage_human = format_bytes(event.usage_bytes or 0),
        limit_human = format_bytes(event.limit_bytes or 0),
        oom_kill_count = tostring(event.oom_kill_count or 0),
        node_name = event.node_name or "unknown",
        emoji = EVENT_EMOJI[event_type] or ":bell:",
        color = SEVERITY_COLORS[event.severity] or "#808080",
    }
end

-- Expand template with variables
local function expand_template(template, vars)
    return template:gsub("%${([%w_]+)}", function(key)
        return vars[key] or ""
    end)
end

-- Build default Slack payload (attachment format)
local function build_default_payload(event, channel)
    local vars = build_vars(event)

    local title
    if event.event_type == "oom_killed" then
        title = string.format("%s OOM Kill: %s/%s", vars.emoji, vars.namespace, vars.pod_name)
    else
        title = string.format("%s Memory Pressure: %s/%s", vars.emoji, vars.namespace, vars.pod_name)
    end

    local fields = {
        { title = "Namespace", value = vars.namespace, short = true },
        { title = "Pod Name", value = vars.pod_name, short = true },
        { title = "Container", value = vars.container_name, short = true },
        { title = "Severity", value = string.upper(vars.severity), short = true },
    }

    -- Only show memory usage for memory pressure events (not OOM killed)
    if event.event_type ~= "oom_killed" then
        table.insert(fields, { title = "Memory Usage", value = string.format("%s / %s (%s%%)", vars.usage_human, vars.limit_human, vars.usage_percent), short = false })
    end

    if event.oom_kill_count and event.oom_kill_count > 0 then
        table.insert(fields, { title = "OOM Kill Count", value = vars.oom_kill_count, short = true })
    end

    if event.node_name and event.node_name ~= "" then
        table.insert(fields, { title = "Node", value = vars.node_name, short = true })
    end

    return {
        channel = channel,
        username = USERNAME,
        attachments = {
            {
                color = vars.color,
                title = title,
                fields = fields,
                ts = os.time()
            }
        }
    }
end

-- Build custom template payload (simple text format)
local function build_template_payload(event, channel, template)
    local vars = build_vars(event)
    local text = expand_template(template, vars)

    return {
        channel = channel,
        username = USERNAME,
        text = text,
        mrkdwn = true
    }
end

-- Simple JSON encoder
local function json_encode(val)
    local t = type(val)

    if t == "nil" then
        return "null"
    elseif t == "boolean" then
        return val and "true" or "false"
    elseif t == "number" then
        return tostring(val)
    elseif t == "string" then
        local escaped = val:gsub('\\', '\\\\')
                           :gsub('"', '\\"')
                           :gsub('\n', '\\n')
                           :gsub('\r', '\\r')
                           :gsub('\t', '\\t')
        return '"' .. escaped .. '"'
    elseif t == "table" then
        local is_array = true
        local max_idx = 0
        for k, _ in pairs(val) do
            if type(k) ~= "number" or k ~= math.floor(k) or k < 1 then
                is_array = false
                break
            end
            if k > max_idx then max_idx = k end
        end
        if is_array and max_idx > 0 then
            for i = 1, max_idx do
                if val[i] == nil then
                    is_array = false
                    break
                end
            end
        end

        if is_array and max_idx > 0 then
            local parts = {}
            for i = 1, max_idx do
                table.insert(parts, json_encode(val[i]))
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local parts = {}
            for k, v in pairs(val) do
                if type(k) == "string" then
                    table.insert(parts, json_encode(k) .. ":" .. json_encode(v))
                end
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    else
        return "null"
    end
end

-- Send notification to Slack
local function send_to_slack(payload)
    local body = json_encode(payload)

    log.debug(string.format("Sending to Slack channel %s", payload.channel))

    local resp = http.fetch("POST", SLACK_API_URL, {
        body = body,
        content_type = "application/json",
        headers = {
            "Authorization: Bearer " .. BOT_TOKEN
        }
    })

    if resp.error then
        return false, resp.error
    end

    if resp.status ~= 200 then
        return false, string.format("HTTP %d: %s", resp.status, resp.body or "")
    end

    if resp.body and resp.body:find('"ok":false') then
        local err = resp.body:match('"error":"([^"]+)"') or "unknown error"
        return false, err
    end

    return true, nil
end

function on_event(event, ctx_arg)
    log.info(string.format("Event: %s ns=%s pod=%s container=%s severity=%s",
        event.event_type or "unknown",
        event.namespace or "?",
        event.pod_name or "?",
        event.container_name or "?",
        event.severity or "?"))

    -- Check bot token
    if not BOT_TOKEN or BOT_TOKEN == "" then
        log.warn("plugins.lua.slack.bot_token not configured, skipping notification")
        return "skipped"
    end

    -- Parse channels
    local channels = parse_channels(CHANNELS_STR)
    if #channels == 0 then
        log.warn("plugins.lua.slack.channels not configured, skipping notification")
        return "skipped"
    end

    -- Check dry run
    if ctx_arg and ctx_arg.dry_run then
        log.info("Dry run - skipping Slack notification")
        return "dry_run"
    end

    -- Send to each channel
    local success_count = 0
    local error_count = 0

    for _, channel in ipairs(channels) do
        local payload
        if TEMPLATE then
            payload = build_template_payload(event, channel, TEMPLATE)
        else
            payload = build_default_payload(event, channel)
        end

        local ok, err = send_to_slack(payload)
        if ok then
            success_count = success_count + 1
            log.info(string.format("Sent to %s", channel))
        else
            error_count = error_count + 1
            log.error(string.format("Failed to send to %s: %s", channel, err or "unknown"))
        end
    end

    if error_count > 0 then
        log.warn(string.format("Sent to %d/%d channels", success_count, success_count + error_count))
        return success_count > 0 and "partial" or "error"
    end

    log.info(string.format("Notification sent to %d channel(s)", success_count))
    return "sent"
end
