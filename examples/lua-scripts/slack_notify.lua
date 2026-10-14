-- slack_notify.lua - Send memory pressure and OOM kill notifications to Slack
--
-- Sends formatted messages to Slack using the Bot Token API.
-- Supports both memory_pressure (warning) and oom_killed (critical) events.
--
-- Configuration (via plugins.lua.slack in config.json):
--   plugins.lua.slack.bot_token   - Slack bot token (xoxb-...)
--   plugins.lua.slack.channels    - Channels to post to (comma-separated string or array)
--   plugins.lua.slack.username    - Bot username (default: "Pressured")
--   plugins.lua.slack.template    - Custom message template (see below)
--   plugins.lua.slack.api_base    - Web API base URL (default: https://slack.com/api/,
--                                   env: SLACK_API_BASE)
--   plugins.lua.slack.remind_seconds - Re-notify an unchanged condition at most
--                                   this often (default: 3600, env:
--                                   SLACK_REMIND_SECONDS, 0 = every event)
--
-- The event generator re-emits memory_pressure every cooldown period while a
-- container stays above its threshold. To keep the channel usable:
--   - memory_pressure is sent when severity rises above what was last sent for
--     that container, or when the condition is still ongoing after
--     remind_seconds
--   - oom_killed is grouped per workload (pod name without the ReplicaSet hash
--     and pod suffix) and container: the first kill is sent right away, later
--     kills within remind_seconds are held. Held kills are reported with the
--     next kill after the window, or in a summary on the first event of any
--     kind after the window.
-- State is kept per channel and in memory only. A condition counts as
-- notified once Slack accepted the message for that channel (in dry-run mode:
-- once it would have been sent). A failed post is retried no sooner than
-- RETRY_SECONDS later; held OOM kills that cannot be reported within
-- HOLD_SECONDS are dropped with a warning.
--
-- Dumps: handlers that run before this one (scripts run in filename order,
-- e.g. pprof_dump.lua) can add files to event.dumps:
--   { filename = "...", data = "<bytes>" | nil, key = "<storage key>" }
-- Dumps with data are uploaded into the alert's thread (needs the files:write
-- scope). Storage keys of dumps that could not be attached (too large, upload
-- failed, or the alert itself failed and is sent later) are posted as a reply
-- in the thread.
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
--   ${workload}       - Owning workload, e.g. "api" for pod "api-7d4f9c8b6-x2k9p"
--   ${oom_kill_events} - oom_killed: kill events in this workload since the last message
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
local REMIND_SECONDS = tonumber(slack_cfg.remind_seconds or ctx.getenv("SLACK_REMIND_SECONDS")) or 3600
local SLACK_API_BASE = slack_cfg.api_base or ctx.getenv("SLACK_API_BASE") or "https://slack.com/api/"
local RETRY_SECONDS = 60
local HOLD_SECONDS = 24 * 3600

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

local SEVERITY_RANK = {
    ok = 0,
    warn = 1,
    warning = 1,
    critical = 2,
}

-- Alphabet of pod-template-hash and pod name suffixes (rand.SafeEncodeString)
local SAFE_CHAR = "[bcdfghjklmnpqrstvwxz2456789]"

-- Owning workload of a pod: "api-7d4f9c8b6-x2k9p" -> "api", "job-x2k9p" -> "job"
local function workload_name(pod_name)
    local base = pod_name:match("^(.+)%-" .. string.rep(SAFE_CHAR, 5) .. "$")
    if not base then
        return pod_name
    end
    local owner, hash = base:match("^(.+)%-(" .. SAFE_CHAR .. "+)$")
    if owner and #hash >= 6 and #hash <= 10 then
        return owner
    end
    return base
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Notification state, per channel
--   pressure[container key] = { rank = severity rank, at = time of last message }
--   oom[workload key]       = { at = start of the current window, held = kill
--                               events not reported yet, last_kill, namespace,
--                               workload, container }
--   pending_refs[condition key] = { { key = storage key, at = capture time } }
--                               dumps not attached or listed in Slack yet
-- ─────────────────────────────────────────────────────────────────────────────

local channel_state = {}

local function state_for(channel)
    local state = channel_state[channel]
    if not state then
        state = { pressure = {}, oom = {}, pending_refs = {} }
        channel_state[channel] = state
    end
    return state
end

-- Each decide_* returns nil (nothing to send) or details plus a commit
-- function to call with whether the message was delivered.

-- Key of the condition an event belongs to: the container for memory
-- pressure, the workload and container for OOM kills
local function condition_key(event)
    if event.event_type == "oom_killed" then
        return string.format("%s/%s/%s", event.namespace or "", workload_name(event.pod_name or ""), event.container_name or "")
    end
    return string.format("%s/%s/%s", event.namespace or "", event.pod_name or "", event.container_name or "")
end

local function decide_pressure(state, event, now)
    local key = condition_key(event)
    local rank = SEVERITY_RANK[event.severity] or 0
    local last = state.pressure[key]

    -- Forget containers whose reminder window (or retry wait) is over
    for k, v in pairs(state.pressure) do
        if math.max(v.retry_at or 0, (v.at or 0) + REMIND_SECONDS) <= now then
            state.pressure[k] = nil
        end
    end

    if last and last.retry_at and now < last.retry_at then
        return nil
    end
    if last and last.at and rank <= last.rank and now - last.at < REMIND_SECONDS then
        return nil
    end

    local reminder = last ~= nil and last.at ~= nil and rank <= last.rank
    return { reminder = reminder }, function(delivered)
        if delivered then
            state.pressure[key] = { rank = rank, at = now }
        else
            -- Keep what was last delivered; try again after RETRY_SECONDS
            state.pressure[key] = { rank = last and last.rank or -1, at = last and last.at, retry_at = now + RETRY_SECONDS }
        end
    end
end

local function decide_oom(state, event, now)
    local workload = workload_name(event.pod_name or "")
    local key = condition_key(event)
    local group = state.oom[key]

    if group and now - group.at < REMIND_SECONDS then
        group.held = group.held + 1
        group.last_kill = now
        return nil
    end

    local kill_events = (group and group.held or 0) + 1
    return { workload = workload, oom_kill_events = kill_events }, function(delivered)
        state.oom[key] = {
            -- A failed message keeps the count; its window ends after RETRY_SECONDS
            at = delivered and now or now - REMIND_SECONDS + RETRY_SECONDS,
            held = delivered and 0 or kill_events,
            last_kill = now,
            namespace = event.namespace or "",
            workload = workload,
            container = event.container_name or "",
        }
    end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Formatting
-- ─────────────────────────────────────────────────────────────────────────────

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

-- Build template variables from event and decide_* details
local function build_vars(event, details)
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
        workload = details.workload or workload_name(event.pod_name or "unknown"),
        oom_kill_events = tostring(details.oom_kill_events or 0),
    }
end

-- Expand template with variables
local function expand_template(template, vars)
    return template:gsub("%${([%w_]+)}", function(key)
        return vars[key] or ""
    end)
end

-- Build default Slack payload (attachment format)
local function build_default_payload(event, channel, details)
    local vars = build_vars(event, details)

    local title
    if event.event_type == "oom_killed" then
        title = string.format("%s OOM Kill: %s/%s", vars.emoji, vars.namespace, vars.workload)
        if details.summary then
            title = title .. string.format(" (%d more OOM kill events since last alert)", details.oom_kill_events)
        elseif details.oom_kill_events > 1 then
            title = title .. string.format(" (%d OOM kill events since last alert)", details.oom_kill_events)
        end
    else
        title = string.format("%s Memory Pressure: %s/%s", vars.emoji, vars.namespace, vars.pod_name)
        if details.reminder then
            title = title .. " (ongoing)"
        end
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

    if event.event_type == "oom_killed" then
        table.insert(fields, { title = "OOM Kill Events Since Last Alert", value = vars.oom_kill_events, short = true })
    elseif event.oom_kill_count and event.oom_kill_count > 0 then
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
local function build_template_payload(event, channel, template, details)
    local vars = build_vars(event, details)
    local text = expand_template(template, vars)

    return {
        channel = channel,
        username = USERNAME,
        text = text,
        mrkdwn = true
    }
end

-- ─────────────────────────────────────────────────────────────────────────────
-- JSON
-- ─────────────────────────────────────────────────────────────────────────────

local JSON_ESCAPES = { ['"'] = '\\"', ["\\"] = "\\\\", ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t" }

local function json_encode(val)
    local t = type(val)

    if t == "nil" then
        return "null"
    elseif t == "boolean" then
        return val and "true" or "false"
    elseif t == "number" then
        return tostring(val)
    elseif t == "string" then
        local escaped = val:gsub('[%c"\\]', function(c)
            return JSON_ESCAPES[c] or string.format("\\u%04x", c:byte())
        end)
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

local JSON_UNESCAPES = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

-- Decode a JSON document. Returns the value, or nil and an error message.
-- null decodes to nil.
local function json_decode(str)
    local pos = 1

    local function skip_ws()
        pos = str:find("[^ \t\r\n]", pos) or #str + 1
    end

    local function parse_string()
        local out = {}
        local i = pos + 1
        while true do
            local j = str:find('["\\\0-\31]', i)
            if not j then
                error("unterminated string")
            end
            if str:byte(j) < 32 then
                error("control character in string at " .. j)
            end
            table.insert(out, str:sub(i, j - 1))
            if str:sub(j, j) == '"' then
                pos = j + 1
                return table.concat(out)
            end
            local e = str:sub(j + 1, j + 1)
            if JSON_UNESCAPES[e] then
                table.insert(out, JSON_UNESCAPES[e])
                i = j + 2
            elseif e == "u" then
                local hex = str:match("^%x%x%x%x", j + 2)
                if not hex then
                    error("bad \\u escape at " .. j)
                end
                local cp = tonumber(hex, 16)
                i = j + 6
                if cp >= 0xD800 and cp <= 0xDBFF then
                    local lo_hex = str:match("^\\u(%x%x%x%x)", i)
                    local lo = lo_hex and tonumber(lo_hex, 16)
                    if lo and lo >= 0xDC00 and lo <= 0xDFFF then
                        cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
                        i = i + 6
                    else
                        cp = 0xFFFD -- lone high surrogate
                    end
                elseif cp >= 0xDC00 and cp <= 0xDFFF then
                    cp = 0xFFFD -- lone low surrogate
                end
                table.insert(out, utf8.char(cp))
            else
                error("bad escape")
            end
        end
    end

    local parse_value

    local function parse_container(close, add)
        pos = pos + 1
        skip_ws()
        if str:sub(pos, pos) == close then
            pos = pos + 1
            return
        end
        while true do
            add()
            skip_ws()
            local c = str:sub(pos, pos)
            pos = pos + 1
            if c == close then
                return
            elseif c ~= "," then
                error(string.format("expected ',' or '%s' at %d", close, pos - 1))
            end
        end
    end

    function parse_value()
        skip_ws()
        local c = str:sub(pos, pos)
        if c == "{" then
            local obj = {}
            parse_container("}", function()
                skip_ws()
                if str:sub(pos, pos) ~= '"' then
                    error("expected key at " .. pos)
                end
                local key = parse_string()
                skip_ws()
                if str:sub(pos, pos) ~= ":" then
                    error("expected ':' at " .. pos)
                end
                pos = pos + 1
                obj[key] = parse_value()
            end)
            return obj
        elseif c == "[" then
            local arr, n = {}, 0
            parse_container("]", function()
                n = n + 1
                arr[n] = parse_value() -- null leaves a hole at its index
            end)
            return arr
        elseif c == '"' then
            return parse_string()
        end
        if str:sub(pos, pos + 3) == "true" then
            pos = pos + 4
            return true
        elseif str:sub(pos, pos + 4) == "false" then
            pos = pos + 5
            return false
        elseif str:sub(pos, pos + 3) == "null" then
            pos = pos + 4
            return nil
        end
        -- number = -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
        local int = str:match("^-?%d+", pos)
        if not int or int:match("^-?0%d") then
            error("bad number at " .. pos)
        end
        local num = int .. (str:match("^%.%d+", pos + #int) or "")
        num = num .. (str:match("^[eE][-+]?%d+", pos + #num) or "")
        if str:match("^[%.eE]", pos + #num) then
            error("bad number at " .. pos)
        end
        pos = pos + #num
        return tonumber(num)
    end

    local ok, result = pcall(function()
        local value = parse_value()
        skip_ws()
        if pos <= #str then
            error("trailing data at " .. pos)
        end
        return value
    end)
    if not ok then
        return nil, tostring(result)
    end
    return result
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Slack Web API
-- ─────────────────────────────────────────────────────────────────────────────

-- Call a Slack Web API method
-- Returns: decoded response, or nil and an error message
local function slack_api(method, body, content_type)
    local resp = http.fetch("POST", SLACK_API_BASE .. method, {
        body = body,
        content_type = content_type,
        headers = {
            "Authorization: Bearer " .. BOT_TOKEN
        }
    })

    if resp.error then
        return nil, resp.error
    end
    if resp.status ~= 200 then
        return nil, string.format("HTTP %d", resp.status)
    end
    local decoded, err = json_decode(resp.body or "")
    if type(decoded) ~= "table" then
        return nil, "invalid response: " .. (err or "not an object")
    end
    if decoded.ok ~= true then
        return nil, tostring(decoded.error or "unknown error")
    end
    return decoded
end

-- Post a message
-- Returns: { channel_id, ts }, or nil and an error message
local function post_message(payload)
    log.debug(string.format("Sending to Slack channel %s", payload.channel))
    local resp, err = slack_api("chat.postMessage", json_encode(payload), "application/json; charset=utf-8")
    if not resp then
        return nil, err
    end
    return { channel_id = resp.channel, ts = resp.ts }
end

-- Upload one file; returns its file id, or nil and an error message
local function upload_file(filename, data)
    local resp, err = slack_api("files.getUploadURLExternal",
        string.format("filename=%s&length=%d", http.urlencode(filename), #data),
        "application/x-www-form-urlencoded")
    if not resp then
        return nil, err
    end
    if type(resp.upload_url) ~= "string" or type(resp.file_id) ~= "string" then
        return nil, "missing upload_url or file_id"
    end

    local upload = http.fetch("POST", resp.upload_url, {
        body = data,
        content_type = "application/octet-stream",
    })
    if upload.error then
        return nil, upload.error
    end
    if upload.status ~= 200 then
        return nil, string.format("upload HTTP %d", upload.status)
    end
    return resp.file_id
end

-- Attach dumps to a message thread. Files that upload are shared together;
-- storage keys of the rest, and of refs (dumps captured earlier and not sent
-- yet), are posted as a reply.
-- Returns: number of files shared, list of problems, refs neither shared nor listed
local function attach_dumps(dumps, refs, message, now)
    local uploaded, missing, problems = {}, {}, {}

    for _, dump in ipairs(dumps) do
        local ref = { key = dump.key or dump.filename, at = now }
        if dump.data then
            local file_id, err = upload_file(dump.filename, dump.data)
            if file_id then
                table.insert(uploaded, { id = file_id, title = dump.filename, ref = ref })
            else
                table.insert(problems, string.format("%s: %s", dump.filename, err))
                table.insert(missing, { ref = ref, why = "upload failed" })
            end
        else
            table.insert(missing, { ref = ref, why = "too large to attach" })
        end
    end
    for _, ref in ipairs(refs) do
        table.insert(missing, { ref = ref, why = "captured for an earlier alert" })
    end

    local shared = 0
    if #uploaded > 0 then
        local files = {}
        for _, file in ipairs(uploaded) do
            table.insert(files, { id = file.id, title = file.title })
        end
        local resp, err = slack_api("files.completeUploadExternal", json_encode({
            files = files,
            channel_id = message.channel_id,
            thread_ts = message.ts,
        }), "application/json; charset=utf-8")
        if resp then
            shared = #uploaded
        else
            table.insert(problems, "completeUploadExternal: " .. err)
            for _, file in ipairs(uploaded) do
                table.insert(missing, { ref = file.ref, why = "upload failed" })
            end
        end
    end

    local unlisted = {}
    if #missing > 0 then
        local lines = {}
        for _, m in ipairs(missing) do
            table.insert(lines, string.format("%s (%s)", m.ref.key, m.why))
        end
        local _, err = post_message({
            channel = message.channel_id,
            thread_ts = message.ts,
            username = USERNAME,
            text = "Dumps not attached, find them in storage:\n" .. table.concat(lines, "\n"),
        })
        if err then
            table.insert(problems, "listing storage keys: " .. err)
            for _, m in ipairs(missing) do
                table.insert(unlisted, m.ref)
            end
        end
    end

    return shared, problems, unlisted
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Event handling
-- ─────────────────────────────────────────────────────────────────────────────

-- Send one message to a channel (or log it in dry-run mode)
-- Returns: true if delivered (or dry-run), message ({ channel_id, ts }) if posted
local function deliver(payload, channel, dry_run)
    if dry_run then
        log.info(string.format("Dry run - skipping Slack notification to %s", channel))
        return true
    end
    local message, err = post_message(payload)
    if not message then
        log.error(string.format("Failed to send to %s: %s", channel, err or "unknown"))
        return false
    end
    log.info(string.format("Sent to %s", channel))
    return true, message
end

local function build_payload(event, channel, details)
    if TEMPLATE then
        return build_template_payload(event, channel, TEMPLATE, details)
    end
    return build_default_payload(event, channel, details)
end

-- Report OOM kills held back in a window that has since closed
-- Returns: messages delivered, messages failed
local function flush_held_oom(state, channel, now, dry_run)
    local sent, failed = 0, 0
    for key, group in pairs(state.oom) do
        if group.held > 0 and now - group.last_kill >= HOLD_SECONDS then
            log.warn(string.format("Dropping %d unreported OOM kill event(s) for %s/%s in %s",
                group.held, group.namespace, group.workload, channel))
            state.oom[key] = nil
        elseif now - group.at >= REMIND_SECONDS then
            if group.held > 0 then
                -- Templates see the workload as pod_name and the held count as
                -- oom_kill_count / oom_kill_events
                local summary = { event_type = "oom_killed", namespace = group.namespace, pod_name = group.workload,
                    container_name = group.container, severity = "critical", oom_kill_count = group.held }
                local details = { workload = group.workload, oom_kill_events = group.held, summary = true }
                if deliver(build_payload(summary, channel, details), channel, dry_run) then
                    sent = sent + 1
                    group.at, group.held = now, 0
                else
                    failed = failed + 1
                    group.at = now - REMIND_SECONDS + RETRY_SECONDS
                end
            else
                state.oom[key] = nil
            end
        end
    end
    return sent, failed
end

-- Dumps not attached or listed yet are kept per condition (newest 20, each
-- for HOLD_SECONDS from its capture) and listed with the next message about it
local function queue_refs(state, key, refs)
    if #refs == 0 then
        return
    end
    local pending = state.pending_refs[key] or {}
    for _, ref in ipairs(refs) do
        table.insert(pending, ref)
    end
    while #pending > 20 do
        table.remove(pending, 1)
    end
    state.pending_refs[key] = pending
end

local function take_refs(state, key)
    local pending = state.pending_refs[key] or {}
    state.pending_refs[key] = nil
    return pending
end

local function expire_refs(state, now)
    for key, pending in pairs(state.pending_refs) do
        local kept = {}
        for _, ref in ipairs(pending) do
            if now - ref.at < HOLD_SECONDS then
                table.insert(kept, ref)
            end
        end
        state.pending_refs[key] = #kept > 0 and kept or nil
    end
end

local function dump_refs(dumps, now)
    local refs = {}
    for _, dump in ipairs(dumps) do
        if dump.key then
            table.insert(refs, { key = dump.key, at = now })
        end
    end
    return refs
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

    local dry_run = ctx_arg and ctx_arg.dry_run
    local now = os.time()
    local dumps = event.dumps or {}
    local sent, failed = 0, 0

    for _, channel in ipairs(channels) do
        local state = state_for(channel)
        expire_refs(state, now)
        local decide = event.event_type == "oom_killed" and decide_oom or decide_pressure
        local key = condition_key(event)
        local details, commit = decide(state, event, now)

        if not details then
            -- Suppressed: keep this event's dumps for the next message about it
            queue_refs(state, key, dump_refs(dumps, now))
        else
            local delivered, message = deliver(build_payload(event, channel, details), channel, dry_run)
            commit(delivered)
            if delivered then
                sent = sent + 1
            else
                failed = failed + 1
                queue_refs(state, key, dump_refs(dumps, now))
            end

            if message then
                local refs = take_refs(state, key)
                if #dumps > 0 or #refs > 0 then
                    if message.channel_id and message.ts then
                        local shared, problems, unlisted = attach_dumps(dumps, refs, message, now)
                        if shared > 0 then
                            log.info(string.format("Attached %d dump(s) in %s", shared, channel))
                        end
                        for _, problem in ipairs(problems) do
                            log.error(string.format("Dump attachment in %s: %s", channel, problem))
                        end
                        queue_refs(state, key, unlisted)
                    else
                        log.error(string.format("Cannot attach dumps in %s: no channel/ts in response", channel))
                        queue_refs(state, key, refs)
                        queue_refs(state, key, dump_refs(dumps, now))
                    end
                end
            end
        end

        local flushed, flush_failed = flush_held_oom(state, channel, now, dry_run)
        sent, failed = sent + flushed, failed + flush_failed
    end

    if sent == 0 and failed == 0 then
        log.debug("Already notified for this condition, skipping")
        return "suppressed"
    end
    if dry_run then
        return "dry_run"
    end
    if failed > 0 then
        log.warn(string.format("Sent to %d/%d channels", sent, sent + failed))
        return sent > 0 and "partial" or "error"
    end
    log.info(string.format("Notification sent to %d channel(s)", sent))
    return "sent"
end
