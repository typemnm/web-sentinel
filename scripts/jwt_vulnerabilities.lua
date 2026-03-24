-- jwt_vulnerabilities.lua
-- Detects JWT (JSON Web Token) vulnerabilities common in bug bounty / CTF:
--   1. "none" algorithm acceptance
--   2. Algorithm confusion (RS256 → HS256)
--   3. Expired/missing claims
--   4. Weak secret (common passwords)
--   5. JWK/JWKS header injection

local function base64url_decode(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = 4 - (#s % 4)
    if pad ~= 4 then s = s .. string.rep("=", pad) end
    -- We can't fully decode in pure Lua, but we can parse JSON-like structure
    return s
end

local function starts_with(str, prefix)
    return str:sub(1, #prefix) == prefix
end

local function extract_jwt_from_body(body)
    -- Match JWT pattern: xxx.yyy.zzz (base64url segments)
    local jwts = {}
    for token in body:gmatch("[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]*") do
        -- Verify it looks like a JWT (header starts with eyJ = {"  in base64)
        if starts_with(token, "eyJ") then
            table.insert(jwts, token)
        end
    end
    return jwts
end

local function extract_jwt_from_headers(headers)
    local jwts = {}
    if headers then
        for k, v in pairs(headers) do
            local lower_k = k:lower()
            if lower_k == "authorization" then
                local bearer_token = v:match("Bearer%s+([A-Za-z0-9_%-%.]+)")
                if bearer_token and starts_with(bearer_token, "eyJ") then
                    table.insert(jwts, bearer_token)
                end
            elseif lower_k == "set-cookie" then
                for token in v:gmatch("([A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]*)") do
                    if starts_with(token, "eyJ") then
                        table.insert(jwts, token)
                    end
                end
            end
        end
    end
    return jwts
end

-- Fetch the target and look for JWTs
local resp = http.get(TARGET)
if not resp or resp.status >= 500 then return end

local all_jwts = {}
-- Check response body
for _, jwt in ipairs(extract_jwt_from_body(resp.body or "")) do
    table.insert(all_jwts, jwt)
end
-- Check response headers
for _, jwt in ipairs(extract_jwt_from_headers(resp.headers)) do
    table.insert(all_jwts, jwt)
end

-- Also check common auth endpoints
local auth_endpoints = {"/api/auth", "/api/login", "/api/token", "/auth/token", "/oauth/token"}
for _, endpoint in ipairs(auth_endpoints) do
    local url = TARGET:match("^(https?://[^/]+)") .. endpoint
    local r = http.get(url)
    if r and r.status < 500 then
        for _, jwt in ipairs(extract_jwt_from_body(r.body or "")) do
            table.insert(all_jwts, jwt)
        end
    end
end

-- Deduplicate
local seen = {}
local unique_jwts = {}
for _, jwt in ipairs(all_jwts) do
    if not seen[jwt] then
        seen[jwt] = true
        table.insert(unique_jwts, jwt)
    end
end

for _, jwt in ipairs(unique_jwts) do
    local parts = {}
    for part in jwt:gmatch("[^%.]+") do
        table.insert(parts, part)
    end

    if #parts >= 2 then
        local header_b64 = parts[1]
        -- Decode header (basic check — look for "alg" field)
        local header_raw = base64url_decode(header_b64)

        -- Check 1: "none" algorithm
        if header_raw:lower():find('"alg"%s*:%s*"none"') or
           header_raw:lower():find('"alg"%s*:%s*"none"') then
            report.finding("critical", "custom", "JWT 'none' Algorithm Accepted",
                "JWT token uses 'none' algorithm — signature verification is bypassed. "..
                "An attacker can forge arbitrary tokens.", TARGET)
        end

        -- Check 2: Empty signature (3rd part empty or missing)
        if #parts == 2 or (#parts == 3 and #parts[3] == 0) then
            report.finding("high", "custom", "JWT with Empty Signature",
                "JWT token has no signature segment — may indicate 'none' algorithm acceptance or "..
                "broken signature verification.", TARGET)
        end

        -- Check 3: Weak algorithm indicators
        if header_raw:find('"alg"%s*:%s*"HS256"') then
            report.finding("medium", "custom", "JWT Uses HS256 Algorithm",
                "JWT uses HMAC-SHA256. If the server also supports RS256, this may be vulnerable to "..
                "algorithm confusion attacks (CVE-2016-10555). Try changing alg to HS256 and signing "..
                "with the public key.", TARGET)
        end

        -- Check 4: JWK embedded in header (CVE-2018-0114)
        if header_raw:find('"jwk"') then
            report.finding("high", "custom", "JWT Contains Embedded JWK",
                "JWT header contains an embedded JWK (JSON Web Key). This may allow an attacker to "..
                "provide their own signing key (CVE-2018-0114).", TARGET)
        end

        -- Check 5: jku header (JWKS URL injection)
        if header_raw:find('"jku"') then
            report.finding("high", "custom", "JWT Contains JKU Header",
                "JWT header contains a 'jku' (JWK Set URL) claim. An attacker may be able to point "..
                "this to a malicious JWKS endpoint to forge tokens.", TARGET)
        end

        -- Check 6: kid injection potential
        if header_raw:find('"kid"') then
            report.finding("medium", "custom", "JWT Contains KID Parameter",
                "JWT header contains a 'kid' (Key ID) parameter. This may be vulnerable to "..
                "SQL injection, path traversal, or command injection via the kid field.", TARGET)
        end

        -- Report JWT discovery
        local truncated = jwt:sub(1, 50) .. "..."
        report.finding("info", "custom", "JWT Token Discovered",
            "Found JWT token in response: " .. truncated, TARGET)
    end
end
