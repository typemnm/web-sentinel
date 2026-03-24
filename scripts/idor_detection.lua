-- idor_detection.lua
-- Detects Insecure Direct Object Reference (IDOR) patterns
-- #1 most common bug bounty finding category
--
-- Tests:
--   1. Sequential integer ID enumeration
--   2. UUID vs sequential ID exposure
--   3. Horizontal privilege escalation patterns
--   4. API endpoint parameter tampering

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- Common API patterns with ID parameters
local idor_patterns = {
    "/api/users/%s",
    "/api/user/%s",
    "/api/v1/users/%s",
    "/api/v1/user/%s",
    "/api/accounts/%s",
    "/api/profile/%s",
    "/api/orders/%s",
    "/api/invoices/%s",
    "/api/documents/%s",
    "/api/files/%s",
    "/api/messages/%s",
    "/api/v1/orders/%s",
    "/api/v2/users/%s",
    "/users/%s/profile",
    "/users/%s/settings",
    "/admin/users/%s",
}

-- Try IDs 1,2,3 — if all return 200 with different content, likely IDOR
for _, pattern in ipairs(idor_patterns) do
    local url1 = base_url .. string.format(pattern, "1")
    local url2 = base_url .. string.format(pattern, "2")

    local resp1 = http.get(url1)
    local resp2 = http.get(url2)

    if resp1 and resp2 then
        -- Both return 200 with different body = sequential IDs are accessible
        if resp1.status == 200 and resp2.status == 200 then
            local body1 = resp1.body or ""
            local body2 = resp2.body or ""

            -- Bodies should be different (different user data)
            if #body1 > 50 and #body2 > 50 and body1 ~= body2 then
                -- Check if response contains user-like data
                local has_user_data = body1:lower():find('"name"') or
                                      body1:lower():find('"email"') or
                                      body1:lower():find('"username"') or
                                      body1:lower():find('"phone"') or
                                      body1:lower():find('"address"')

                if has_user_data then
                    report.finding("high", "custom",
                        "Potential IDOR: Sequential ID Enumeration",
                        "API endpoint " .. string.format(pattern, "{id}") ..
                        " returns different user data for sequential IDs (1, 2). " ..
                        "This indicates missing authorization checks — any user can access " ..
                        "other users' data by changing the ID parameter.",
                        url1)
                    return
                end
            end
        end

        -- ID=1 returns 200 but ID=0 or negative returns error → confirms ID-based access
        if resp1.status == 200 then
            local url_zero = base_url .. string.format(pattern, "0")
            local resp_zero = http.get(url_zero)
            if resp_zero and (resp_zero.status == 404 or resp_zero.status == 400) then
                report.finding("medium", "custom",
                    "Potential IDOR Pattern Detected",
                    "API endpoint " .. string.format(pattern, "{id}") ..
                    " uses sequential integer IDs (ID=1 returns 200, ID=0 returns " ..
                    resp_zero.status .. "). Verify authorization is enforced per-user.",
                    url1)
            end
        end
    end
end

-- Check the main target page for ID parameters in links
local resp = http.get(TARGET)
if resp and resp.body then
    -- Find URLs with numeric IDs
    local id_urls = {}
    for url_match in resp.body:gmatch('href="([^"]*%?[^"]*id=%d+[^"]*)"') do
        table.insert(id_urls, url_match)
    end
    for url_match in resp.body:gmatch('href="([^"]*/[0-9]+)"') do
        table.insert(id_urls, url_match)
    end

    if #id_urls > 0 then
        report.finding("info", "custom",
            "Sequential IDs in URLs (" .. #id_urls .. " found)",
            "Page contains " .. #id_urls .. " links with sequential numeric IDs. " ..
            "These should be tested for IDOR vulnerabilities. " ..
            "Example: " .. id_urls[1], TARGET)
    end
end
