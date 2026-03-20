-- JSONP endpoint detection (cross-site data theft risk)
local endpoints = {"", "/api", "/api/user", "/api/me", "/api/profile", "/api/data"}
local callback = "sentinel_jsonp_test"

for _, ep in ipairs(endpoints) do
    local resp = http.get(TARGET .. ep .. "?callback=" .. callback)
    if resp.status == 200 then
        if resp.body:find(callback .. "%(") then
            report.finding("medium", "custom",
                "JSONP Endpoint Detected: " .. ep,
                "Endpoint responds to callback parameter — potential cross-origin data leak.",
                TARGET .. ep .. "?callback=" .. callback
            )
        end
    end

    -- Also try _callback, jsonp, cb
    for _, param in ipairs({"_callback", "jsonp", "cb"}) do
        local resp2 = http.get(TARGET .. ep .. "?" .. param .. "=" .. callback)
        if resp2.status == 200 and resp2.body:find(callback .. "%(") then
            report.finding("medium", "custom",
                "JSONP Endpoint Detected: " .. ep .. " (param: " .. param .. ")",
                "Endpoint responds to " .. param .. " parameter — potential cross-origin data leak.",
                TARGET .. ep .. "?" .. param .. "=" .. callback
            )
        end
    end
end
