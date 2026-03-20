-- Analyze robots.txt for hidden/sensitive paths
local resp = http.get(TARGET .. "/robots.txt")

if resp.status == 200 and resp.body:find("Disallow") then
    local sensitive_keywords = {"admin", "backup", "config", "secret", "private", "internal", "api", "debug", "test", "staging"}

    for line in resp.body:gmatch("[^\r\n]+") do
        local path = line:match("Disallow:%s*(.+)")
        if path and #path > 1 then
            local path_lower = path:lower()
            for _, kw in ipairs(sensitive_keywords) do
                if path_lower:find(kw) then
                    -- Try to access the disallowed path
                    local check = http.get(TARGET .. path:gsub("%s+$", ""))
                    if check.status == 200 then
                        report.finding("medium", "custom",
                            "Sensitive Path in robots.txt Accessible: " .. path,
                            "Path disallowed in robots.txt but returns 200 OK.",
                            TARGET .. path
                        )
                    end
                    break
                end
            end
        end
    end
end

-- Check sitemap.xml
local sitemap = http.get(TARGET .. "/sitemap.xml")
if sitemap.status == 200 and sitemap.body:find("<urlset") then
    report.finding("info", "custom",
        "Sitemap.xml Found",
        "Sitemap is publicly accessible — useful for enumeration.",
        TARGET .. "/sitemap.xml"
    )
end
