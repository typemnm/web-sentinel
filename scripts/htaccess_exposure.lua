-- .htaccess / .htpasswd exposure check
local files = {
    {path = "/.htaccess",  sig = "RewriteRule"},
    {path = "/.htpasswd",  sig = "$apr1$"},
    {path = "/.htpasswd",  sig = "{SHA}"},
    {path = "/.htpasswd",  sig = "$2y$"},
    {path = "/web.config",  sig = "<configuration"},
}

for _, f in ipairs(files) do
    local resp = http.get(TARGET .. f.path)
    if resp.status == 200 and resp.body:find(f.sig, 1, true) then
        -- Verify it's not an HTML SPA shell
        local body_start = resp.body:sub(1, 200):lower()
        local is_html = body_start:find("<!doctype") or body_start:find("<html")
        if not is_html then
            local sev = "high"
            if f.path:find("htpasswd") then sev = "critical" end
            report.finding(sev, "custom",
                "Config File Exposed: " .. f.path,
                "Server configuration file is publicly readable.",
                TARGET .. f.path
            )
            break  -- one finding per file type
        end
    end
end
