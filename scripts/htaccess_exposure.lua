-- .htaccess / .htpasswd exposure check
local files = {
    {path = "/.htaccess",  sig = "RewriteRule"},
    {path = "/.htpasswd",  sig = ":"},
    {path = "/.htpasswd",  sig = "$apr1$"},
    {path = "/web.config",  sig = "<configuration"},
}

for _, f in ipairs(files) do
    local resp = http.get(TARGET .. f.path)
    if resp.status == 200 and resp.body:find(f.sig) then
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
