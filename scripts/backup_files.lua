-- Common backup and temporary file detection
local paths = {
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/site.tar", "/site.zip", "/www.zip",
    "/web.zip", "/html.zip", "/public.zip",
    "/config.bak", "/config.old", "/config.php.bak",
    "/.DS_Store",
    "/Thumbs.db",
}

for _, p in ipairs(paths) do
    local resp = http.head(TARGET .. p)
    if resp.status == 200 then
        -- Verify with GET only if HEAD succeeds
        local full = http.get(TARGET .. p)
        if full.status == 200 and #full.body > 50 then
            report.finding("high", "custom",
                "Backup/Temp File Exposed: " .. p,
                "Sensitive file is publicly downloadable.",
                TARGET .. p
            )
        end
    end
end
