-- WordPress config backup exposure
local paths = {
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.php.swp",
    "/wp-config.php.orig",
    "/wp-config.txt",
    "/.wp-config.php.swp",
}

for _, p in ipairs(paths) do
    local resp = http.get(TARGET .. p)
    if resp.status == 200 and (
        resp.body:find("DB_NAME") or
        resp.body:find("DB_PASSWORD") or
        resp.body:find("AUTH_KEY") or
        resp.body:find("table_prefix")
    ) then
        report.finding("critical", "custom",
            "WordPress Config Backup Exposed: " .. p,
            "Database credentials and auth keys are publicly accessible.",
            TARGET .. p
        )
    end
end
