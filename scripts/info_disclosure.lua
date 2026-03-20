-- Information disclosure via common info endpoints
local checks = {
    {path = "/phpinfo.php",      sig = "PHP Version",          name = "phpinfo()"},
    {path = "/info.php",         sig = "PHP Version",          name = "PHP Info"},
    {path = "/server-status",    sig = "Apache Server Status", name = "Apache server-status"},
    {path = "/server-info",      sig = "Apache Server",        name = "Apache server-info"},
    {path = "/elmah.axd",        sig = "Error Log",            name = "ELMAH Error Log"},
    {path = "/jmx-console",     sig = "JMX",                  name = "JMX Console"},
    {path = "/status",           sig = "uptime",               name = "Status Page"},
    {path = "/health",           sig = "status",               name = "Health Check"},
    {path = "/version",          sig = "version",              name = "Version Endpoint"},
}

for _, c in ipairs(checks) do
    local resp = http.get(TARGET .. c.path)
    if resp.status == 200 and resp.body:lower():find(c.sig:lower()) then
        report.finding("medium", "custom",
            "Information Disclosure: " .. c.name .. " (" .. c.path .. ")",
            "Endpoint exposes internal server/application information.",
            TARGET .. c.path
        )
    end
end
