-- Error page information leak (stack traces, file paths, framework versions)
local random_path = "/sentinel_404_check_" .. tostring(os and os.time and os.time() or 12345)
local resp = http.get(TARGET .. random_path)

if resp.status >= 400 then
    local body_lower = resp.body:lower()
    local leaks = {
        {sig = "traceback",         desc = "Python stack trace"},
        {sig = "stack trace",       desc = "Stack trace exposed"},
        {sig = "at java.",          desc = "Java stack trace"},
        {sig = "at sun.",           desc = "Java internal trace"},
        {sig = "microsoft.net",     desc = ".NET stack trace"},
        {sig = "notice: undefined", desc = "PHP Notice"},
        {sig = "fatal error:",      desc = "PHP Fatal Error"},
        {sig = "debug mode",        desc = "Debug mode enabled"},
        {sig = "/home/",            desc = "Server file path exposed"},
        {sig = "/var/www/",         desc = "Server web root exposed"},
        {sig = "c:\\",              desc = "Windows file path exposed"},
    }

    for _, l in ipairs(leaks) do
        if body_lower:find(l.sig) then
            report.finding("medium", "custom",
                "Error Page Information Leak: " .. l.desc,
                "Error response for non-existent path reveals internal information.",
                TARGET .. random_path
            )
        end
    end
end
