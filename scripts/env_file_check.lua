-- Check for exposed .env files (credential leak)
local paths = { "/.env", "/.env.local", "/.env.production", "/.env.backup" }

for _, p in ipairs(paths) do
    local resp = http.get(TARGET .. p)
    if resp.status == 200 and (resp.body:find("DB_PASSWORD") or resp.body:find("SECRET_KEY") or resp.body:find("API_KEY")) then
        report.finding(
            "critical",
            "custom",
            "Exposed Environment File: " .. p,
            "Sensitive credentials found in publicly accessible environment file.",
            TARGET .. p
        )
    end
end
