-- Example Sentinel Lua plugin
-- Checks for exposed .git directory
-- Usage: Place in scripts/ directory and run sentinel with your target

local resp = http.get(TARGET .. "/.git/HEAD")

if resp.status == 200 and resp.body:find("ref:") then
    report.finding(
        "high",
        "custom",
        "Exposed .git Directory",
        "The .git directory is publicly accessible. Source code and credentials may be leaked.",
        TARGET .. "/.git/HEAD"
    )
end
