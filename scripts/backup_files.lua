-- Common backup and temporary file detection
-- Includes false-positive filtering for SPAs that serve HTML for all routes
local paths = {
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/site.tar", "/site.zip", "/www.zip",
    "/web.zip", "/html.zip", "/public.zip",
    "/config.bak", "/config.old", "/config.php.bak",
    "/.DS_Store",
    "/Thumbs.db",
}

-- Get the baseline SPA shell response to compare against
local baseline = http.get(TARGET .. "/nonexistent_sentinel_check_" .. tostring(math.random(100000, 999999)))
local baseline_is_html = false
if baseline and baseline.status == 200 then
    -- If a random nonexistent path returns 200, this is likely an SPA
    baseline_is_html = true
end

for _, p in ipairs(paths) do
    local resp = http.head(TARGET .. p)
    if resp.status == 200 then
        -- Verify with GET only if HEAD succeeds
        local full = http.get(TARGET .. p)
        if full.status == 200 and #full.body > 50 then
            -- False-positive filter: if the server is an SPA (returns 200 for random paths),
            -- check that the response is NOT HTML (real backup files are binary/text, not HTML)
            local body_start = full.body:sub(1, 200):lower()
            local is_html = body_start:find("<!doctype") or body_start:find("<html") or body_start:find("<head")
            local ct = (full.headers and full.headers["content-type"]) or ""
            local ct_is_html = ct:find("text/html") ~= nil

            if baseline_is_html and (is_html or ct_is_html) then
                -- Skip: SPA serving HTML shell for all routes (false positive)
            else
                report.finding("high", "custom",
                    "Backup/Temp File Exposed: " .. p,
                    "Sensitive file is publicly downloadable.",
                    TARGET .. p
                )
            end
        end
    end
end
