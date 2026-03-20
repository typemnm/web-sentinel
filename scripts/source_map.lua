-- Source map file exposure (allows source code reconstruction)
local resp = http.get(TARGET)
if resp.status ~= 200 then return end

-- Extract JS file references
local js_files = {}
for src in resp.body:gmatch('src=["\']([^"\']+%.js)["\']') do
    table.insert(js_files, src)
end

for _, js in ipairs(js_files) do
    -- Build absolute URL
    local js_url
    if js:find("^http") then
        js_url = js
    elseif js:find("^//") then
        js_url = "https:" .. js
    elseif js:find("^/") then
        js_url = TARGET .. js
    else
        js_url = TARGET .. "/" .. js
    end

    local map_url = js_url .. ".map"
    local map_resp = http.head(map_url)
    if map_resp.status == 200 then
        report.finding("medium", "custom",
            "Source Map Exposed: " .. js .. ".map",
            "JavaScript source map file is publicly accessible — original source code can be reconstructed.",
            map_url
        )
    end
end
