-- Server-Side Template Injection (SSTI) probe
-- Injects math expressions into parameters, checks if server evaluates them.

if not TARGET:find("?") then return end

local probes = {
    {payload = "{{7*7}}",           expected = "49",     engine = "Jinja2/Twig"},
    {payload = "${7*7}",            expected = "49",      engine = "FreeMarker/Thymeleaf"},
    {payload = "#{7*7}",            expected = "49",      engine = "Ruby ERB/Java EL"},
    {payload = "<%= 7*7 %>",        expected = "49",      engine = "ERB/EJS"},
    {payload = "${{7*7}}",          expected = "49",      engine = "Angular/Pebble"},
}

-- Extract parameters
for param in TARGET:gmatch("[?&]([^=]+)=") do
    for _, probe in ipairs(probes) do
        local test_url = TARGET:gsub("([?&]" .. param .. "=)[^&]*", "%1" .. probe.payload)
        if test_url ~= TARGET then
            local resp = http.get(test_url)
            if resp.status == 200 and resp.body:find(probe.expected, 1, true) then
                -- Verify it's not just reflecting the raw expression
                if not resp.body:find(probe.payload, 1, true) then
                    report.finding("critical", "custom",
                        "SSTI in parameter '" .. param .. "' (" .. probe.engine .. ")",
                        "Template expression " .. probe.payload .. " evaluated to " .. probe.expected,
                        test_url
                    )
                    return -- one finding is enough
                end
            end
        end
    end
end
