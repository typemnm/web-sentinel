-- Debug/admin endpoint exposure check
local checks = {
    -- Spring Boot Actuator
    {path = "/actuator",         sig = "actuator",        name = "Spring Actuator"},
    {path = "/actuator/env",     sig = "spring",          name = "Spring Actuator /env"},
    {path = "/actuator/health",  sig = "status",          name = "Spring Actuator /health"},
    {path = "/actuator/beans",   sig = "beans",           name = "Spring Actuator /beans"},
    -- Laravel Telescope
    {path = "/telescope",        sig = "telescope",       name = "Laravel Telescope"},
    -- Flask/Werkzeug debugger
    {path = "/console",          sig = "debugger",        name = "Werkzeug Debugger"},
    -- Express debug
    {path = "/debug",            sig = "debug",           name = "Debug Endpoint"},
    -- phpMyAdmin
    {path = "/phpmyadmin/",      sig = "phpMyAdmin",      name = "phpMyAdmin"},
    {path = "/pma/",             sig = "phpMyAdmin",      name = "phpMyAdmin (pma)"},
    -- Adminer
    {path = "/adminer.php",      sig = "adminer",         name = "Adminer"},
    -- Swagger/OpenAPI
    {path = "/swagger-ui.html",  sig = "swagger",         name = "Swagger UI"},
    {path = "/swagger-ui/",      sig = "swagger",         name = "Swagger UI"},
    {path = "/api-docs",         sig = "openapi",         name = "OpenAPI Docs"},
    -- Profiling
    {path = "/trace",            sig = "trace",           name = "Trace Endpoint"},
    {path = "/metrics",          sig = "metric",          name = "Metrics Endpoint"},
    {path = "/_profiler",        sig = "profiler",        name = "Symfony Profiler"},
}

for _, c in ipairs(checks) do
    local resp = http.get(TARGET .. c.path)
    if resp.status == 200 and resp.body:lower():find(c.sig) then
        report.finding("critical", "custom",
            "Debug/Admin Endpoint Exposed: " .. c.name,
            "Endpoint " .. c.path .. " is publicly accessible.",
            TARGET .. c.path
        )
    end
end
