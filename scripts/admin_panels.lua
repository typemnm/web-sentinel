-- Admin panel detection
local panels = {
    {path = "/admin",           sig = nil},
    {path = "/admin/",          sig = nil},
    {path = "/administrator",   sig = nil},
    {path = "/wp-admin",        sig = "wp-login"},
    {path = "/wp-login.php",    sig = "wp-login"},
    {path = "/manager",         sig = nil},
    {path = "/cpanel",          sig = "cpanel"},
    {path = "/webmail",         sig = nil},
    {path = "/login",           sig = nil},
    {path = "/auth/login",      sig = nil},
    {path = "/user/login",      sig = nil},
    {path = "/dashboard",       sig = nil},
    {path = "/panel",           sig = nil},
}

for _, p in ipairs(panels) do
    local resp = http.get(TARGET .. p.path)
    if resp.status == 200 then
        local is_login = resp.body:lower():find("password")
            or resp.body:lower():find("login")
            or resp.body:lower():find("sign in")
        if p.sig then
            is_login = is_login or resp.body:lower():find(p.sig)
        end
        if is_login then
            report.finding("medium", "custom",
                "Admin/Login Panel Found: " .. p.path,
                "Login page is publicly accessible — potential brute-force target.",
                TARGET .. p.path
            )
        end
    end
end
