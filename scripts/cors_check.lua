-- CORS misconfiguration: Origin reflection check
-- Tests if server reflects arbitrary Origin header (more dangerous than wildcard *)

local resp = http.get_with_headers(TARGET, {["Origin"] = "https://evil-attacker.com"})

if resp.status == 200 then
    local acao = resp.headers["access-control-allow-origin"]
    if acao and acao:find("evil%-attacker%.com") then
        local creds = resp.headers["access-control-allow-credentials"]
        if creds and creds == "true" then
            report.finding("critical", "cors",
                "CORS: Origin Reflection with Credentials",
                "Server reflects arbitrary Origin AND allows credentials — full account takeover possible.",
                TARGET
            )
        else
            report.finding("high", "cors",
                "CORS: Origin Reflection",
                "Server reflects arbitrary Origin header (Access-Control-Allow-Origin: https://evil-attacker.com).",
                TARGET
            )
        end
    end
end
