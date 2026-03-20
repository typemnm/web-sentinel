-- Host Header Injection check
-- If the application trusts the Host header for URL generation (password reset, redirects),
-- an attacker can poison links.

local resp = http.get_with_headers(TARGET, {["Host"] = "evil-host.com"})

if resp.status == 200 or resp.status == 302 then
    if resp.body:find("evil%-host%.com") then
        report.finding("high", "custom",
            "Host Header Injection (Body)",
            "Injected Host header value reflected in response body — password reset poisoning risk.",
            TARGET
        )
    end
    local location = resp.headers["location"]
    if location and location:find("evil%-host%.com") then
        report.finding("high", "custom",
            "Host Header Injection (Redirect)",
            "Injected Host header caused redirect to evil-host.com.",
            TARGET
        )
    end
end
