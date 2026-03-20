-- Detect known-vulnerable JavaScript library versions
local resp = http.get(TARGET)
if resp.status ~= 200 then return end

local body = resp.body

-- jQuery version detection
local jquery_ver = body:match("jquery[/%-]([%d%.]+)") or body:match("jQuery v([%d%.]+)")
if jquery_ver then
    local major, minor, patch = jquery_ver:match("(%d+)%.(%d+)%.?(%d*)")
    major = tonumber(major) or 0
    minor = tonumber(minor) or 0
    patch = tonumber(patch) or 0
    -- jQuery < 3.5.0 has XSS vulnerability (CVE-2020-11022, CVE-2020-11023)
    if major < 3 or (major == 3 and minor < 5) then
        report.finding("high", "custom",
            "Vulnerable jQuery " .. jquery_ver,
            "jQuery < 3.5.0 is vulnerable to XSS (CVE-2020-11022/CVE-2020-11023).",
            TARGET
        )
    end
end

-- Angular.js version detection (1.x is EOL and has multiple XSS)
local angular_ver = body:match("angular[/%-]([%d%.]+)") or body:match("AngularJS v([%d%.]+)")
if angular_ver then
    local major = tonumber(angular_ver:match("^(%d+)")) or 0
    if major == 1 then
        report.finding("high", "custom",
            "Vulnerable AngularJS " .. angular_ver,
            "AngularJS 1.x is end-of-life with known sandbox escape vulnerabilities.",
            TARGET
        )
    end
end

-- Lodash < 4.17.21 (CVE-2021-23337 — command injection via template)
local lodash_ver = body:match("lodash[/%-]([%d%.]+)")
if lodash_ver then
    local major, minor, patch = lodash_ver:match("(%d+)%.(%d+)%.(%d+)")
    major = tonumber(major) or 0
    minor = tonumber(minor) or 0
    patch = tonumber(patch) or 0
    if major < 4 or (major == 4 and minor < 17) or (major == 4 and minor == 17 and patch < 21) then
        report.finding("high", "custom",
            "Vulnerable Lodash " .. lodash_ver,
            "Lodash < 4.17.21 is vulnerable to command injection (CVE-2021-23337).",
            TARGET
        )
    end
end

-- Bootstrap < 3.4.0 / < 4.3.1 (XSS via data attributes)
local bootstrap_ver = body:match("bootstrap[/%-]([%d%.]+)") or body:match("Bootstrap v([%d%.]+)")
if bootstrap_ver then
    local major, minor, patch = bootstrap_ver:match("(%d+)%.(%d+)%.?(%d*)")
    major = tonumber(major) or 0
    minor = tonumber(minor) or 0
    patch = tonumber(patch) or 0
    local vuln = false
    if major == 3 and (minor < 4 or (minor == 4 and patch < 1)) then vuln = true end
    if major == 4 and (minor < 3 or (minor == 3 and patch < 1)) then vuln = true end
    if vuln then
        report.finding("medium", "custom",
            "Vulnerable Bootstrap " .. bootstrap_ver,
            "Bootstrap version has known XSS vulnerabilities.",
            TARGET
        )
    end
end
