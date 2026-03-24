-- deserialization.lua
-- Detects insecure deserialization vulnerabilities
-- High-value targets in bug bounty (Java, PHP, Python, .NET, Node.js)
--
-- Tests:
--   1. Java deserialization (ysoserial gadgets)
--   2. PHP object injection (O: serialized format)
--   3. Python pickle detection
--   4. .NET ViewState analysis
--   5. Node.js node-serialize detection

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

local resp = http.get(TARGET)
if not resp then return end

local body = resp.body or ""
local headers = resp.headers or {}

-- ── 1. Java Deserialization Indicators ──────────────────────────────────────

-- Check for Java serialized data (magic bytes: AC ED 00 05 in hex / rO0AB in base64)
if body:find("rO0AB") or body:find("aced0005") then
    report.finding("high", "custom", "Java Serialized Object Detected",
        "Response contains Java serialized data (base64: rO0AB or hex: aced0005). " ..
        "If user-controllable, this is likely vulnerable to deserialization attacks " ..
        "(e.g., ysoserial gadget chains).", TARGET)
end

-- Check for common Java frameworks that use serialization
local java_indicators = {
    {pattern = "JSESSIONID", desc = "Java servlet session (JSESSIONID)"},
    {pattern = "X-Powered-By: JSF", desc = "JavaServer Faces (JSF ViewState)"},
    {pattern = "javax.faces.ViewState", desc = "JSF ViewState parameter"},
}
for _, ind in ipairs(java_indicators) do
    local found_in_body = body:find(ind.pattern, 1, true)
    local found_in_headers = false
    for k, v in pairs(headers) do
        if v:find(ind.pattern, 1, true) then
            found_in_headers = true
            break
        end
    end
    if found_in_body or found_in_headers then
        if ind.pattern == "javax.faces.ViewState" then
            report.finding("medium", "custom", "JSF ViewState Found (Deserialization Risk)",
                "Page contains javax.faces.ViewState. If not encrypted, this may be vulnerable " ..
                "to Java deserialization attacks.", TARGET)
        end
    end
end

-- ── 2. PHP Object Injection ────────────────────────────────────────────────

-- Look for PHP serialized data patterns in body (O:N:"ClassName":... or a:N:{...)
if body:find('O:%d+:"') or body:find("a:%d+:{") then
    report.finding("high", "custom", "PHP Serialized Data Detected",
        "Response contains PHP serialized objects. If user input flows into unserialize(), " ..
        "this is vulnerable to PHP Object Injection (POP chains, __wakeup/__destruct abuse).",
        TARGET)
end

-- Check cookies for PHP serialized data
for k, v in pairs(headers) do
    if k:lower() == "set-cookie" then
        if v:find('O:%d+:"') or v:find("a:%d+:{") then
            report.finding("high", "custom", "PHP Serialized Cookie Detected",
                "Cookie contains PHP serialized data. This is a strong indicator of " ..
                "insecure deserialization vulnerability.", TARGET)
        end
    end
end

-- ── 3. Python Pickle Detection ─────────────────────────────────────────────

-- Base64-encoded pickle starts with gASV (protocol 4) or \x80\x04
if body:find("gASV") then
    report.finding("high", "custom", "Python Pickle Data Detected",
        "Response contains what appears to be base64-encoded Python pickle data (gASV prefix). " ..
        "If user-controllable, this allows arbitrary code execution via pickle.loads().",
        TARGET)
end

-- ── 4. .NET ViewState Analysis ─────────────────────────────────────────────

-- Look for __VIEWSTATE in body
local viewstate_match = body:match('name="__VIEWSTATE"[^>]*value="([^"]*)"')
if viewstate_match then
    -- Check if it's unencrypted (starts with /wEP = base64 for 0xFF 0x01 0x0F)
    if viewstate_match:sub(1, 4) == "/wEP" then
        report.finding("medium", "custom", ".NET ViewState Without MAC",
            "ASP.NET ViewState detected without message authentication code (MAC). " ..
            "This may be vulnerable to deserialization attacks (CVE-2020-0688).",
            TARGET)
    else
        report.finding("info", "custom", ".NET ViewState Detected",
            "ASP.NET ViewState parameter found. Verify MAC validation is enabled " ..
            "and encryption is applied.", TARGET)
    end
end

-- ── 5. Node.js node-serialize Detection ────────────────────────────────────

-- Check for _$$ND_FUNC$$ pattern (node-serialize RCE marker)
if body:find("_$$ND_FUNC$$") then
    report.finding("critical", "custom", "Node.js node-serialize RCE Indicator",
        "Response contains '_$$ND_FUNC$$' pattern, indicating use of vulnerable " ..
        "node-serialize library (CVE-2017-5941). This allows arbitrary code execution.",
        TARGET)
end

-- Check cookies for serialized JavaScript objects
for k, v in pairs(headers) do
    if k:lower() == "set-cookie" then
        -- JSON in cookie (potential deserialization target)
        if v:find("{") and v:find("}") and
           (v:find('"username"') or v:find('"user"') or v:find('"data"')) then
            report.finding("medium", "custom", "JSON Object in Cookie",
                "Cookie contains a JSON object. If deserialized server-side with " ..
                "unsafe libraries, this may be exploitable.", TARGET)
        end
    end
end
