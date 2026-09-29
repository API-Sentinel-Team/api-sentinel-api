# ============================================================
# API Sentinel - End-to-End Test Script (FINAL)
# Auth uses httpOnly cookies - uses WebSession to persist them
# ============================================================
$BASE = "http://127.0.0.1:8000"
$PASS = 0; $FAIL_COUNT = 0

function Step($m)   { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function OK($m)     { Write-Host "  [OK]   $m" -ForegroundColor Green;  $script:PASS++ }
function FAIL($m)   { Write-Host "  [FAIL] $m" -ForegroundColor Red;    $script:FAIL_COUNT++ }
function INFO($m)   { Write-Host "  [INFO] $m" -ForegroundColor Yellow }
function Chk($c,$l) { if ($c) { OK $l } else { FAIL $l } }

# ── STEP 1: Health ──────────────────────────────────────────
Step "STEP 1 - Backend Health Check"
try {
    $h = Invoke-RestMethod "$BASE/api/health" -Method Get -TimeoutSec 10
    Chk ($h.status -eq "healthy") "Backend healthy"
    Chk ($h.database.status -eq "connected") "Database connected ($($h.database.type))"
    INFO "Pre-test: endpoints=$($h.stats.total_endpoints) actors=$($h.stats.total_threat_actors) events=$($h.stats.total_events)"
} catch { FAIL "Health failed: $($_.Exception.Message)"; exit 1 }

# ── STEP 2: Signup ──────────────────────────────────────────
Step "STEP 2 - Signup (POST /api/auth/signup)"
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$signupBody = '{"email":"e2etest@example.com","password":"TestPass123!","account_name":"E2E Corp"}'
try {
    $signup = Invoke-RestMethod "$BASE/api/auth/signup" -Method Post `
        -Body $signupBody -ContentType "application/json" `
        -WebSession $session -TimeoutSec 10
    OK "Signed up | Account ID: $($signup.account_id)"
} catch {
    $errMsg = $_.ErrorDetails.Message
    if ($errMsg -match "already") {
        INFO "Account already exists - logging in"
    } else {
        INFO "Signup error: $errMsg"
    }
}

# ── STEP 3: Login (cookie-based) ────────────────────────────
Step "STEP 3 - Login (POST /api/auth/login)"
$loginBody = '{"email":"e2etest@example.com","password":"TestPass123!"}'
try {
    $login = Invoke-RestMethod "$BASE/api/auth/login" -Method Post `
        -Body $loginBody -ContentType "application/json" `
        -WebSession $session -TimeoutSec 10
    Chk ($login.status -eq "authenticated") "Login successful"
    INFO "Role: $($login.role)"
    # Verify cookie was set
    $cookieCount = $session.Cookies.GetCookies("$BASE").Count
    Chk ($cookieCount -gt 0) "Auth cookie received ($cookieCount cookies)"
} catch { FAIL "Login failed: $($_.Exception.Message)"; exit 1 }

# ── STEP 4: Verify /me ──────────────────────────────────────
Step "STEP 4 - Verify /auth/me (uses cookie auth)"
try {
    $me = Invoke-RestMethod "$BASE/api/auth/me" -Method Get -WebSession $session -TimeoutSec 10
    Chk ($me.email -eq "e2etest@example.com") "Got current user: $($me.email)"
    $ACCOUNT_ID = $me.account_id
    INFO "User ID: $($me.user_id) | Account: $ACCOUNT_ID | Role: $($me.role)"
} catch { FAIL "Get /me failed: $($_.Exception.Message)"; exit 1 }

# ── STEP 5: Nginx Log Upload ─────────────────────────────────
Step "STEP 5 - Inject Traffic via Nginx Log Upload (30 requests)"
$NOW = Get-Date -Format "dd/MMM/yyyy:HH:mm:ss +0000"
$nginxLog = @"
10.0.0.1 - - [$NOW] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.1 - - [$NOW] "POST /api/users HTTP/1.1" 201 512 "-" "Mozilla/5.0"
10.0.0.2 - - [$NOW] "GET /api/users/123 HTTP/1.1" 200 890 "-" "Mozilla/5.0"
10.0.0.2 - - [$NOW] "PUT /api/users/123 HTTP/1.1" 200 456 "-" "Mozilla/5.0"
10.0.0.3 - - [$NOW] "DELETE /api/users/123 HTTP/1.1" 204 0 "-" "Mozilla/5.0"
10.0.0.4 - - [$NOW] "GET /api/products HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
10.0.0.4 - - [$NOW] "GET /api/products/456 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
10.0.0.5 - - [$NOW] "POST /api/orders HTTP/1.1" 201 768 "-" "Mozilla/5.0"
10.0.0.5 - - [$NOW] "GET /api/orders/789 HTTP/1.1" 200 900 "-" "Mozilla/5.0"
10.0.0.6 - - [$NOW] "POST /api/auth/login HTTP/1.1" 200 300 "-" "Mozilla/5.0"
10.0.0.7 - - [$NOW] "GET /api/payments HTTP/1.1" 200 1500 "-" "Mozilla/5.0"
10.0.0.8 - - [$NOW] "POST /api/payments HTTP/1.1" 201 600 "-" "Mozilla/5.0"
10.0.0.9 - - [$NOW] "GET /api/admin/settings HTTP/1.1" 200 400 "-" "Mozilla/5.0"
10.0.0.10 - - [$NOW] "GET /api/reports HTTP/1.1" 200 3200 "-" "Mozilla/5.0"
10.0.0.11 - - [$NOW] "GET /api/customers HTTP/1.1" 200 500 "-" "Mozilla/5.0"
192.168.99.1 - - [$NOW] "GET /api/users HTTP/1.1" 500 200 "-" "sqlmap/1.7 union select null,username,password from users--"
192.168.99.1 - - [$NOW] "POST /api/login HTTP/1.1" 200 300 "-" "sqlmap/1.7 OR 1=1 --"
192.168.99.1 - - [$NOW] "GET /api/products HTTP/1.1" 500 100 "-" "1; DROP TABLE users; --"
172.16.0.1 - - [$NOW] "GET /api/search HTTP/1.1" 200 400 "-" "onerror=alert(1) src=x javascript:void"
172.16.0.2 - - [$NOW] "GET /api/profile HTTP/1.1" 200 300 "-" "onload=fetch evil.com alert(xss)"
10.10.10.1 - - [$NOW] "GET /api/files/../../etc/passwd HTTP/1.1" 200 1000 "-" "curl/7.64"
10.10.10.1 - - [$NOW] "GET /api/download/../../../etc/shadow HTTP/1.1" 403 0 "-" "curl/7.64"
10.10.10.2 - - [$NOW] "GET /api/logs/%2e%2e%2fetc%2fpasswd HTTP/1.1" 200 500 "-" "scanner/1.0"
185.220.101.1 - - [$NOW] "POST /api/ping HTTP/1.1" 200 50 "-" "cmd.exe /c whoami"
185.220.101.2 - - [$NOW] "GET /api/exec HTTP/1.1" 200 50 "-" "powershell -enc aGVsbG8="
185.220.101.3 - - [$NOW] "POST /api/run HTTP/1.1" 500 0 "-" "eval(base64_decode(exploit))"
10.0.0.1 - - [$NOW] "GET /api/invoices HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.2 - - [$NOW] "POST /api/invoices HTTP/1.1" 201 890 "-" "Mozilla/5.0"
10.0.0.3 - - [$NOW] "GET /api/categories HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
10.0.0.4 - - [$NOW] "GET /health HTTP/1.1" 200 50 "-" "HealthChecker/1.0"
"@

$logFile = [System.IO.Path]::Combine($env:TEMP, "sentinel_e2e_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).log")
[System.IO.File]::WriteAllText($logFile, $nginxLog, [System.Text.Encoding]::UTF8)

try {
    $boundary = "----FormBoundary" + [System.Guid]::NewGuid().ToString("N")
    $LF = "`r`n"
    $bodyParts  = "--$boundary$LF"
    $bodyParts += "Content-Disposition: form-data; name=`"file`"; filename=`"access.log`"$LF"
    $bodyParts += "Content-Type: text/plain$LF$LF"
    $bodyParts += $nginxLog + $LF
    $bodyParts += "--$boundary--"
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyParts)

    $nginxResp = Invoke-RestMethod "$BASE/api/traffic/import/nginx-log" -Method Post `
        -Body $bodyBytes `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -WebSession $session -TimeoutSec 30

    Chk ($nginxResp.status -eq "ok") "Nginx log uploaded: status=$($nginxResp.status)"
    OK "Lines processed:     $($nginxResp.lines)"
    OK "Endpoints found:     $($nginxResp.endpoints_discovered)"
    OK "Request logs:        $($nginxResp.request_logs)"
    OK "Threats detected:    $($nginxResp.threats_detected)"
} catch {
    FAIL "Nginx log upload: $($_.Exception.Message)"
    try {
        $errBody = $_.ErrorDetails.Message
        INFO "Error details: $errBody"
    } catch {}
}
if (Test-Path $logFile) { Remove-Item $logFile -Force }

# ── STEP 6: v2/events injection ─────────────────────────────
Step "STEP 6 - Inject via v2/events API (5 more events)"
$NOW_TS = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$payload6 = "{`"version`":`"v1`",`"events`":[{`"method`":`"GET`",`"path`":`"/api/subscriptions`",`"host`":`"app.example.com`",`"status_code`":200,`"source_ip`":`"10.5.5.1`",`"ts`":$NOW_TS},{`"method`":`"POST`",`"path`":`"/api/subscriptions`",`"host`":`"app.example.com`",`"status_code`":201,`"source_ip`":`"10.5.5.2`",`"ts`":$NOW_TS},{`"method`":`"GET`",`"path`":`"/api/webhooks`",`"host`":`"app.example.com`",`"status_code`":200,`"source_ip`":`"10.5.5.3`",`"ts`":$NOW_TS},{`"method`":`"GET`",`"path`":`"/api/users`",`"host`":`"app.example.com`",`"status_code`":500,`"source_ip`":`"10.6.6.1`",`"ts`":$NOW_TS,`"headers`":{`"user-agent`":`"sqlmap/1.7 union select null--`"}},{`"method`":`"GET`",`"path`":`"/api/admin`",`"host`":`"app.example.com`",`"status_code`":403,`"source_ip`":`"10.7.7.1`",`"ts`":$NOW_TS,`"headers`":{`"user-agent`":`"nmap scanner nikto`"}}]}"
try {
    $r6 = Invoke-RestMethod "$BASE/api/ingestion/v2/events" -Method Post `
        -Body $payload6 -ContentType "application/json" `
        -WebSession $session -TimeoutSec 15
    Chk ($r6.events_processed -gt 0) "v2/events: $($r6.events_processed) events processed"
    INFO "Threats from v2: $($r6.threats_detected)"
} catch { FAIL "v2/events: $($_.Exception.Message)" }

# ── STEP 7: Backend Stats after ingestion ───────────────────
Step "STEP 7 - Backend Stats after Ingestion"
$h2 = Invoke-RestMethod "$BASE/api/health" -Method Get -TimeoutSec 10
Chk ($h2.stats.total_endpoints -gt 0) "Endpoints discovered: $($h2.stats.total_endpoints)"
Chk ($h2.stats.total_threat_actors -gt 0) "Threat actors tracked: $($h2.stats.total_threat_actors)"
Chk ($h2.stats.total_events -gt 0) "Malicious events logged: $($h2.stats.total_events)"

# ── STEP 8: Alerts ──────────────────────────────────────────
Step "STEP 8 - Alerts"
try {
    $alertList = Invoke-RestMethod "$BASE/api/alerts/" -Method Get -WebSession $session -TimeoutSec 10
    Chk ($alertList.Count -gt 0) "Alerts created: $($alertList.Count)"
    $alertList | Select-Object -First 5 | ForEach-Object { INFO "  [$($_.severity)] $($_.title)" }
} catch { FAIL "Alerts: $($_.Exception.Message)" }

# ── STEP 9: Alert Summary ───────────────────────────────────
Step "STEP 9 - Alert Summary"
try {
    $sum = Invoke-RestMethod "$BASE/api/alerts/summary" -Method Get -WebSession $session -TimeoutSec 10
    OK "Total=$($sum.total) Open=$($sum.open) Critical=$($sum.critical) High=$($sum.high) Medium=$($sum.medium)"
} catch { INFO "Alert summary: $($_.Exception.Message)" }

# ── STEP 10: API Inventory ──────────────────────────────────
Step "STEP 10 - API Endpoint Inventory"
try {
    $eps = Invoke-RestMethod "$BASE/api/endpoints" -Method Get -WebSession $session -TimeoutSec 10
    $epList = if ($eps.endpoints) { $eps.endpoints } elseif ($eps -is [array]) { $eps } else { @() }
    Chk ($epList.Count -gt 0) "API endpoints in inventory: $($epList.Count)"
    $epList | Select-Object -First 10 | ForEach-Object {
        $p = if ($_.path_pattern) { $_.path_pattern } else { $_.path }
        INFO "  $($_.method) $p"
    }
} catch { FAIL "Endpoints: $($_.Exception.Message)" }

# ── STEP 11: Threat Actors ──────────────────────────────────
Step "STEP 11 - Threat Actors"
try {
    $actors = Invoke-RestMethod "$BASE/api/threat-actors" -Method Get -WebSession $session -TimeoutSec 10
    $actorList = if ($actors.actors) { $actors.actors } elseif ($actors -is [array]) { $actors } else { @() }
    Chk ($actorList.Count -gt 0) "Threat actors: $($actorList.Count)"
    $actorList | ForEach-Object {
        INFO "  IP=$($_.source_ip) Risk=$([math]::Round($_.risk_score,2)) Events=$($_.event_count)"
    }
} catch { FAIL "Threat actors: $($_.Exception.Message)" }

# ── STEP 12: Dashboard ──────────────────────────────────────
Step "STEP 12 - Dashboard Overview"
try {
    $dash = Invoke-RestMethod "$BASE/api/dashboard/overview" -Method Get -WebSession $session -TimeoutSec 10
    OK "Dashboard loaded - keys: $($dash.PSObject.Properties.Name -join ', ')"
} catch { INFO "Dashboard: $($_.Exception.Message)" }

# ── STEP 13: Collections ────────────────────────────────────
Step "STEP 13 - API Collections"
try {
    $cols = Invoke-RestMethod "$BASE/api/collections" -Method Get -WebSession $session -TimeoutSec 10
    $colList = if ($cols.collections) { $cols.collections } elseif ($cols -is [array]) { $cols } else { @() }
    Chk ($colList.Count -gt 0) "Collections: $($colList.Count)"
    $colList | ForEach-Object { $ec = if ($_.endpoint_count) { $_.endpoint_count } else { "?" }; INFO "  $($_.name) ($($_.type)) - $ec endpoints" }
} catch { FAIL "Collections: $($_.Exception.Message)" }

# ── FINAL REPORT ─────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor White
Write-Host "  END-TO-END TEST RESULTS" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host "  PASSED : $PASS" -ForegroundColor Green
Write-Host "  FAILED : $FAIL_COUNT" -ForegroundColor $(if ($FAIL_COUNT -gt 0) {"Red"} else {"Green"})
Write-Host ""
Write-Host "  Backend Stats after E2E:" -ForegroundColor White
Write-Host "    Endpoints   : $($h2.stats.total_endpoints)" -ForegroundColor Green
Write-Host "    Threat IPs  : $($h2.stats.total_threat_actors)" -ForegroundColor Red
Write-Host "    Bad Events  : $($h2.stats.total_events)" -ForegroundColor Red
Write-Host ""
Write-Host "  Open UI at http://127.0.0.1:5173 :" -ForegroundColor Cyan
Write-Host "    /app/dashboard              -> KPIs + threat overview" -ForegroundColor Cyan
Write-Host "    /app/discovery/catalogue    -> API endpoint inventory" -ForegroundColor Cyan
Write-Host "    /app/protection/alerts      -> security alerts" -ForegroundColor Cyan
Write-Host "    /app/protection/live-feed   -> real-time traffic feed" -ForegroundColor Cyan
Write-Host "    /app/protection/threat-actors -> attacker IPs" -ForegroundColor Cyan
Write-Host ""
