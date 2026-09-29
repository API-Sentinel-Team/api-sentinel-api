# AppSentinel — Complete End-to-End Flow Diagrams

---

## DIAGRAM 1 — Master System Overview

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                          APPSENTINEL — HOW IT ALL WORKS                            ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

  YOUR WEBSITE / APP                  APPSENTINEL SOC                   ANALYST BROWSER
  ─────────────────                  ───────────────                   ───────────────

  [User visits site]
       │
       ▼
  ┌─────────┐   HTTP    ┌───────────┐
  │ Browser │ ────────▶ │   nginx   │ ──────▶ [Your Web Application]
  └─────────┘           └───────────┘
                              │
                              │ writes every request
                              ▼
                     /var/log/nginx/access.log
                              │
                              │ tail -f (watches for new lines)
                              ▼
                     ┌─────────────────┐
                     │  log_shipper.py │  ← runs on YOUR server
                     │  (Python agent) │
                     └─────────────────┘
                              │
                              │ POST every 5 seconds
                              │ (batch of up to 500 lines)
                              ▼
                     ┌─────────────────────────────────────────┐
                     │         APPSENTINEL BACKEND             │
                     │         FastAPI + Python                │
                     │                                         │
                     │  POST /api/stream/ingest                │
                     │    │                                    │
                     │    ├─ 1. Parse log line (regex)         │
                     │    ├─ 2. Run 10 attack signatures       │
                     │    ├─ 3. Score threat actor             │
                     │    ├─ 4. Write to database              │
                     │    └─ 5. Broadcast via WebSocket        │
                     │                    │                    │
                     │             WebSocket hub               │
                     └─────────────────────────────────────────┘
                                          │
                              ┌───────────┴──────────┐
                              │    broadcasts to ALL  │
                              │    connected browsers │
                              ▼                       ▼
                     ┌──────────────┐       ┌──────────────┐
                     │  Analyst 1   │       │  Analyst 2   │
                     │  /live page  │       │  /live page  │
                     └──────────────┘       └──────────────┘
```

---

## DIAGRAM 2 — Request Journey (Step by Step)

```
STEP 1: User sends HTTP request to your website
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Browser → GET /api/users/123?id=1' OR '1'='1 HTTP/1.1
                          │
                          ▼ (nginx serves it)
  nginx writes to access.log:
  "45.142.12.100 - - [10/Mar/2026:14:30:00] "GET /api/users/123?id=1' OR '1'='1" 200 512"


STEP 2: log_shipper detects new line
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  log_shipper.py is watching the log file...
  ┌─────────────────────────────────────┐
  │  Buffer: 1 new line detected        │
  │  Timer: 5s not reached yet          │
  │  ...more lines come in...           │
  │  Timer: 5s reached → SHIP!          │
  └─────────────────────────────────────┘
  POST http://appsentinel:8000/api/stream/ingest
  Body: { "sensor_key": "abc123", "lines": ["45.142.12.100 ..."] }


STEP 3: Backend parses and detects attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Raw line: "45.142.12.100 - - [10/Mar/2026:14:30:00] "GET /api/users/123?id=1' OR '1'='1" 200 512"
                │
                ▼ regex parse
  {
    ip: "45.142.12.100",
    method: "GET",
    path: "/api/users/123?id=1' OR '1'='1",
    status: 200,
    bytes: 512,
    timestamp: "2026-03-10T14:30:00"
  }
                │
                ▼ run 10 attack patterns
  ┌────────────────────────────────────────────────────────┐
  │  SQL Injection pattern:  OR '1'='1  ← MATCH!          │
  │  Blind SQLi pattern:     SLEEP(     → no match        │
  │  XSS pattern:            <script    → no match        │
  │  Path Traversal:         ../        → no match        │
  │  Command Injection:      ;cat       → no match        │
  │  SSRF:                   file://    → no match        │
  │  ... (10 total checks)                                 │
  └────────────────────────────────────────────────────────┘
  RESULT: SQL Injection detected! Severity: HIGH


STEP 4: Database writes (all at once)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ┌─────────────────────────┐
  │  RequestLog             │  ← every request logged here
  │  ip: 45.142.12.100      │
  │  path: /api/users/123   │
  │  status: 200            │
  └─────────────────────────┘

  ┌─────────────────────────┐
  │  MaliciousEventRecord   │  ← created because attack found
  │  category: SQL Injection│
  │  severity: HIGH         │
  │  payload: OR '1'='1     │
  └─────────────────────────┘

  ┌─────────────────────────┐
  │  ThreatActor (UPSERT)   │  ← actor score updated
  │  ip: 45.142.12.100      │
  │  event_count: +1        │
  │  risk_score: +0.5 (HIGH)│
  └─────────────────────────┘

  ┌─────────────────────────┐
  │  Alert (auto-created)   │  ← because severity = HIGH
  │  title: SQL Injection   │
  │  status: OPEN           │
  │  source_ip: 45.142.12.100│
  └─────────────────────────┘


STEP 5: WebSocket broadcast to dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ws_manager.broadcast({
    type: "log_entry",
    data: {
      ip: "45.142.12.100",
      method: "GET",
      path: "/api/users/123?id=1' OR '1'='1",
      status: 200,
      attacks: [{ category: "SQL Injection", severity: "HIGH" }],
      blocked: false
    }
  })
  → Delivered INSTANTLY to every analyst's browser


STEP 6: Dashboard shows the attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LiveFeed.tsx receives WebSocket message
  → New row added at TOP of table
  → Row background = RED (attack detected)
  → Badge shows "SQL Injection — HIGH"
  → Threats counter increments
  → RPM counter updates
```

---

## DIAGRAM 3 — Authentication Flow

```
  USER                    FRONTEND                    BACKEND                  DATABASE
  ────                    ────────                    ───────                  ────────

  fills login form
       │
       ▼
  [clicks Login]
       │
       ▼
                    POST /api/auth/login
                    { email, password }
                          │
                          ▼
                                          check rate limit (5/min)
                                               │
                                               ▼
                                          find user by email
                                               │
                                               ▼
                                                           SELECT * FROM users
                                                           WHERE email = ?
                                                                │
                                                                ▼
                                                           returns user row
                                               │
                                               ▼
                                          bcrypt.verify(
                                            password,
                                            user.hashed_password
                                          )
                                               │
                                         ┌─────┴─────┐
                                      WRONG          CORRECT
                                         │              │
                                         ▼              ▼
                                    401 error     create JWT token:
                                                  {
                                                    sub: user.id,
                                                    email: user.email,
                                                    account_id: 1000001,
                                                    role: "ADMIN",
                                                    exp: now + 24h
                                                  }
                                                  sign with SECRET_KEY
                                                       │
                          200 OK ◄─────────────────────┘
                          { token: "eyJhbG..." }
                          │
                          ▼
                    save to localStorage:
                    sentinel_token = "eyJhbG..."
                          │
                          ▼
                    redirect to /dashboard


  ALL FUTURE API CALLS:
  ─────────────────────
  Frontend automatically adds header:
  Authorization: Bearer eyJhbG...
                          │
                          ▼
                                          require_auth() middleware:
                                          1. Extract Bearer token
                                          2. jwt.decode(token, SECRET_KEY)
                                          3. Check expiry
                                          4. Return current_user
                                               │
                                         ┌─────┴─────┐
                                      INVALID      VALID
                                         │              │
                                         ▼              ▼
                                    401 error     proceed to endpoint
```

---

## DIAGRAM 4 — Live Feed (WebSocket Flow)

```
  BROWSER                              BACKEND SERVER
  ───────                              ──────────────

  User opens /live page
       │
       ▼
  LiveFeed.tsx mounts
       │
       ▼
  new WebSocket(
    "ws://localhost:8000/api/stream/live
     ?token=eyJhbG..."
  )
       │
       ▼
  WS connection request ─────────────────────────▶  /api/stream/live
                                                        │
                                                        ▼
                                                   validate token
                                                        │
                                                        ▼
                                                   ws_manager.connect(ws)
                                                   (added to active list)
                                                        │
                                                        ▼
  ◀─────────── send last 20 events (history) ──────────┘
       │
       ▼
  shows 20 rows in table
  (recent attacks/requests)


  LIVE STREAMING:
  ───────────────

  [log_shipper sends new lines]
       │
       ▼
  /api/stream/ingest
  detects attack → writes DB
       │
       ▼
  ws_manager.broadcast(event)
       │
       ├──────────────────────────▶  Browser 1 (/live)
       ├──────────────────────────▶  Browser 2 (/live)
       └──────────────────────────▶  Browser 3 (/live)

  Each browser:
  onmessage = (event) => {
    data = JSON.parse(event.data)
    setFeed(prev => [data, ...prev].slice(0, 200))
    // max 200 rows kept in memory
  }


  RECONNECT LOGIC:
  ────────────────
  WS closes (network blip)
       │
       ▼
  onclose fires
       │
       ▼
  wait 3 seconds
       │
       ▼
  reconnect automatically
  (max 5 attempts, then shows error banner)
```

---

## DIAGRAM 5 — Attack Detection Engine

```
  INPUT: raw nginx log line
  ═══════════════════════════════════════════════════════
  "45.0.0.1 - - [date] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "sqlmap/1.0""


  STAGE 1: REGEX PARSE
  ───────────────────────────────────────
  Pattern: ^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+) "([^"]*)" "([^"]*)"$
                │
                ▼
  {
    ip:         "45.0.0.1"
    timestamp:  "date"
    method:     "GET"
    path:       "/search?q=<script>alert(1)</script>"
    status:     200
    bytes:      512
    user_agent: "sqlmap/1.0"
  }


  STAGE 2: URL DECODE
  ───────────────────────────────────────
  /search?q=%3Cscript%3Ealert(1)%3C/script%3E
                │  url decode
                ▼
  /search?q=<script>alert(1)</script>
  (encoded attacks are caught too)


  STAGE 3: SIGNATURE MATCHING (runs all 10 in parallel)
  ───────────────────────────────────────
  Check path + user_agent against each pattern:

  ┌──────────────────────────────────────────────────────────────┐
  │  Pattern              │ Check          │ Result              │
  ├──────────────────────────────────────────────────────────────┤
  │  SQL Injection        │ path           │ ✗ no match          │
  │  Blind SQLi           │ path           │ ✗ no match          │
  │  XSS                  │ path           │ ✓ <script> MATCH!   │
  │  Path Traversal       │ path           │ ✗ no match          │
  │  Command Injection    │ path           │ ✗ no match          │
  │  Code Injection       │ path           │ ✗ no match          │
  │  Scanning Tool        │ user_agent     │ ✓ sqlmap MATCH!     │
  │  Sensitive File       │ path           │ ✗ no match          │
  │  LDAP Injection       │ path           │ ✗ no match          │
  │  SSRF                 │ path           │ ✗ no match          │
  └──────────────────────────────────────────────────────────────┘

  DETECTED: 2 attacks
    → XSS (HIGH) from path
    → Scanning Tool (MEDIUM) from user_agent


  STAGE 4: RISK SCORING
  ───────────────────────────────────────
  ThreatActor for ip 45.0.0.1:
    previous risk_score: 3.0
    + XSS (HIGH):    +0.5  → 3.5
    + Scan (MEDIUM): +0.1  → 3.6
    capped at 10.0 max

  UI display: 3.6 × 10 = 36/100


  STAGE 5: AUTO-ACTIONS
  ───────────────────────────────────────
  risk_score >= 8.0 (80)?  → NO → skip auto-block
  severity = CRITICAL?     → NO → skip immediate block
  severity = HIGH?         → YES → create Alert (OPEN)


  OUTPUT:
  ───────────────────────────────────────
  → DB: RequestLog (always)
  → DB: MaliciousEventRecord (attacks only)
  → DB: ThreatActor updated (attacks only)
  → DB: Alert created (HIGH or CRITICAL only)
  → WS: broadcast to all live dashboards
```

---

## DIAGRAM 6 — Log Shipper Agent Internal Flow

```
  START: python log_shipper.py --key abc123 --log /var/log/nginx/access.log
                │
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  INITIALIZATION                                         │
  │  1. Parse CLI arguments                                 │
  │  2. Verify log file exists                              │
  │  3. Register/verify sensor key with backend             │
  │  4. Seek to END of file (skip old lines)                │
  │     (unless --from-start flag used)                     │
  └─────────────────────────────────────────────────────────┘
                │
                ▼
  ┌─────────────────────────────────────────────────────────┐
  │  MAIN LOOP (runs forever)                               │
  │                                                         │
  │  Every iteration (0.5s sleep):                          │
  │    ┌──────────────────────────────────────────────┐     │
  │    │  1. Read new lines from log file             │     │
  │    │     • Check if file shrank (log rotation)    │     │
  │    │       → If yes: reopen from beginning        │     │
  │    │     • readline() all new content             │     │
  │    │     • Add to buffer[]                        │     │
  │    └──────────────────────────────────────────────┘     │
  │                                                         │
  │    ┌──────────────────────────────────────────────┐     │
  │    │  2. Should we ship?                          │     │
  │    │     Check: buffer.length >= 500?  → YES      │     │
  │    │     Check: time since last ship >= 5s? → YES │     │
  │    │     Either condition → SHIP                  │     │
  │    └──────────────────────────────────────────────┘     │
  │                                                         │
  │    ┌──────────────────────────────────────────────┐     │
  │    │  3. SHIP batch                               │     │
  │    │     POST /api/stream/ingest                  │     │
  │    │     { sensor_key, lines: [...] }             │     │
  │    │                                              │     │
  │    │     SUCCESS → clear buffer, reset timer      │     │
  │    │     FAIL    → retry with backoff:            │     │
  │    │               1s → 2s → 5s → 10s → 30s      │     │
  │    └──────────────────────────────────────────────┘     │
  │                                                         │
  │    ┌──────────────────────────────────────────────┐     │
  │    │  4. Heartbeat (every 30s)                    │     │
  │    │     POST /api/sensors/{key}/heartbeat        │     │
  │    │     → keeps sensor status = ONLINE           │     │
  │    │     → if silent > 120s: auto-OFFLINE         │     │
  │    └──────────────────────────────────────────────┘     │
  └─────────────────────────────────────────────────────────┘
```

---

## DIAGRAM 7 — Alert Lifecycle

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                      ALERT CREATION                               │
  │                                                                   │
  │  Attack detected (HIGH or CRITICAL severity)                      │
  │       │                                                           │
  │       ▼                                                           │
  │  Auto-create Alert:                                               │
  │  {                                                                │
  │    title:     "SQL Injection Detected"                            │
  │    message:   "Attack from 45.0.0.1 on /api/login"               │
  │    severity:  "HIGH"                                              │
  │    category:  "SQL Injection"                                     │
  │    source_ip: "45.0.0.1"                                         │
  │    endpoint:  "/api/login"                                        │
  │    status:    "OPEN"    ◄─── starts here                         │
  │  }                                                                │
  └───────────────────────────────────────────────────────────────────┘
                          │
                          │ Alert shown in /alerts page
                          │ (auto-refreshes every 30s)
                          ▼

  ┌─────────┐         ┌─────────────┐         ┌──────────┐
  │  OPEN   │─────────▶ ACKNOWLEDGED │─────────▶ RESOLVED │
  │         │         │             │         │          │
  │ New     │ analyst │ Someone is  │ issue   │ Closed   │
  │ threat  │ clicks  │ looking     │ fixed   │ out      │
  │ found   │ "Ack"   │ into it     │         │          │
  └─────────┘         └─────────────┘         └──────────┘
       │                                            │
       │                                            │
       └──────── analyst clicks "Delete" ───────────┘
                          │
                          ▼
                     Alert removed
                  (for false positives)


  ALERT SEVERITY COLORS:
  ───────────────────────────────────────
  CRITICAL → Red  border  (left side of card)
  HIGH     → Orange border
  MEDIUM   → Yellow border
  LOW      → Blue border
```

---

## DIAGRAM 8 — IP Block List Flow

```
  METHOD 1: MANUAL BLOCK
  ──────────────────────
  Analyst sees attack from 45.0.0.1
       │
       ▼
  Opens /blocklist page
       │
       ▼
  Clicks "Block IP" button
  Fills: IP = 45.0.0.1, Reason = "SQL Injection attack", Expiry = 24h
       │
       ▼
  POST /api/blocklist/ { ip, reason, expires_in_hours: 24 }
       │
       ▼
  BlockedIP record created in DB


  METHOD 2: AUTO BLOCK (one click)
  ─────────────────────────────────
  Analyst clicks "Auto-Block High Risk"
       │
       ▼
  POST /api/blocklist/auto { threshold: 80 }
       │
       ▼
  Backend queries: SELECT * FROM threat_actors WHERE risk_score >= 80
       │
       ▼
  For each high-risk actor → create BlockedIP entry
       │
       ▼
  Returns count of newly blocked IPs


  METHOD 3: EXPORT TO NGINX
  ──────────────────────────
  Analyst clicks "Export nginx deny list"
       │
       ▼
  GET /api/blocklist/export/nginx
       │
       ▼
  Backend generates plain text:
  ┌──────────────────────────────────────────────────┐
  │ # AppSentinel Block List — 2026-03-10            │
  │ # Generated automatically — do not edit manually │
  │                                                  │
  │ deny 45.0.0.1;    # SQL Injection | risk=92      │
  │ deny 10.20.30.40; # XSS | risk=85 | by=AUTO      │
  │ deny 192.168.1.5; # Scanning | risk=81 | by=MANUAL│
  └──────────────────────────────────────────────────┘
       │
       ▼
  File downloaded as appsentinel_blocklist.conf
       │
       ▼
  Admin copies to nginx server:
  cp appsentinel_blocklist.conf /etc/nginx/
       │
       ▼
  Add to nginx.conf:
  include /etc/nginx/appsentinel_blocklist.conf;
       │
       ▼
  nginx -s reload
       │
       ▼
  Blocked IPs now receive 403 Forbidden
  (enforced at nginx level, before reaching app)
```

---

## DIAGRAM 9 — Multi-Sensor Architecture

```
  (for monitoring multiple websites)

  ┌──────────────────────────────────────────────────────────────────┐
  │                      YOUR INFRASTRUCTURE                        │
  │                                                                  │
  │  nginx Server 1          nginx Server 2          nginx Server 3  │
  │  (api.company.com)       (app.company.com)       (admin.company) │
  │        │                       │                       │         │
  │  log_shipper.py          log_shipper.py          log_shipper.py  │
  │  --key SENSOR_KEY_1      --key SENSOR_KEY_2      --key SENSOR_3  │
  │        │                       │                       │         │
  └────────┼───────────────────────┼───────────────────────┼─────────┘
           │                       │                       │
           │     POST /api/stream/ingest (with sensor_key) │
           └──────────────────┬────┴───────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │   APPSENTINEL BACKEND   │
                │                         │
                │  Identifies which sensor│
                │  sent each batch        │
                │  account_id isolation   │
                └─────────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │  /system-health page    │
                │                         │
                │  Sensor 1: ● ONLINE     │
                │  Last beat: 5s ago      │
                │  Lines shipped: 45,231  │
                │                         │
                │  Sensor 2: ● ONLINE     │
                │  Last beat: 12s ago     │
                │  Lines shipped: 12,044  │
                │                         │
                │  Sensor 3: ○ OFFLINE    │  ← went silent > 2 min
                │  Last beat: 5min ago    │
                └─────────────────────────┘
```

---

## DIAGRAM 10 — Frontend Page Data Sources

```
  PAGE              DATA SOURCE              REFRESH METHOD
  ────              ───────────              ──────────────

  /live          ── WebSocket (push)      ── Instant (real-time)
                    + GET /api/stream/recent (initial load)

  /alerts        ── GET /api/alerts/      ── Every 30 seconds
                    GET /api/alerts/summary    (React Query)

  /blocklist     ── GET /api/blocklist/   ── On page load
                    GET /api/blocklist/summary  + after mutations

  /dashboard     ── GET /api/dashboard/   ── On page load
                    (aggregated metrics)

  /protection    ── GET /api/threat-actors/events  ── On page load
                    GET /api/threat-actors/geo
                    GET /api/threat-actors/

  /discovery     ── GET /api/endpoints/   ── On page load
                    GET /api/collections/

  /testing       ── GET /api/vulnerabilities/  ── On page load
                    GET /api/vulnerabilities/trend

  /reports       ── GET /api/compliance/  ── On page load
                    GET /api/compliance/owasp

  /system-health ── GET /api/sensors/     ── Every 30 seconds
                    GET /api/sensors/summary

  /settings      ── GET /api/auth/users   ── On page load
                    GET /api/integrations/
```

---

## DIAGRAM 11 — Database Write Flow (What Gets Stored Where)

```
  EVERY HTTP request that arrives:
  ─────────────────────────────────
  → request_logs table  (always written)
    { source_ip, method, path, status_code, bytes, timestamp }

  ONLY IF attack detected:
  ─────────────────────────────────
  → malicious_event_records table
    { ip, url, category, severity, payload, detected_at }

  → threat_actors table  (UPSERT — update if exists)
    { source_ip, event_count+1, risk_score+=delta, last_seen=now }

  ONLY IF severity = HIGH or CRITICAL:
  ─────────────────────────────────
  → alerts table
    { title, message, severity, source_ip, status=OPEN }

  ONLY IF risk_score >= 80 AND auto-block enabled:
  ─────────────────────────────────
  → blocked_ips table
    { ip, reason, blocked_by=AUTO, risk_score }

  EVERY 30 seconds from log_shipper:
  ─────────────────────────────────
  → sensors table  (UPDATE heartbeat)
    { last_heartbeat=now, lines_shipped+=batch_size }

  EVERY user action in UI:
  ─────────────────────────────────
  → audit_logs table  (always)
    { action, user_id, resource_type, ip_address, timestamp }
```

---

## DIAGRAM 12 — Complete Technology Stack Map

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        BROWSER (React)                              │
  │                                                                     │
  │  React 18 + TypeScript + Vite                                       │
  │  ├── React Router (page routing)                                    │
  │  ├── TanStack Query (REST data fetching + caching)                  │
  │  ├── Zustand (login state)                                          │
  │  ├── WebSocket API (live feed)                                      │
  │  ├── shadcn/ui + Radix (buttons, modals, tables)                    │
  │  ├── Tailwind CSS (styling)                                         │
  │  ├── Recharts (graphs)                                              │
  │  └── Plus Jakarta Sans font                                         │
  └───────────────────────┬─────────────────────────────────────────────┘
                          │  HTTP (port 8000) + WS
                          │  /api/* proxy via Vite (dev)
                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     BACKEND (Python)                                │
  │                                                                     │
  │  FastAPI (async REST framework)                                     │
  │  ├── Uvicorn (ASGI server)                                          │
  │  ├── slowapi (rate limiting)                                        │
  │  ├── PyJWT + bcrypt (auth)                                          │
  │  ├── SQLAlchemy 2.0 async (ORM)                                     │
  │  ├── Alembic (DB migrations)                                        │
  │  ├── scikit-learn (ML anomaly detection)                            │
  │  ├── spacy + presidio (NLP + PII detection)                         │
  │  ├── APScheduler (background jobs)                                  │
  │  └── structlog (structured logging)                                 │
  └───────────────────────┬─────────────────────────────────────────────┘
                          │  SQLAlchemy async queries
                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    DATABASE (SQLite)                                │
  │                                                                     │
  │  aiosqlite (async SQLite driver)                                    │
  │  File: api_security.db                                              │
  │  35 tables, all with account_id column (multi-tenant)               │
  │                                                                     │
  │  Key tables:                                                        │
  │  users, request_logs, malicious_event_records, threat_actors,       │
  │  alerts, blocked_ips, sensors, api_endpoints, vulnerabilities,      │
  │  audit_logs, integrations                                           │
  └─────────────────────────────────────────────────────────────────────┘
                          │
                    separate process
                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                 LOG SHIPPER (Python Agent)                          │
  │                                                                     │
  │  log_shipper.py  — runs on nginx server                             │
  │  ├── tail -f equivalent (file watching)                             │
  │  ├── batch buffer (500 lines or 5s)                                 │
  │  ├── HTTP POST to /api/stream/ingest                                │
  │  ├── heartbeat every 30s                                            │
  │  └── retry backoff on failure                                       │
  └─────────────────────────────────────────────────────────────────────┘
```

---

*AppSentinel Flow Diagrams — Version 1.0 — March 2026*
