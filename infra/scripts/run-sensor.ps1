#Requires -Version 5.1
<#
.SYNOPSIS
  Pull and run the Argus api-sentinel-sensor (Linux eBPF) via Docker.

.NOTES
  - Registry is private: docker login registry.gitlab.com first (GitLab PAT with read_registry).
  - eBPF needs Linux kernel >= 5.8. Docker Desktop uses a Linux VM; BPF may still fail — use bare-metal Linux for production.

.EXAMPLE
  .\infra\scripts\run-sensor.ps1 -ApiKey "your-sensor-key" -IngestUrl "https://api.example.com/v1/events" -AccountId 1000000 -DiscoverLibs
  .\infra\scripts\run-sensor.ps1 -ApiKey "devkey" -IngestUrl "http://host.docker.internal:8000/v1/events" -SkipPull
#>
param(
  [Parameter(Mandatory = $true)]
  [string] $ApiKey,

  [string] $IngestUrl = "http://host.docker.internal:8000/v1/events",

  [int] $AccountId = 1000000,

  [string] $Image = "registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.0.0",

  [string] $RustLog = "info",

  [double] $SampleRate = 1.0,

  [switch] $SkipPull,

  [switch] $DiscoverLibs
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker not found. Install Docker Desktop and ensure it is running."
}

if (-not $SkipPull) {
  Write-Host "==> docker pull $Image" -ForegroundColor Cyan
  docker pull $Image
  if ($LASTEXITCODE -ne 0) {
    Write-Host @"

Pull failed. If you see 'access forbidden', the registry is private — authenticate:

  docker login registry.gitlab.com -u <gitlab-username> -p <token>

Use a GitLab Personal Access Token with scope: read_registry

"@ -ForegroundColor Yellow
    exit 1
  }
} else {
  Write-Host "==> Skipping pull (-SkipPull)" -ForegroundColor Gray
}

$name = "api-sentinel-sensor-run"
docker rm -f $name 2>$null | Out-Null

Write-Host "==> Starting sensor: $name" -ForegroundColor Cyan
Write-Host "    INGEST: $IngestUrl | ACCOUNT_ID: $AccountId" -ForegroundColor Gray

$extra = @()
if ($DiscoverLibs) { $extra += "--discover-libs" }

docker run --name $name `
  --privileged `
  --pid=host `
  --net=host `
  -v /sys/fs/bpf:/sys/fs/bpf `
  -v /sys/kernel/debug:/sys/kernel/debug:ro `
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro `
  -e "API_KEY=$ApiKey" `
  -e "RUST_LOG=$RustLog" `
  $Image `
  --bpf /app/bpf/http_trace.bpf.o `
  --ingest $IngestUrl `
  --account-id $AccountId `
  --sample-rate $SampleRate `
  @extra
