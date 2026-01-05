<#
  CTF Suite smoke test
  - Verifies HTTP health endpoints for all web services
  - Verifies TCP reachability of SSH (port 2222)


    # Local host
    .\smoke.ps1 -TargetHost localhost
#>

[CmdletBinding()]
param(
  [string]$TargetHost = '35.210.32.202')

$ErrorActionPreference = 'Stop'

$httpServices = @(
  @{ name = 'portal';              url = "http://$TargetHost/healthz" },
  @{ name = 'login-sqli';          url = "http://$TargetHost:8001/healthz" },
  @{ name = 'jwt-weak';            url = "http://$TargetHost:8002/healthz" },
  @{ name = 'static-secrets';      url = "http://$TargetHost:8003/healthz" },
  @{ name = 'command-injection';   url = "http://$TargetHost:8004/healthz" },
  @{ name = 'ssrf-internal';       url = "http://$TargetHost:8005/healthz" },
  @{ name = 'xxe-injection';       url = "http://$TargetHost:8006/healthz" },
  @{ name = 'container-breakout';  url = "http://$TargetHost:8007/healthz" }
)

foreach ($svc in $httpServices) {
  Write-Host "Checking $($svc.name) at $($svc.url)" -ForegroundColor Cyan
  $resp = Invoke-WebRequest -Uri $svc.url -UseBasicParsing -TimeoutSec 5
  if ($resp.StatusCode -ne 200) { throw "Health check failed for $($svc.name)" }
}

Write-Host "HTTP health checks passed." -ForegroundColor Green

Write-Host "Checking brute-ssh TCP port at $TargetHost:2222" -ForegroundColor Cyan
$sshOk = Test-NetConnection -ComputerName $TargetHost -Port 2222 -InformationLevel Quiet
if (-not $sshOk) { throw "TCP check failed for brute-ssh on port 2222" }

Write-Host "All health checks passed." -ForegroundColor Green
