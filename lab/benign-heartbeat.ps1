<#
.SYNOPSIS
    Benign HTTP heartbeat for an authorized, isolated Windows VM lab.
.DESCRIPTION
    Sends a small, fixed number of clearly labeled HTTP GET requests to
    a private IPv4 server. No C2 commands, remote execution, persistence,
    concealment, credential access, or file transfers.
.EXAMPLE
    .\benign-heartbeat.ps1 -ServerUrl "http://192.168.56.10:8080/" -Count 5 -IntervalSeconds 3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [ValidateRange(1, 10)]
    [int]$Count = 5,

    [ValidateRange(1, 30)]
    [int]$IntervalSeconds = 3
)

$uri = $null
if (-not [System.Uri]::TryCreate($ServerUrl, [System.UriKind]::Absolute, [ref]$uri)) {
    throw "ServerUrl must be a valid absolute URL."
}
if ($uri.Scheme -ne 'http') {
    throw "Use plain HTTP only for this isolated, non-sensitive lab."
}
if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
    throw "Do not include credentials in the test URL."
}

$ip = $null
if (-not [System.Net.IPAddress]::TryParse($uri.Host, [ref]$ip)) {
    throw "Use a literal, private IPv4 address on your isolated lab network."
}
$bytes = $ip.GetAddressBytes()
if ($bytes.Length -ne 4) {
    throw "Use a private IPv4 address."
}
$private = ($bytes[0] -eq 10) -or
           ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
           ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
if (-not $private) {
    throw "Only RFC1918 private IPv4 addresses are accepted."
}

Write-Host "[LAB] Benign network heartbeat; endpoint: $($uri.Host):$($uri.Port)"
Write-Host "[LAB] Requests: $Count; interval: $IntervalSeconds seconds"
for ($i = 1; $i -le $Count; $i++) {
    $separator = if ($uri.Query.Length -gt 0) { '&' } else { '?' }
    $url = "$($uri.AbsoluteUri)$($separator)lab=benign-heartbeat&sequence=$i"
    $timestamp = Get-Date -Format 'o'
    try {
        $response = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[$timestamp] Request $i/$Count status=$([int]$response.StatusCode)"
    } catch {
        Write-Warning "[$timestamp] Request $i/$Count failed: $($_.Exception.Message)"
    }
    if ($i -lt $Count) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}
Write-Host "[LAB] Completed; no persistence or background task created."
