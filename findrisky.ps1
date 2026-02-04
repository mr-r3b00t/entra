#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

<#
.SYNOPSIS
    Enumerates risky users in Entra ID, retrieves risk detection dates,
    and validates whether the user's password was changed AFTER the risk was detected.

.DESCRIPTION
    Uses Microsoft Graph API to:
    1. Pull all risky users (from /identityProtection/riskyUsers)
    2. Pull risk detections (from /identityProtection/riskDetections) for date context
    3. Get each user's lastPasswordChangeDateTime
    4. Compare: password change date > risk detection date = remediated

.NOTES
    Required permissions (Application or Delegated):
      - IdentityRiskyUser.Read.All
      - IdentityRiskEvent.Read.All
      - User.Read.All  (or Directory.Read.All)

    Install modules if needed:
      Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
      Install-Module Microsoft.Graph.Users -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$CsvPath = ".\RiskyUsers_PasswordValidation.csv"
)

# ── Connect to Graph ──────────────────────────────────────────────────────────
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All", "User.Read.All" -ErrorAction Stop
Write-Host "Connected.`n" -ForegroundColor Green

# ── 1. Get all risky users ────────────────────────────────────────────────────
Write-Host "Fetching risky users..." -ForegroundColor Cyan
$riskyUsers = Get-MgRiskyUser -All -ErrorAction Stop
Write-Host "Found $($riskyUsers.Count) risky user(s).`n" -ForegroundColor Yellow

if ($riskyUsers.Count -eq 0) {
    Write-Host "No risky users found. Exiting." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

# ── 2. Get all risk detections (for per-user latest detection date) ───────────
Write-Host "Fetching risk detections..." -ForegroundColor Cyan
$riskDetections = Get-MgRiskDetection -All -ErrorAction Stop
Write-Host "Found $($riskDetections.Count) risk detection(s).`n" -ForegroundColor Yellow

# Build a lookup: UserId -> most recent detection datetime
$latestDetectionByUser = @{}
foreach ($det in $riskDetections) {
    $uid = $det.UserId
    $detDate = $det.DetectedDateTime

    if ($null -eq $uid -or $null -eq $detDate) { continue }

    if (-not $latestDetectionByUser.ContainsKey($uid) -or $detDate -gt $latestDetectionByUser[$uid].DetectedDateTime) {
        $latestDetectionByUser[$uid] = $det
    }
}

# ── 3. For each risky user, compare password change date vs detection date ────
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($riskyUser in $riskyUsers) {
    $userId = $riskyUser.Id
    $upn    = $riskyUser.UserPrincipalName

    # Get the user's password change date
    try {
        $user = Get-MgUser -UserId $userId -Property "displayName,userPrincipalName,lastPasswordChangeDateTime" -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve user details for $upn ($userId): $_"
        $results.Add([PSCustomObject]@{
            UserPrincipalName          = $upn
            DisplayName                = "N/A"
            RiskLevel                  = $riskyUser.RiskLevel
            RiskState                  = $riskyUser.RiskState
            RiskLastUpdated            = $riskyUser.RiskLastUpdatedDateTime
            LatestRiskDetectionDate    = "N/A"
            RiskDetectionType          = "N/A"
            LastPasswordChangeDate     = "N/A"
            PasswordChangedAfterRisk   = "UNKNOWN"
        })
        continue
    }

    $pwdChangeDate = $user.LastPasswordChangeDateTime

    # Look up the latest risk detection for this user
    $detection     = $latestDetectionByUser[$userId]
    $detectionDate = if ($detection) { $detection.DetectedDateTime } else { $riskyUser.RiskLastUpdatedDateTime }
    $detectionType = if ($detection) { $detection.RiskEventType }    else { "N/A" }

    # Compare
    if ($null -ne $pwdChangeDate -and $null -ne $detectionDate) {
        $remediated = $pwdChangeDate -gt $detectionDate
    }
    else {
        $remediated = $null
    }

    $status = switch ($remediated) {
        $true   { "YES" }
        $false  { "NO" }
        default { "UNKNOWN" }
    }

    $obj = [PSCustomObject]@{
        UserPrincipalName          = $user.UserPrincipalName
        DisplayName                = $user.DisplayName
        RiskLevel                  = $riskyUser.RiskLevel
        RiskState                  = $riskyUser.RiskState
        RiskLastUpdated            = $riskyUser.RiskLastUpdatedDateTime
        LatestRiskDetectionDate    = $detectionDate
        RiskDetectionType          = $detectionType
        LastPasswordChangeDate     = $pwdChangeDate
        PasswordChangedAfterRisk   = $status
    }

    $results.Add($obj)

    # Console colour coding
    $colour = switch ($status) {
        "YES"     { "Green"  }
        "NO"      { "Red"    }
        default   { "Yellow" }
    }

    Write-Host "$($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor White -NoNewline
    Write-Host " | Risk: $($riskyUser.RiskLevel)" -ForegroundColor Yellow -NoNewline
    Write-Host " | Detection: $detectionDate" -NoNewline
    Write-Host " | PwdChange: $pwdChangeDate" -NoNewline
    Write-Host " | Remediated: $status" -ForegroundColor $colour
}

# ── 4. Output ─────────────────────────────────────────────────────────────────
Write-Host "`n────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "  Total risky users : $($results.Count)"
Write-Host "  Password changed  : $(($results | Where-Object PasswordChangedAfterRisk -eq 'YES').Count)" -ForegroundColor Green
Write-Host "  NOT changed       : $(($results | Where-Object PasswordChangedAfterRisk -eq 'NO').Count)" -ForegroundColor Red
Write-Host "  Unknown           : $(($results | Where-Object PasswordChangedAfterRisk -eq 'UNKNOWN').Count)" -ForegroundColor Yellow

$results | Format-Table -AutoSize

if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nExported to $CsvPath" -ForegroundColor Green
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Graph." -ForegroundColor DarkGray
