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

# ── Connect to Graph (reuse existing session if available) ─────────────────────
Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

$needsConnect = $true
try {
    $context = Get-MgContext
    if ($null -ne $context -and -not [string]::IsNullOrWhiteSpace($context.Account)) {
        # Verify required scopes are present
        $requiredScopes = @("IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All", "User.Read.All")
        $currentScopes  = $context.Scopes
        $missingScopes  = $requiredScopes | Where-Object { $_ -notin $currentScopes }

        if ($missingScopes.Count -eq 0) {
            Write-Host "Active session found for $($context.Account) with all required scopes." -ForegroundColor Green
            $needsConnect = $false
        }
        else {
            Write-Host "Active session found for $($context.Account) but missing scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
            Write-Host "Reconnecting with required scopes..." -ForegroundColor Yellow
        }
    }
}
catch {
    # No active session, proceed to connect
}

if ($needsConnect) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All", "User.Read.All" -ErrorAction Stop
    Write-Host "Connected as $((Get-MgContext).Account).`n" -ForegroundColor Green
}
else {
    Write-Host ""
}

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

# Build lookups: UserId -> most recent detection, and UserId -> all detections
$latestDetectionByUser = @{}
$allDetectionsByUser   = @{}
foreach ($det in $riskDetections) {
    $uid     = $det.UserId
    $detDate = $det.DetectedDateTime

    if ($null -eq $uid -or $null -eq $detDate) { continue }

    # Track latest
    if (-not $latestDetectionByUser.ContainsKey($uid) -or $detDate -gt $latestDetectionByUser[$uid].DetectedDateTime) {
        $latestDetectionByUser[$uid] = $det
    }

    # Track all detections per user
    if (-not $allDetectionsByUser.ContainsKey($uid)) {
        $allDetectionsByUser[$uid] = [System.Collections.Generic.List[object]]::new()
    }
    $allDetectionsByUser[$uid].Add($det)
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
            RiskReason                 = "N/A"
            SourceIP                   = "N/A"
            Location                   = "N/A"
            DetectionSource            = "N/A"
            TotalDetections            = 0
            AllDetectionsDetail        = "N/A"
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

    # Extract detailed risk context from the latest detection
    $riskDetail    = if ($detection) { $detection.RiskDetail }       else { "N/A" }
    $sourceIP      = if ($detection -and $detection.IpAddress) { $detection.IpAddress } else { "N/A" }
    $detActivity   = if ($detection) { $detection.Activity }         else { "N/A" }
    $detSource     = if ($detection) { $detection.Source }            else { "N/A" }

    # Location info (city, state, country)
    $locationStr = "N/A"
    if ($detection -and $detection.Location) {
        $loc = $detection.Location
        $parts = @($loc.City, $loc.State, $loc.CountryOrRegion) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($parts.Count -gt 0) { $locationStr = $parts -join ", " }
    }

    # Build a human-readable risk reason summary
    $riskReasonParts = [System.Collections.Generic.List[string]]::new()

    # Map common riskEventType values to plain-English explanations
    $riskExplanation = switch ($detectionType) {
        "unfamiliarFeatures"          { "Sign-in had unfamiliar properties (device, location, or IP not seen before)" }
        "anonymizedIPAddress"         { "Sign-in from an anonymized IP address (e.g. Tor, VPN anonymizer)" }
        "maliciousIPAddress"          { "Sign-in from a known malicious IP address" }
        "suspiciousIPAddress"         { "Sign-in from a suspicious IP address with known bad activity" }
        "leakedCredentials"           { "User's credentials were found in a public data breach / leak" }
        "investigationsThreatIntelligence" { "Microsoft Threat Intelligence flagged unusual activity for this user" }
        "generic"                     { "Entra ID detected generic anomalous behaviour" }
        "adminConfirmedUserCompromised"    { "An administrator manually confirmed this user as compromised" }
        "passwordSpray"               { "Account was targeted in a password spray attack" }
        "anomalousToken"              { "Unusual token characteristics detected (token replay or theft suspected)" }
        "tokenIssuerAnomaly"          { "Abnormal SAML token issuer detected" }
        "malwareInfectedIPAddress"    { "Sign-in from an IP address infected with malware (bot activity)" }
        "mcasImpossibleTravel"        { "Impossible travel — sign-ins from geographically distant locations in a short timeframe" }
        "mcasSuspiciousInboxManipulationRules" { "Suspicious inbox forwarding/manipulation rules detected (Defender for Cloud Apps)" }
        "riskyUser"                   { "User flagged as risky based on aggregate signals" }
        "newCountry"                  { "Sign-in from a country the user has never signed in from before" }
        "impossibleTravel"            { "Impossible travel — sign-ins from distant locations in an implausible timeframe" }
        "attackerinTheMiddle"         { "Adversary-in-the-middle (AiTM) phishing attack detected" }
        "suspiciousBrowser"           { "Suspicious browser characteristics detected during sign-in" }
        "suspiciousAPITraffic"        { "Unusual API/Graph traffic patterns detected from the user's sessions" }
        default                       { $detectionType }
    }
    $riskReasonParts.Add($riskExplanation)

    if ($riskDetail -and $riskDetail -ne "none" -and $riskDetail -ne "hidden") {
        $riskReasonParts.Add("Detail: $riskDetail")
    }
    if ($sourceIP -ne "N/A") {
        $riskReasonParts.Add("Source IP: $sourceIP")
    }
    if ($locationStr -ne "N/A") {
        $riskReasonParts.Add("Location: $locationStr")
    }

    $riskReason = $riskReasonParts -join " | "

    # Collect ALL detections for this user for the detail column
    $userDetections = $allDetectionsByUser[$userId]
    $allDetectionsSummary = "N/A"
    if ($userDetections -and $userDetections.Count -gt 0) {
        $sorted = $userDetections | Sort-Object DetectedDateTime -Descending
        $summaryLines = foreach ($d in $sorted) {
            $dLoc = "N/A"
            if ($d.Location) {
                $dParts = @($d.Location.City, $d.Location.State, $d.Location.CountryOrRegion) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                if ($dParts.Count -gt 0) { $dLoc = $dParts -join ", " }
            }
            $dIP = if ($d.IpAddress) { $d.IpAddress } else { "N/A" }
            "[$($d.DetectedDateTime)] $($d.RiskEventType) (IP: $dIP, Location: $dLoc)"
        }
        $allDetectionsSummary = $summaryLines -join " ;; "
    }

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
        RiskReason                 = $riskReason
        SourceIP                   = $sourceIP
        Location                   = $locationStr
        DetectionSource            = $detSource
        TotalDetections            = if ($userDetections) { $userDetections.Count } else { 0 }
        AllDetectionsDetail        = $allDetectionsSummary
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

    Write-Host "`n  $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor White
    Write-Host "    Risk Level   : $($riskyUser.RiskLevel) | State: $($riskyUser.RiskState)" -ForegroundColor Yellow
    Write-Host "    Why Risky    : $riskExplanation" -ForegroundColor Magenta
    if ($sourceIP -ne "N/A")    { Write-Host "    Source IP    : $sourceIP" -ForegroundColor DarkCyan }
    if ($locationStr -ne "N/A") { Write-Host "    Location     : $locationStr" -ForegroundColor DarkCyan }
    if ($detSource -and $detSource -ne "N/A") { Write-Host "    Det. Source  : $detSource" -ForegroundColor DarkCyan }
    if ($userDetections -and $userDetections.Count -gt 1) {
        Write-Host "    Total Detections: $($userDetections.Count)" -ForegroundColor DarkYellow
    }
    Write-Host "    Detection    : $detectionDate" -NoNewline
    Write-Host "  |  Pwd Changed : $pwdChangeDate" -NoNewline
    Write-Host "  |  Remediated  : $status" -ForegroundColor $colour
}

# ── 4. Output ─────────────────────────────────────────────────────────────────
Write-Host "`n────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "  Total risky users : $($results.Count)"
Write-Host "  Password changed  : $(($results | Where-Object PasswordChangedAfterRisk -eq 'YES').Count)" -ForegroundColor Green
Write-Host "  NOT changed       : $(($results | Where-Object PasswordChangedAfterRisk -eq 'NO').Count)" -ForegroundColor Red
Write-Host "  Unknown           : $(($results | Where-Object PasswordChangedAfterRisk -eq 'UNKNOWN').Count)" -ForegroundColor Yellow

$results | Select-Object UserPrincipalName, DisplayName, RiskLevel, RiskState, RiskDetectionType, RiskReason, SourceIP, Location, TotalDetections, LatestRiskDetectionDate, LastPasswordChangeDate, PasswordChangedAfterRisk | Format-List

if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nExported to $CsvPath" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "Would you like to export the results to CSV?" -ForegroundColor Cyan
    Write-Host "  [1] Yes - export to default path ($CsvPath)"
    Write-Host "  [2] Yes - specify a custom path"
    Write-Host "  [3] No  - skip export"
    Write-Host ""

    $choice = Read-Host "Select an option (1/2/3)"

    switch ($choice) {
        "1" {
            $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nExported to $CsvPath" -ForegroundColor Green
        }
        "2" {
            $customPath = Read-Host "Enter the full file path (e.g. C:\Reports\risky.csv)"
            if ([string]::IsNullOrWhiteSpace($customPath)) {
                Write-Host "No path provided. Skipping export." -ForegroundColor Yellow
            }
            else {
                $results | Export-Csv -Path $customPath -NoTypeInformation -Encoding UTF8
                Write-Host "`nExported to $customPath" -ForegroundColor Green
            }
        }
        default {
            Write-Host "Export skipped." -ForegroundColor DarkGray
        }
    }
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Graph." -ForegroundColor DarkGray
