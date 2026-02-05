#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

<#
.SYNOPSIS
    Enumerates risky users in Entra ID, retrieves risk detection dates,
    validates password change dates, and optionally dismisses remediated risk states.

.DESCRIPTION
    Uses Microsoft Graph API to:
    1. Pull all risky users (from /identityProtection/riskyUsers)
    2. Pull risk detections (from /identityProtection/riskDetections) for date context
    3. Get each user's lastPasswordChangeDateTime
    4. Compare: password change date > risk detection date = remediated
    5. Optionally dismiss risk state for users whose password was changed after detection

.NOTES
    Required permissions (Application or Delegated):
      - IdentityRiskyUser.Read.All
      - IdentityRiskyUser.ReadWrite.All  (for dismissing risk state)
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

# -- Connect to Graph (reuse existing session if available) --------------------
Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

$needsConnect = $true
try {
    $context = Get-MgContext
    if ($null -ne $context -and ($context.Account -or $context.ClientId)) {
        # Check scopes (ReadWrite.All implies Read.All)
        $currentScopes = $context.Scopes

        $hasRiskyUserWrite = $currentScopes -contains "IdentityRiskyUser.ReadWrite.All"
        $hasRiskEvent      = $currentScopes -contains "IdentityRiskEvent.Read.All"
        $hasUserRead       = ($currentScopes -contains "User.Read.All") -or ($currentScopes -contains "Directory.Read.All")

        if ($hasRiskyUserWrite -and $hasRiskEvent -and $hasUserRead) {
            # Validate the session is actually alive with a lightweight test call
            try {
                Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
                $sessionIdentity = if ($context.Account) { $context.Account } else { "AppId: $($context.ClientId)" }
                Write-Host "Active session validated for $sessionIdentity with all required scopes." -ForegroundColor Green
                $needsConnect = $false
            }
            catch {
                Write-Host "Session exists but is expired or invalid. Re-authenticating..." -ForegroundColor Yellow
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
        }
        else {
            $missing = @()
            if (-not $hasRiskyUserWrite) { $missing += "IdentityRiskyUser.ReadWrite.All" }
            if (-not $hasRiskEvent)      { $missing += "IdentityRiskEvent.Read.All" }
            if (-not $hasUserRead)       { $missing += "User.Read.All" }
            Write-Host "Session found but missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
            Write-Host "Disconnecting and reconnecting with required scopes..." -ForegroundColor Yellow
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
catch {
    # No active session, proceed to connect
}

if ($needsConnect) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "IdentityRiskyUser.ReadWrite.All", "IdentityRiskEvent.Read.All", "User.Read.All" -ErrorAction Stop
    $ctx = Get-MgContext
    $identity = if ($ctx.Account) { $ctx.Account } else { "AppId: $($ctx.ClientId)" }
    Write-Host "Connected as $identity.`n" -ForegroundColor Green
}
else {
    Write-Host ""
}

# -- 1. Get all risky users --------------------------------------------------
Write-Host "Fetching risky users..." -ForegroundColor Cyan

$riskyUsers = $null
$maxRetries = 5
$retryCount = 0

while ($null -eq $riskyUsers -and $retryCount -lt $maxRetries) {
    try {
        $riskyUsers = Get-MgRiskyUser -All -ErrorAction Stop
    }
    catch {
        $retryCount++
        if ($retryCount -ge $maxRetries) {
            Write-Error "Failed to retrieve risky users after $maxRetries attempts: $_"
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            return
        }
        $backoff = [math]::Pow(2, $retryCount) * 5
        Write-Host "  Request throttled. Retrying in $backoff seconds (attempt $retryCount of $maxRetries)..." -ForegroundColor Yellow
        Start-Sleep -Seconds $backoff
    }
}

Write-Host "Found $($riskyUsers.Count) risky user(s).`n" -ForegroundColor Yellow

if ($riskyUsers.Count -eq 0) {
    Write-Host "No risky users found. Exiting." -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    return
}

# -- 2. Get risk detections (filtered to recent window with retry logic) -------
Write-Host "How many days of risk detections would you like to retrieve?" -ForegroundColor Cyan
Write-Host "  Enter a number (e.g. 30, 90, 180) or 0 for ALL detections" -ForegroundColor Cyan
Write-Host "  Note: Larger ranges may be throttled by the Graph API." -ForegroundColor DarkGray
$daysInput = Read-Host "Days (default: 90)"

if ([string]::IsNullOrWhiteSpace($daysInput)) {
    $detectionDays = 90
}
else {
    $detectionDays = [int]$daysInput
}

$riskDetections = $null
$retryCount = 0
$pageSize = 100

if ($detectionDays -gt 0) {
    $filterDate = (Get-Date).AddDays(-$detectionDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "Fetching risk detections from the last $detectionDays days..." -ForegroundColor Cyan

    while ($null -eq $riskDetections -and $retryCount -lt $maxRetries) {
        try {
            $riskDetections = Get-MgRiskDetection -Filter "detectedDateTime ge $filterDate" -Top $pageSize -All -ErrorAction Stop
        }
        catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                Write-Warning "Failed to retrieve risk detections after $maxRetries attempts."
                Write-Warning "Error: $_"
                Write-Host "Continuing without risk detection details. Detection dates will fall back to riskyUser timestamps." -ForegroundColor Yellow
                $riskDetections = @()
                break
            }
            $backoff = [math]::Pow(2, $retryCount) * 5
            Write-Host "  Request throttled. Retrying in $backoff seconds (attempt $retryCount of $maxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $backoff
        }
    }
}
else {
    Write-Host "Fetching ALL risk detections (this may take a while)..." -ForegroundColor Yellow

    while ($null -eq $riskDetections -and $retryCount -lt $maxRetries) {
        try {
            $riskDetections = Get-MgRiskDetection -Top $pageSize -All -ErrorAction Stop
        }
        catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                Write-Warning "Failed to retrieve risk detections after $maxRetries attempts."
                Write-Warning "Error: $_"
                Write-Host "Continuing without risk detection details. Detection dates will fall back to riskyUser timestamps." -ForegroundColor Yellow
                $riskDetections = @()
                break
            }
            $backoff = [math]::Pow(2, $retryCount) * 5
            Write-Host "  Request throttled. Retrying in $backoff seconds (attempt $retryCount of $maxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $backoff
        }
    }
}

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

# -- 3. For each risky user, compare password change date vs detection date --
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($riskyUser in $riskyUsers) {
    $userId = $riskyUser.Id
    $upn    = $riskyUser.UserPrincipalName

    # Get the user's password change date
    try {
        $user = Get-MgUser -UserId $userId -Property "displayName","userPrincipalName","lastPasswordChangeDateTime" -ErrorAction Stop
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
        "mcasImpossibleTravel"        { "Impossible travel - sign-ins from geographically distant locations in a short timeframe" }
        "mcasSuspiciousInboxManipulationRules" { "Suspicious inbox forwarding/manipulation rules detected (Defender for Cloud Apps)" }
        "riskyUser"                   { "User flagged as risky based on aggregate signals" }
        "newCountry"                  { "Sign-in from a country the user has never signed in from before" }
        "impossibleTravel"            { "Impossible travel - sign-ins from distant locations in an implausible timeframe" }
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
        TotalDetections            = $(if ($userDetections) { $userDetections.Count } else { 0 })
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

# -- 4. Output ----------------------------------------------------------------
Write-Host "`n------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "  Total risky users : $($results.Count)"
Write-Host "  Password changed  : $(@($results | Where-Object PasswordChangedAfterRisk -eq 'YES').Count)" -ForegroundColor Green
Write-Host "  NOT changed       : $(@($results | Where-Object PasswordChangedAfterRisk -eq 'NO').Count)" -ForegroundColor Red
Write-Host "  Unknown           : $(@($results | Where-Object PasswordChangedAfterRisk -eq 'UNKNOWN').Count)" -ForegroundColor Yellow

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

# -- 5. Offer to dismiss risk for remediated users -------------------------
$remediatedUsers = @($results | Where-Object PasswordChangedAfterRisk -eq "YES")

if ($remediatedUsers.Count -gt 0) {
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "RISK DISMISSAL" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The following $($remediatedUsers.Count) user(s) have changed their password AFTER the risk detection" -ForegroundColor Green
    Write-Host "and are eligible to have their risk state dismissed:" -ForegroundColor Green
    Write-Host ""

    $i = 1
    foreach ($ru in $remediatedUsers) {
        Write-Host "  [$i] $($ru.DisplayName) ($($ru.UserPrincipalName))" -ForegroundColor White
        Write-Host "      Risk: $($ru.RiskLevel) | Detection: $($ru.LatestRiskDetectionDate) | Pwd Changed: $($ru.LastPasswordChangeDate)" -ForegroundColor DarkCyan
        Write-Host "      Reason: $($ru.RiskReason)" -ForegroundColor DarkGray
        $i++
    }

    Write-Host ""
    Write-Host "Would you like to dismiss the risk state for these users?" -ForegroundColor Yellow
    Write-Host "  [1] Yes - dismiss ALL $($remediatedUsers.Count) remediated user(s)"
    Write-Host "  [2] Yes - let me select which users to dismiss"
    Write-Host "  [3] No  - do not dismiss any risk states"
    Write-Host ""

    $dismissChoice = Read-Host "Select an option (1/2/3)"

    $usersToDismiss = [System.Collections.Generic.List[PSCustomObject]]::new()

    switch ($dismissChoice) {
        "1" {
            foreach ($ru in $remediatedUsers) { $usersToDismiss.Add($ru) }
        }
        "2" {
            Write-Host ""
            Write-Host "Enter the numbers of the users to dismiss (comma-separated, e.g. 1,3,5):" -ForegroundColor Cyan
            $selection = Read-Host "Selection"
            $indices = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }

            $remediatedArray = @($remediatedUsers)
            foreach ($idx in $indices) {
                if ($idx -ge 1 -and $idx -le $remediatedArray.Count) {
                    $usersToDismiss.Add($remediatedArray[$idx - 1])
                }
                else {
                    Write-Warning "Invalid selection: $idx (skipped)"
                }
            }
        }
        default {
            Write-Host "Risk dismissal skipped." -ForegroundColor DarkGray
        }
    }

    if ($usersToDismiss.Count -gt 0) {
        # Final confirmation before making changes
        Write-Host ""
        Write-Host "WARNING: You are about to dismiss the risk state for $($usersToDismiss.Count) user(s):" -ForegroundColor Red
        foreach ($u in $usersToDismiss) {
            Write-Host "  - $($u.DisplayName) ($($u.UserPrincipalName))" -ForegroundColor White
        }
        Write-Host ""
        $confirm = Read-Host "Type 'CONFIRM' to proceed (anything else to cancel)"

        if ($confirm -eq "CONFIRM") {
            Write-Host ""
            $dismissedCount = 0
            $failedCount    = 0

            foreach ($u in $usersToDismiss) {
                $uid = ($riskyUsers | Where-Object UserPrincipalName -eq $u.UserPrincipalName).Id
                Write-Host "  Dismissing risk for $($u.UserPrincipalName)..." -ForegroundColor Cyan -NoNewline

                try {
                    Invoke-MgDismissRiskyUser -BodyParameter @{ UserIds = @($uid) } -ErrorAction Stop
                    Write-Host " Done" -ForegroundColor Green
                    $dismissedCount++
                }
                catch {
                    Write-Host " FAILED" -ForegroundColor Red
                    Write-Warning "    Error: $_"
                    $failedCount++
                }
            }

            Write-Host ""
            Write-Host "Risk dismissal complete: $dismissedCount succeeded, $failedCount failed." -ForegroundColor Cyan
        }
        else {
            Write-Host "Risk dismissal cancelled." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "`nNo remediated users eligible for risk dismissal." -ForegroundColor DarkGray
}

# -- Cleanup -------------------------------------------------------------------
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Graph." -ForegroundColor DarkGray
