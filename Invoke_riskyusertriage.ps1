#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users

<#
.SYNOPSIS
    Interactive triage tool for active risky users in Entra ID.
    Presents each atRisk user with full detection context and asks what action to take.

.DESCRIPTION
    Uses Microsoft Graph API to:
    1. Pull risky users filtered to riskState = atRisk
    2. Pull risk detections for context (reason, IP, location, timeline)
    3. Get each user's password change date and sign-in activity
    4. Present a detailed risk profile per user
    5. Prompt the operator to take action: Dismiss, Confirm Compromised, Skip, or Exit

.NOTES
    Required permissions (Application or Delegated):
      - IdentityRiskyUser.ReadWrite.All
      - IdentityRiskEvent.Read.All
      - User.Read.All  (or Directory.Read.All)

    Install modules if needed:
      Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
      Install-Module Microsoft.Graph.Users -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$CsvPath = ".\ActiveRiskyUsers_Triage.csv"
)

# -- Connect to Graph (reuse existing session if available) --------------------
Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

$needsConnect = $true
try {
    $context = Get-MgContext
    if ($null -ne $context -and ($context.Account -or $context.ClientId)) {
        $currentScopes = $context.Scopes

        $hasRiskyUserWrite = $currentScopes -contains "IdentityRiskyUser.ReadWrite.All"
        $hasRiskEvent      = $currentScopes -contains "IdentityRiskEvent.Read.All"
        $hasUserRead       = ($currentScopes -contains "User.Read.All") -or ($currentScopes -contains "Directory.Read.All")

        if ($hasRiskyUserWrite -and $hasRiskEvent -and $hasUserRead) {
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

# -- 1. Get risky users with riskState = atRisk only --------------------------
Write-Host "Fetching risky users with riskState 'atRisk'..." -ForegroundColor Cyan

$riskyUsers = $null
$maxRetries = 5
$retryCount = 0

while ($null -eq $riskyUsers -and $retryCount -lt $maxRetries) {
    try {
        $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -All -ErrorAction Stop
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

Write-Host "Found $($riskyUsers.Count) active risky user(s).`n" -ForegroundColor Yellow

if ($riskyUsers.Count -eq 0) {
    Write-Host "No active risky users found. Exiting." -ForegroundColor Green
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    return
}

# -- 2. Get risk detections ----------------------------------------------------
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
                Write-Host "Continuing without detailed detection info." -ForegroundColor Yellow
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
                Write-Host "Continuing without detailed detection info." -ForegroundColor Yellow
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

# -- Build detection lookups per user ------------------------------------------
$allDetectionsByUser = @{}
foreach ($det in $riskDetections) {
    $detUid  = $det.UserId
    $detDate = $det.DetectedDateTime

    if ($null -eq $detUid -or $null -eq $detDate) { continue }

    if (-not $allDetectionsByUser.ContainsKey($detUid)) {
        $allDetectionsByUser[$detUid] = [System.Collections.Generic.List[object]]::new()
    }
    $allDetectionsByUser[$detUid].Add($det)
}

# -- Risk event type to plain-English mapping ----------------------------------
function Get-RiskExplanation {
    param([string]$RiskEventType)

    switch ($RiskEventType) {
        "unfamiliarFeatures"               { "Sign-in had unfamiliar properties (device, location, or IP not seen before)" }
        "anonymizedIPAddress"              { "Sign-in from an anonymized IP address (e.g. Tor, VPN anonymizer)" }
        "maliciousIPAddress"               { "Sign-in from a known malicious IP address" }
        "suspiciousIPAddress"              { "Sign-in from a suspicious IP address with known bad activity" }
        "leakedCredentials"                { "User's credentials were found in a public data breach / leak" }
        "investigationsThreatIntelligence" { "Microsoft Threat Intelligence flagged unusual activity for this user" }
        "generic"                          { "Entra ID detected generic anomalous behaviour" }
        "adminConfirmedUserCompromised"    { "An administrator manually confirmed this user as compromised" }
        "passwordSpray"                    { "Account was targeted in a password spray attack" }
        "anomalousToken"                   { "Unusual token characteristics detected (token replay or theft suspected)" }
        "tokenIssuerAnomaly"               { "Abnormal SAML token issuer detected" }
        "malwareInfectedIPAddress"         { "Sign-in from an IP address infected with malware (bot activity)" }
        "mcasImpossibleTravel"             { "Impossible travel - sign-ins from geographically distant locations in a short timeframe" }
        "mcasSuspiciousInboxManipulationRules" { "Suspicious inbox forwarding/manipulation rules detected (Defender for Cloud Apps)" }
        "riskyUser"                        { "User flagged as risky based on aggregate signals" }
        "newCountry"                       { "Sign-in from a country the user has never signed in from before" }
        "impossibleTravel"                 { "Impossible travel - sign-ins from distant locations in an implausible timeframe" }
        "attackerinTheMiddle"              { "Adversary-in-the-middle (AiTM) phishing attack detected" }
        "suspiciousBrowser"                { "Suspicious browser characteristics detected during sign-in" }
        "suspiciousAPITraffic"             { "Unusual API/Graph traffic patterns detected from the user's sessions" }
        default                            { $RiskEventType }
    }
}

# -- 3. Interactive triage loop ------------------------------------------------
Write-Host "============================================================" -ForegroundColor White
Write-Host "  INTERACTIVE RISKY USER TRIAGE" -ForegroundColor Cyan
Write-Host "  $($riskyUsers.Count) active risky user(s) to review" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor White

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$actionLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$dismissedCount = 0
$compromisedCount = 0
$skippedCount = 0
$userIndex = 0
$exitTriage = $false

foreach ($riskyUser in $riskyUsers) {
    if ($exitTriage) { break }
    $userIndex++
    $userId = $riskyUser.Id
    $upn    = $riskyUser.UserPrincipalName

    # -- Get user details ------------------------------------------------------
    $user = $null
    try {
        $user = Get-MgUser -UserId $userId -Property "displayName","userPrincipalName","lastPasswordChangeDateTime","lastSignInDateTime","mail","jobTitle","department","accountEnabled" -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve user details for $upn ($userId): $_"
    }

    $displayName   = if ($user) { $user.DisplayName } else { "N/A" }
    $pwdChangeDate = if ($user) { $user.LastPasswordChangeDateTime } else { $null }
    $lastSignIn    = if ($user -and $user.AdditionalProperties.ContainsKey("signInActivity")) { $user.AdditionalProperties["signInActivity"]["lastSignInDateTime"] } else { $null }
    $jobTitle      = if ($user -and $user.JobTitle) { $user.JobTitle } else { "N/A" }
    $department    = if ($user -and $user.Department) { $user.Department } else { "N/A" }
    $enabled       = if ($user) { $user.AccountEnabled } else { "N/A" }

    # -- Get detections for this user ------------------------------------------
    $userDetections = $allDetectionsByUser[$userId]
    $latestDetection = $null
    $sortedDetections = $null

    # If no detections found in the batch, try a direct query for this user
    if (-not $userDetections -or $userDetections.Count -eq 0) {
        Write-Host "  (No detections in initial batch - querying directly for this user...)" -ForegroundColor DarkGray
        try {
            $directDetections = Get-MgRiskDetection -Filter "userId eq '$userId'" -Top 10 -ErrorAction Stop
            if ($directDetections -and $directDetections.Count -gt 0) {
                $userDetections = [System.Collections.Generic.List[object]]::new()
                foreach ($dd in $directDetections) { $userDetections.Add($dd) }
            }
        }
        catch {
            Write-Warning "  Could not query risk detections for this user: $_"
        }
    }

    # If still nothing, fall back to riskyUser history endpoint
    if (-not $userDetections -or $userDetections.Count -eq 0) {
        Write-Host "  (No detections from API - falling back to risky user history...)" -ForegroundColor DarkGray
        try {
            $historyUri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/$userId/history"
            $historyResponse = Invoke-MgGraphRequest -Method GET -Uri $historyUri -ErrorAction Stop

            if ($historyResponse -and $historyResponse.value -and $historyResponse.value.Count -gt 0) {
                # Build pseudo-detection objects from history entries
                $userDetections = [System.Collections.Generic.List[object]]::new()
                foreach ($histEntry in $historyResponse.value) {
                    $activity = $histEntry.activity
                    if (-not $activity) { continue }

                    # The activity object contains riskEventTypes and detail
                    $histObj = [PSCustomObject]@{
                        DetectedDateTime = $histEntry.riskLastUpdatedDateTime
                        RiskEventType    = if ($activity.riskEventTypes -and $activity.riskEventTypes.Count -gt 0) { $activity.riskEventTypes[0] } elseif ($activity.eventTypes -and $activity.eventTypes.Count -gt 0) { $activity.eventTypes[0] } else { "N/A" }
                        RiskDetail       = if ($histEntry.riskDetail) { $histEntry.riskDetail } else { "N/A" }
                        IpAddress        = if ($activity.ipAddress) { $activity.ipAddress } else { $null }
                        Location         = if ($activity.location) { $activity.location } else { $null }
                        Source           = "riskyUserHistory"
                        UserId           = $userId
                    }

                    # Also check the nested detail property for additional event types
                    if ($histObj.RiskEventType -eq "N/A" -and $histEntry.riskDetail -and $histEntry.riskDetail -ne "none") {
                        $histObj.RiskEventType = $histEntry.riskDetail
                    }

                    $userDetections.Add($histObj)
                }

                if ($userDetections.Count -gt 0) {
                    Write-Host "  (Found $($userDetections.Count) history entry/entries)" -ForegroundColor DarkGray
                }
            }
        }
        catch {
            Write-Warning "  Could not retrieve risky user history: $_"
        }
    }

    if ($userDetections -and $userDetections.Count -gt 0) {
        $sortedDetections = $userDetections | Sort-Object DetectedDateTime -Descending
        $latestDetection = $sortedDetections[0]
    }

    $detectionDate = if ($latestDetection) { $latestDetection.DetectedDateTime } else { $riskyUser.RiskLastUpdatedDateTime }
    $detectionType = if ($latestDetection) { $latestDetection.RiskEventType } else { "N/A" }
    $riskDetail    = if ($latestDetection) { $latestDetection.RiskDetail } else { "N/A" }
    $sourceIP      = if ($latestDetection -and $latestDetection.IpAddress) { $latestDetection.IpAddress } else { "N/A" }
    $detSource     = if ($latestDetection) { $latestDetection.Source } else { "N/A" }

    $locationStr = "N/A"
    if ($latestDetection -and $latestDetection.Location) {
        $loc = $latestDetection.Location
        # Handle both SDK objects (properties) and history hashtables (keys)
        $city    = if ($loc -is [hashtable]) { $loc["city"] } else { $loc.City }
        $state   = if ($loc -is [hashtable]) { $loc["state"] } else { $loc.State }
        $country = if ($loc -is [hashtable]) { $loc["countryOrRegion"] } else { $loc.CountryOrRegion }
        $locParts = @($city, $state, $country) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($locParts.Count -gt 0) { $locationStr = $locParts -join ", " }
    }

    $riskExplanation = Get-RiskExplanation -RiskEventType $detectionType

    # Password changed after risk?
    $pwdStatus = "UNKNOWN"
    if ($null -ne $pwdChangeDate -and $null -ne $detectionDate) {
        if ($pwdChangeDate -gt $detectionDate) { $pwdStatus = "YES" } else { $pwdStatus = "NO" }
    }

    # -- Display user risk profile ---------------------------------------------
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  USER $userIndex of $($riskyUsers.Count)" -ForegroundColor White
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Name           : $displayName" -ForegroundColor White
    Write-Host "  UPN            : $upn" -ForegroundColor White
    Write-Host "  User ID        : $userId" -ForegroundColor DarkGray
    Write-Host "  Job Title      : $jobTitle" -ForegroundColor White
    Write-Host "  Department     : $department" -ForegroundColor White
    Write-Host "  Account Enabled: $enabled" -ForegroundColor $(if ($enabled -eq $true) { "Green" } else { "Red" })
    Write-Host ""
    Write-Host "  -- Risk Information --" -ForegroundColor Yellow
    Write-Host "  Risk Level     : $($riskyUser.RiskLevel)" -ForegroundColor $(switch ($riskyUser.RiskLevel) { "high" { "Red" } "medium" { "Yellow" } "low" { "DarkYellow" } default { "White" } })
    Write-Host "  Risk State     : $($riskyUser.RiskState)" -ForegroundColor Red
    Write-Host "  Last Updated   : $($riskyUser.RiskLastUpdatedDateTime)" -ForegroundColor White
    Write-Host ""
    Write-Host "  -- Latest Detection --" -ForegroundColor Magenta
    Write-Host "  Detection Type : $detectionType" -ForegroundColor White
    Write-Host "  Why Flagged    : $riskExplanation" -ForegroundColor Magenta
    if ($riskDetail -and $riskDetail -ne "none" -and $riskDetail -ne "hidden" -and $riskDetail -ne "N/A") {
        Write-Host "  Risk Detail    : $riskDetail" -ForegroundColor White
    }
    Write-Host "  Detected At    : $detectionDate" -ForegroundColor White
    Write-Host "  Source IP      : $sourceIP" -ForegroundColor White
    Write-Host "  Location       : $locationStr" -ForegroundColor White
    Write-Host "  Det. Source    : $detSource" -ForegroundColor White
    Write-Host ""
    Write-Host "  -- Password & Sign-In --" -ForegroundColor Cyan
    Write-Host "  Last Pwd Change: $pwdChangeDate" -ForegroundColor White
    Write-Host "  Pwd Changed After Detection: $pwdStatus" -ForegroundColor $(switch ($pwdStatus) { "YES" { "Green" } "NO" { "Red" } default { "Yellow" } })
    Write-Host "  Last Sign-In   : $lastSignIn" -ForegroundColor White

    # Show all detections if more than one
    if ($userDetections -and $userDetections.Count -gt 1) {
        Write-Host ""
        Write-Host "  -- All Detections ($($userDetections.Count) total) --" -ForegroundColor DarkCyan
        $detIndex = 1
        foreach ($d in $sortedDetections) {
            $dLoc = "N/A"
            if ($d.Location) {
                $dLocObj = $d.Location
                $dCity    = if ($dLocObj -is [hashtable]) { $dLocObj["city"] } else { $dLocObj.City }
                $dState   = if ($dLocObj -is [hashtable]) { $dLocObj["state"] } else { $dLocObj.State }
                $dCountry = if ($dLocObj -is [hashtable]) { $dLocObj["countryOrRegion"] } else { $dLocObj.CountryOrRegion }
                $dParts = @($dCity, $dState, $dCountry) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                if ($dParts.Count -gt 0) { $dLoc = $dParts -join ", " }
            }
            $dIP = if ($d.IpAddress) { $d.IpAddress } else { "N/A" }
            $dExplain = Get-RiskExplanation -RiskEventType $d.RiskEventType
            Write-Host "    $detIndex. [$($d.DetectedDateTime)] $($d.RiskEventType)" -ForegroundColor DarkCyan
            Write-Host "       Reason  : $dExplain" -ForegroundColor DarkGray
            Write-Host "       IP: $dIP | Location: $dLoc" -ForegroundColor DarkGray
            $detIndex++
        }
    }

    # -- Prompt for action -----------------------------------------------------
    Write-Host ""
    Write-Host "  What action would you like to take?" -ForegroundColor Yellow
    Write-Host "    [1] Dismiss risk        - Mark as safe / false positive"
    Write-Host "    [2] Confirm compromised - Escalate, sets risk to high"
    Write-Host "    [3] Skip                - Take no action, move to next user"
    Write-Host "    [4] Exit                - Stop processing remaining users"
    Write-Host ""

    $action = Read-Host "  Action (1/2/3/4)"
    $actionTaken = "SKIPPED"

    switch ($action) {
        "1" {
            # Dismiss
            if ($userId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                Write-Host "  Invalid user ID format. Cannot dismiss." -ForegroundColor Red
                $actionTaken = "FAILED_INVALID_ID"
            }
            else {
                $confirmDismiss = Read-Host "  Confirm DISMISS risk for $displayName? (Y/N)"
                if ($confirmDismiss -eq "Y" -or $confirmDismiss -eq "y") {
                    try {
                        $body = @{ userIds = @($userId) } | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss" -Body $body -ContentType "application/json" -ErrorAction Stop
                        Write-Host "  DISMISSED - Risk cleared for $displayName." -ForegroundColor Green
                        $actionTaken = "DISMISSED"
                        $dismissedCount++
                    }
                    catch {
                        Write-Host "  FAILED to dismiss risk." -ForegroundColor Red
                        Write-Warning "  Error: $_"
                        $actionTaken = "FAILED_DISMISS"
                    }
                }
                else {
                    Write-Host "  Dismiss cancelled." -ForegroundColor DarkGray
                    $actionTaken = "SKIPPED"
                    $skippedCount++
                }
            }
        }
        "2" {
            # Confirm compromised
            if ($userId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                Write-Host "  Invalid user ID format. Cannot confirm compromised." -ForegroundColor Red
                $actionTaken = "FAILED_INVALID_ID"
            }
            else {
                Write-Host ""
                Write-Host "  WARNING: This will set the user's risk level to HIGH." -ForegroundColor Red
                Write-Host "  Conditional Access policies that block high-risk users will apply." -ForegroundColor Red
                $confirmCompromised = Read-Host "  Confirm COMPROMISED for $displayName? (Y/N)"
                if ($confirmCompromised -eq "Y" -or $confirmCompromised -eq "y") {
                    try {
                        $body = @{ userIds = @($userId) } | ConvertTo-Json -Compress
                        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised" -Body $body -ContentType "application/json" -ErrorAction Stop
                        Write-Host "  CONFIRMED COMPROMISED - $displayName flagged as compromised." -ForegroundColor Red
                        $actionTaken = "CONFIRMED_COMPROMISED"
                        $compromisedCount++
                    }
                    catch {
                        Write-Host "  FAILED to confirm compromised." -ForegroundColor Red
                        Write-Warning "  Error: $_"
                        $actionTaken = "FAILED_COMPROMISED"
                    }
                }
                else {
                    Write-Host "  Confirm compromised cancelled." -ForegroundColor DarkGray
                    $actionTaken = "SKIPPED"
                    $skippedCount++
                }
            }
        }
        "4" {
            Write-Host "  Exiting triage. Remaining users will not be processed." -ForegroundColor Yellow
            $actionTaken = "EXITED"
            $skippedCount++
            $exitTriage = $true
        }
        default {
            Write-Host "  Skipped." -ForegroundColor DarkGray
            $actionTaken = "SKIPPED"
            $skippedCount++
        }
    }

    # Record result
    $results.Add([PSCustomObject]@{
        UserId                  = $userId
        UserPrincipalName       = $upn
        DisplayName             = $displayName
        JobTitle                = $jobTitle
        Department              = $department
        AccountEnabled          = $enabled
        RiskLevel               = $riskyUser.RiskLevel
        RiskState               = $riskyUser.RiskState
        RiskLastUpdated         = $riskyUser.RiskLastUpdatedDateTime
        LatestDetectionDate     = $detectionDate
        DetectionType           = $detectionType
        RiskExplanation         = $riskExplanation
        SourceIP                = $sourceIP
        Location                = $locationStr
        DetectionSource         = $detSource
        TotalDetections         = $(if ($userDetections) { $userDetections.Count } else { 0 })
        LastPasswordChangeDate  = $pwdChangeDate
        PwdChangedAfterRisk     = $pwdStatus
        ActionTaken             = $actionTaken
    })

    $actionLog.Add([PSCustomObject]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        UserId    = $userId
        UPN       = $upn
        Action    = $actionTaken
    })

    Write-Host ""
}

# -- 4. Summary ----------------------------------------------------------------
Write-Host "============================================================" -ForegroundColor White
Write-Host "  TRIAGE SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Total reviewed  : $($results.Count) of $($riskyUsers.Count)"
Write-Host "  Dismissed       : $dismissedCount" -ForegroundColor Green
Write-Host "  Compromised     : $compromisedCount" -ForegroundColor Red
Write-Host "  Skipped / Other : $skippedCount" -ForegroundColor Yellow
Write-Host ""

Write-Host "  -- Action Log --" -ForegroundColor DarkCyan
$actionLog | Format-Table -AutoSize

# -- 5. Export -----------------------------------------------------------------
if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $CsvPath" -ForegroundColor Green
}
else {
    Write-Host "Would you like to export the triage results to CSV?" -ForegroundColor Cyan
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
            $customPath = Read-Host "Enter the full file path (e.g. C:\Reports\triage.csv)"
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

# -- 6. Disconnect prompt ------------------------------------------------------
Write-Host ""
Write-Host "Would you like to disconnect from Microsoft Graph?" -ForegroundColor Cyan
Write-Host "  [1] Yes - disconnect"
Write-Host "  [2] No  - keep session active"
Write-Host ""
$disconnectChoice = Read-Host "Select an option (1/2)"

if ($disconnectChoice -eq "1") {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disconnected from Graph." -ForegroundColor DarkGray
}
else {
    Write-Host "Session kept active. Run 'Disconnect-MgGraph' when finished." -ForegroundColor Green
}

# -- Clear script variables ----------------------------------------------------
Write-Host "Clearing script variables..." -ForegroundColor DarkGray

$variablesToClear = @(
    'context', 'ctx', 'needsConnect', 'sessionIdentity', 'identity',
    'currentScopes', 'hasRiskyUserWrite', 'hasRiskEvent', 'hasUserRead', 'missing',
    'riskyUsers', 'maxRetries', 'retryCount',
    'daysInput', 'detectionDays', 'filterDate', 'pageSize',
    'riskDetections', 'allDetectionsByUser',
    'det', 'detUid', 'detDate',
    'results', 'actionLog', 'riskyUser', 'userId', 'upn', 'user',
    'displayName', 'pwdChangeDate', 'lastSignIn', 'jobTitle', 'department', 'enabled',
    'userDetections', 'sortedDetections', 'latestDetection', 'directDetections', 'dd',
    'historyUri', 'historyResponse', 'histEntry', 'histObj', 'activity',
    'loc', 'locationStr', 'locParts', 'city', 'state', 'country',
    'dLocObj', 'dCity', 'dState', 'dCountry',
    'detectionDate', 'detectionType', 'riskDetail', 'sourceIP', 'detSource',
    'riskExplanation', 'pwdStatus',
    'action', 'actionTaken', 'body',
    'confirmDismiss', 'confirmCompromised',
    'dismissedCount', 'compromisedCount', 'skippedCount', 'userIndex', 'exitTriage',
    'choice', 'customPath', 'disconnectChoice',
    'detIndex', 'd', 'dLoc', 'dParts', 'dIP', 'dExplain'
)

foreach ($var in $variablesToClear) {
    Remove-Variable -Name $var -ErrorAction SilentlyContinue
}
Remove-Variable -Name 'variablesToClear' -ErrorAction SilentlyContinue

Write-Host "Done.`n" -ForegroundColor DarkGray
