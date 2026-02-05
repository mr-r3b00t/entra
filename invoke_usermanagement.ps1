#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, ActiveDirectory

<#
.SYNOPSIS
    Interactive user management tool for Entra ID and Active Directory.
    Search for users, view key info, and take remediation actions.

.DESCRIPTION
    Connects to both Microsoft Graph (Entra ID) and Active Directory to:
    1. Search users by UPN, first name, or last name (partial match)
    2. Display key user information from both Entra and AD
    3. Display linked devices (Entra registered + owned) with key info
    4. Take actions per user:
       - Reset password (via AD) and revoke Entra sessions
       - Require password change on next logon (via AD)
       - Disable account (via AD) and revoke Entra sessions
       - Go back to search

.NOTES
    Required Graph permissions (Delegated):
      - User.ReadWrite.All
      - Directory.ReadWrite.All
      - Device.Read.All

    Required AD permissions:
      - Account Operator or equivalent (password reset, disable, set pwd flags)

    Install modules if needed:
      Install-Module Microsoft.Graph.Users -Scope CurrentUser
      Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
      Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
      Install-Module ActiveDirectory  (comes with RSAT)
#>

[CmdletBinding()]
param()

# ==============================================================================
# FUNCTIONS
# ==============================================================================

function Connect-ToGraph {
    Write-Host "Checking for existing Microsoft Graph session..." -ForegroundColor Cyan

    $needsConnect = $true
    try {
        $context = Get-MgContext
        if ($null -ne $context -and ($context.Account -or $context.ClientId)) {
            $currentScopes = $context.Scopes
            $hasUserWrite  = ($currentScopes -contains "User.ReadWrite.All") -or ($currentScopes -contains "Directory.ReadWrite.All")
            $hasUserRead   = ($currentScopes -contains "User.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or $hasUserWrite
            $hasDeviceRead = ($currentScopes -contains "Device.Read.All") -or ($currentScopes -contains "Directory.Read.All") -or ($currentScopes -contains "Directory.ReadWrite.All")

            if ($hasUserWrite -and $hasUserRead -and $hasDeviceRead) {
                try {
                    Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
                    $sessionId = if ($context.Account) { $context.Account } else { "AppId: $($context.ClientId)" }
                    Write-Host "Active Graph session validated for $sessionId." -ForegroundColor Green
                    $needsConnect = $false
                }
                catch {
                    Write-Host "Graph session expired. Re-authenticating..." -ForegroundColor Yellow
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                }
            }
            else {
                $missing = @()
                if (-not $hasUserWrite) { $missing += "User.ReadWrite.All or Directory.ReadWrite.All" }
                if (-not $hasDeviceRead) { $missing += "Device.Read.All or Directory.Read.All" }
                Write-Host "Session missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    catch {
        # No session
    }

    if ($needsConnect) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Device.Read.All" -ErrorAction Stop
        $ctx = Get-MgContext
        $id = if ($ctx.Account) { $ctx.Account } else { "AppId: $($ctx.ClientId)" }
        Write-Host "Connected to Graph as $id." -ForegroundColor Green
    }
}

function Connect-ToAD {
    Write-Host "Checking Active Directory module and connectivity..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not installed. Install RSAT or the AD PowerShell module."
        return $false
    }

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    try {
        Get-ADDomainController -Discover -ErrorAction Stop | Out-Null
        $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
        Write-Host "Connected to Active Directory domain: $domain" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Cannot connect to Active Directory: $_"
        return $false
    }
}

function Search-Users {
    param([string]$SearchTerm)

    Write-Host "Searching for '$SearchTerm'..." -ForegroundColor Cyan
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Search Entra ID via Graph
    # Use startsWith on displayName and UPN, plus contains via filter
    try {
        # Escape single quotes for OData filter syntax
        $safeTerm = $SearchTerm -replace "'", "''"
        $graphFilter = "startsWith(userPrincipalName,'$safeTerm') or startsWith(displayName,'$safeTerm') or startsWith(givenName,'$safeTerm') or startsWith(surname,'$safeTerm')"
        $entraUsers = Get-MgUser -Filter $graphFilter -Top 25 -Property "id","displayName","userPrincipalName","givenName","surname","jobTitle","department","accountEnabled","mail","lastPasswordChangeDateTime" -ErrorAction Stop
    }
    catch {
        # If filter fails (special chars etc), fall back to search
        Write-Host "  Graph filter failed, trying search..." -ForegroundColor DarkGray
        try {
            $entraUsers = Get-MgUser -Search "displayName:$SearchTerm" -Top 25 -Property "id","displayName","userPrincipalName","givenName","surname","jobTitle","department","accountEnabled","mail","lastPasswordChangeDateTime" -ConsistencyLevel eventual -ErrorAction Stop
        }
        catch {
            Write-Warning "Graph search failed: $_"
            $entraUsers = @()
        }
    }

    foreach ($eu in $entraUsers) {
        $results.Add([PSCustomObject]@{
            Id                = $eu.Id
            DisplayName       = $eu.DisplayName
            UPN               = $eu.UserPrincipalName
            GivenName         = $eu.GivenName
            Surname           = $eu.Surname
            JobTitle          = $eu.JobTitle
            Department        = $eu.Department
            Mail              = $eu.Mail
            AccountEnabled    = $eu.AccountEnabled
            LastPwdChange     = $eu.LastPasswordChangeDateTime
        })
    }

    return $results
}

function Show-UserDetail {
    param([PSCustomObject]$User)

    $userId = $User.Id
    $upn    = $User.UPN

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  USER DETAILS" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White

    # -- Entra ID info ---------------------------------------------------------
    Write-Host ""
    Write-Host "  -- Entra ID --" -ForegroundColor Cyan
    Write-Host "  Display Name   : $($User.DisplayName)" -ForegroundColor White
    Write-Host "  UPN            : $upn" -ForegroundColor White
    Write-Host "  Object ID      : $userId" -ForegroundColor DarkGray
    Write-Host "  First Name     : $($User.GivenName)" -ForegroundColor White
    Write-Host "  Last Name      : $($User.Surname)" -ForegroundColor White
    Write-Host "  Job Title      : $($User.JobTitle)" -ForegroundColor White
    Write-Host "  Department     : $($User.Department)" -ForegroundColor White
    Write-Host "  Email          : $($User.Mail)" -ForegroundColor White
    Write-Host "  Account Enabled: $($User.AccountEnabled)" -ForegroundColor $(if ($User.AccountEnabled -eq $true) { "Green" } else { "Red" })
    Write-Host "  Last Pwd Change: $($User.LastPwdChange)" -ForegroundColor White

    # -- Try to get Entra risk info --------------------------------------------
    try {
        $riskyUser = Get-MgRiskyUser -RiskyUserId $userId -ErrorAction Stop
        if ($riskyUser) {
            Write-Host ""
            Write-Host "  -- Entra Risk Status --" -ForegroundColor Yellow
            Write-Host "  Risk State     : $($riskyUser.RiskState)" -ForegroundColor $(switch ($riskyUser.RiskState) { "atRisk" { "Red" } "confirmedCompromised" { "Red" } "dismissed" { "Green" } "remediated" { "Green" } default { "Yellow" } })
            Write-Host "  Risk Level     : $($riskyUser.RiskLevel)" -ForegroundColor $(switch ($riskyUser.RiskLevel) { "high" { "Red" } "medium" { "Yellow" } "low" { "DarkYellow" } default { "White" } })
            Write-Host "  Risk Updated   : $($riskyUser.RiskLastUpdatedDateTime)" -ForegroundColor White
        }
    }
    catch {
        Write-Host ""
        Write-Host "  -- Entra Risk Status --" -ForegroundColor Yellow
        Write-Host "  No risk record found for this user." -ForegroundColor DarkGray
    }

    # -- Active Directory info -------------------------------------------------
    Write-Host ""
    Write-Host "  -- Active Directory --" -ForegroundColor Cyan

    # Derive sAMAccountName from UPN prefix
    $samAccount = ($upn -split '@')[0]

    try {
        # Search the entire domain recursively so users in any OU are found
        $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName

        $adUser = Get-ADUser -Filter "SamAccountName -eq '$samAccount'" `
            -SearchBase $domainDN -SearchScope Subtree -Properties `
            Enabled, LockedOut, PasswordLastSet, PasswordExpired, `
            PasswordNeverExpires, LastLogonDate, LastBadPasswordAttempt, `
            BadPwdCount, Description, whenCreated, MemberOf -ErrorAction Stop

        # If sAMAccountName didn't match, try matching on UPN
        if (-not $adUser) {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" `
                -SearchBase $domainDN -SearchScope Subtree -Properties `
                Enabled, LockedOut, PasswordLastSet, PasswordExpired, `
                PasswordNeverExpires, LastLogonDate, LastBadPasswordAttempt, `
                BadPwdCount, Description, whenCreated, MemberOf -ErrorAction Stop
        }

        if (-not $adUser) {
            Write-Host "  No AD account found for '$samAccount' (searched all OUs)." -ForegroundColor Yellow
            return $null
        }

        # If filter returned multiple (shouldn't for exact match, but be safe) take the first
        if ($adUser -is [array]) { $adUser = $adUser[0] }

        Write-Host "  sAMAccountName : $($adUser.SamAccountName)" -ForegroundColor White
        Write-Host "  AD Enabled     : $($adUser.Enabled)" -ForegroundColor $(if ($adUser.Enabled) { "Green" } else { "Red" })
        Write-Host "  Locked Out     : $($adUser.LockedOut)" -ForegroundColor $(if ($adUser.LockedOut) { "Red" } else { "Green" })
        Write-Host "  Pwd Last Set   : $($adUser.PasswordLastSet)" -ForegroundColor White
        Write-Host "  Pwd Expired    : $($adUser.PasswordExpired)" -ForegroundColor $(if ($adUser.PasswordExpired) { "Red" } else { "Green" })
        Write-Host "  Pwd Never Exp  : $($adUser.PasswordNeverExpires)" -ForegroundColor $(if ($adUser.PasswordNeverExpires) { "Yellow" } else { "White" })
        Write-Host "  Last Logon     : $($adUser.LastLogonDate)" -ForegroundColor White
        Write-Host "  Last Bad Pwd   : $($adUser.LastBadPasswordAttempt)" -ForegroundColor White
        Write-Host "  Bad Pwd Count  : $($adUser.BadPwdCount)" -ForegroundColor $(if ($adUser.BadPwdCount -gt 0) { "Yellow" } else { "White" })
        Write-Host "  Description    : $($adUser.Description)" -ForegroundColor White
        Write-Host "  Created        : $($adUser.whenCreated)" -ForegroundColor White

        # Group memberships (first 10)
        if ($adUser.MemberOf -and $adUser.MemberOf.Count -gt 0) {
            Write-Host ""
            Write-Host "  -- Group Memberships (top 10) --" -ForegroundColor DarkCyan
            $groups = $adUser.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' } | Select-Object -First 10
            foreach ($g in $groups) {
                Write-Host "    - $g" -ForegroundColor DarkGray
            }
            if ($adUser.MemberOf.Count -gt 10) {
                Write-Host "    ... and $($adUser.MemberOf.Count - 10) more" -ForegroundColor DarkGray
            }
        }

        return $adUser
    }
    catch {
        Write-Host "  Could not find AD account for '$samAccount': $_" -ForegroundColor Yellow
        return $null
    }
}

function Show-UserDevices {
    param([PSCustomObject]$User)

    $userId = $User.Id

    Write-Host ""
    Write-Host "  -- Linked Devices --" -ForegroundColor Cyan

    # Collect registered + owned devices, deduplicate by device Id
    $allDevices = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()

    $deviceProperties = "id","displayName","operatingSystem","operatingSystemVersion","deviceId",
                        "trustType","isCompliant","isManaged","profileType",
                        "registrationDateTime","approximateLastSignInDateTime",
                        "accountEnabled","manufacturer","model"

    # Registered devices
    try {
        $registered = Get-MgUserRegisteredDevice -UserId $userId -All -ErrorAction Stop
        foreach ($dev in $registered) {
            # Filter to device objects only (skip service principals, apps, etc.)
            $odataType = $dev.AdditionalProperties['@odata.type']
            if ($odataType -and $odataType -ne '#microsoft.graph.device') { continue }

            if (-not $allDevices.ContainsKey($dev.Id)) {
                # Fetch full device object for detailed properties
                try {
                    $full = Get-MgDevice -DeviceId $dev.Id -Property $deviceProperties -ErrorAction Stop
                    $full | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Registered' -Force
                    $allDevices[$dev.Id] = $full
                }
                catch {
                    # Fall back to the directoryObject with limited info
                    $dev | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Registered' -Force
                    $allDevices[$dev.Id] = $dev
                }
            }
        }
    }
    catch {
        Write-Host "  Could not retrieve registered devices: $_" -ForegroundColor Yellow
    }

    # Owned devices
    try {
        $owned = Get-MgUserOwnedDevice -UserId $userId -All -ErrorAction Stop
        foreach ($dev in $owned) {
            # Filter to device objects only
            $odataType = $dev.AdditionalProperties['@odata.type']
            if ($odataType -and $odataType -ne '#microsoft.graph.device') { continue }

            if ($allDevices.ContainsKey($dev.Id)) {
                # Already have it from registered - mark as both
                $existing = $allDevices[$dev.Id]
                if ($existing._Source -notlike '*Owned*') {
                    $existing._Source = "$($existing._Source) + Owned"
                }
            }
            else {
                try {
                    $full = Get-MgDevice -DeviceId $dev.Id -Property $deviceProperties -ErrorAction Stop
                    $full | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Owned' -Force
                    $allDevices[$dev.Id] = $full
                }
                catch {
                    $dev | Add-Member -NotePropertyName '_Source' -NotePropertyValue 'Owned' -Force
                    $allDevices[$dev.Id] = $dev
                }
            }
        }
    }
    catch {
        Write-Host "  Could not retrieve owned devices: $_" -ForegroundColor Yellow
    }

    if ($allDevices.Count -eq 0) {
        Write-Host "  No devices linked to this user." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Found $($allDevices.Count) device(s):" -ForegroundColor White
    Write-Host ""

    $deviceIndex = 1
    foreach ($entry in $allDevices.GetEnumerator()) {
        $d = $entry.Value

        # Safely read properties (some may be null on directoryObject fallback)
        $dName     = if ($d.DisplayName)       { $d.DisplayName }       else { "N/A" }
        $dOS       = if ($d.OperatingSystem)    { $d.OperatingSystem }    else { "—" }
        $dOSVer    = if ($d.OperatingSystemVersion) { $d.OperatingSystemVersion } else { "" }
        $dMfr      = if ($d.Manufacturer)       { $d.Manufacturer }       else { "" }
        $dModel    = if ($d.Model)              { $d.Model }              else { "" }
        $dHardware = if ($dMfr -or $dModel) { "$dMfr $dModel".Trim() } else { "—" }
        $dTrust    = if ($d.TrustType)          { $d.TrustType }          else { "—" }
        $dProfile  = if ($d.ProfileType)        { $d.ProfileType }        else { "" }
        $dSource   = if ($d._Source)            { $d._Source }            else { "—" }

        # Compliance
        $complianceText   = switch ($d.IsCompliant) { $true { "Compliant" } $false { "Non-Compliant" } default { "Unknown" } }
        $complianceColour = switch ($d.IsCompliant) { $true { "Green" }     $false { "Red" }           default { "DarkGray" } }

        # Managed
        $managedText   = switch ($d.IsManaged) { $true { "Managed" } $false { "Unmanaged" } default { "Unknown" } }
        $managedColour = switch ($d.IsManaged) { $true { "Green" }   $false { "Yellow" }    default { "DarkGray" } }

        # Enabled
        $enabledText   = switch ($d.AccountEnabled) { $true { "Enabled" } $false { "Disabled" } default { "—" } }
        $enabledColour = switch ($d.AccountEnabled) { $true { "Green" }   $false { "Red" }      default { "DarkGray" } }

        # Timestamps
        $dRegistered = if ($d.RegistrationDateTime)             { $d.RegistrationDateTime.ToString("yyyy-MM-dd HH:mm") } else { "—" }
        $dLastSignIn = if ($d.ApproximateLastSignInDateTime)     { $d.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd HH:mm") } else { "—" }

        # Stale device warning (no sign-in in 90+ days)
        $staleWarning = ""
        if ($d.ApproximateLastSignInDateTime) {
            $daysSince = ((Get-Date) - $d.ApproximateLastSignInDateTime).Days
            if ($daysSince -ge 90) {
                $staleWarning = " (STALE - ${daysSince}d ago)"
            }
        }

        Write-Host "    [$deviceIndex] $dName" -ForegroundColor White
        Write-Host "        OS           : $dOS $dOSVer" -ForegroundColor White
        Write-Host "        Hardware     : $dHardware" -ForegroundColor White
        Write-Host "        Trust Type   : $dTrust" -ForegroundColor $(switch ($dTrust) { "AzureAd" { "Cyan" } "ServerAd" { "DarkCyan" } "Workplace" { "DarkYellow" } default { "White" } })
        if ($dProfile) {
            Write-Host "        Profile Type : $dProfile" -ForegroundColor White
        }
        Write-Host "        Relationship : $dSource" -ForegroundColor DarkGray
        Write-Host "        Status       : " -ForegroundColor White -NoNewline
        Write-Host $enabledText -ForegroundColor $enabledColour -NoNewline
        Write-Host " | " -NoNewline
        Write-Host $complianceText -ForegroundColor $complianceColour -NoNewline
        Write-Host " | " -NoNewline
        Write-Host $managedText -ForegroundColor $managedColour
        Write-Host "        Registered   : $dRegistered" -ForegroundColor White
        Write-Host "        Last Sign-In : $dLastSignIn" -ForegroundColor White -NoNewline
        if ($staleWarning) {
            Write-Host $staleWarning -ForegroundColor Red
        }
        else {
            Write-Host ""
        }
        Write-Host "        Device ID    : $($d.DeviceId)" -ForegroundColor DarkGray
        Write-Host ""

        $deviceIndex++
    }
}

function Invoke-ResetPasswordAndRevoke {
    param(
        [PSCustomObject]$User,
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    if (-not $ADUser) {
        Write-Host "  No AD account found. Cannot reset password." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  PASSWORD RESET + SESSION REVOKE" -ForegroundColor Yellow
    Write-Host "  This will:" -ForegroundColor White
    Write-Host "    1. Reset the AD password to a random temporary password" -ForegroundColor White
    Write-Host "    2. Set 'must change password at next logon' in AD" -ForegroundColor White
    Write-Host "    3. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    # Generate random password
    $length = 16
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new($length)
    $rng.GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    # Step 1: Reset AD password
    Write-Host "  [1/3] Resetting AD password..." -ForegroundColor Cyan -NoNewline
    try {
        Set-ADAccountPassword -Identity $ADUser.SamAccountName -NewPassword $securePassword -Reset -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
        return
    }

    # Step 2: Force change at next logon
    Write-Host "  [2/3] Setting change password at next logon..." -ForegroundColor Cyan -NoNewline
    try {
        Set-ADUser -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    # Step 3: Revoke Entra sessions
    Write-Host "  [3/3] Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
    try {
        $revokeUri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    Write-Host ""
    Write-Host "  Temporary password: $password" -ForegroundColor Yellow
    Write-Host "  IMPORTANT: Communicate this to the user securely." -ForegroundColor Yellow
    Write-Host "  The user must change it at next logon." -ForegroundColor Yellow
}

function Invoke-RequirePasswordChange {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    if (-not $ADUser) {
        Write-Host "  No AD account found. Cannot set password flag." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  REQUIRE PASSWORD CHANGE AT NEXT LOGON" -ForegroundColor Yellow
    Write-Host "  This will flag the AD account so the user must change" -ForegroundColor White
    Write-Host "  their password at next sign-in." -ForegroundColor White
    Write-Host ""

    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Setting change password at next logon..." -ForegroundColor Cyan -NoNewline
    try {
        Set-ADUser -Identity $ADUser.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }
}

function Invoke-DisableAndRevoke {
    param(
        [PSCustomObject]$User,
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    Write-Host ""
    Write-Host "  DISABLE ACCOUNT + REVOKE SESSIONS" -ForegroundColor Red
    Write-Host "  This will:" -ForegroundColor White
    if ($ADUser) {
        Write-Host "    1. Disable the account in Active Directory" -ForegroundColor White
        Write-Host "    2. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    }
    else {
        Write-Host "    1. No AD account found - will skip AD disable" -ForegroundColor Yellow
        Write-Host "    2. Revoke all Entra ID sign-in sessions" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "  WARNING: The user will be unable to sign in." -ForegroundColor Red
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return
    }

    # Step 1: Disable in AD
    if ($ADUser) {
        Write-Host "  [1/2] Disabling AD account..." -ForegroundColor Cyan -NoNewline
        try {
            Disable-ADAccount -Identity $ADUser.SamAccountName -ErrorAction Stop
            Write-Host " Done" -ForegroundColor Green
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warning "    Error: $_"
        }
    }
    else {
        Write-Host "  [1/2] Skipped AD disable (no AD account)." -ForegroundColor Yellow
    }

    # Step 2: Revoke Entra sessions
    Write-Host "  [2/2] Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
    try {
        $revokeUri = "https://graph.microsoft.com/v1.0/users/$($User.Id)/revokeSignInSessions"
        Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "    Error: $_"
    }

    Write-Host ""
    Write-Host "  Account disabled and sessions revoked." -ForegroundColor Red
}

# ==============================================================================
# MAIN
# ==============================================================================

Write-Host "============================================================" -ForegroundColor White
Write-Host "  USER MANAGEMENT TOOL" -ForegroundColor Cyan
Write-Host "  Entra ID + Active Directory" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor White

# -- Connect to services ------------------------------------------------------
Connect-ToGraph

Write-Host ""
$adConnected = Connect-ToAD

if (-not $adConnected) {
    Write-Host ""
    Write-Host "Active Directory is not available. AD actions will be limited." -ForegroundColor Yellow
    Write-Host "Entra-only actions will still work." -ForegroundColor Yellow
}

Write-Host ""

# -- Main loop -----------------------------------------------------------------
$exitScript = $false

while (-not $exitScript) {
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  SEARCH FOR A USER" -ForegroundColor Cyan
    Write-Host "  Enter a search term (partial UPN, first name, or last name)" -ForegroundColor White
    Write-Host "  Or type 'EXIT' to quit." -ForegroundColor DarkGray
    Write-Host ""

    $searchTerm = Read-Host "  Search"

    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "  No search term entered." -ForegroundColor Yellow
        continue
    }

    if ($searchTerm -eq "EXIT" -or $searchTerm -eq "exit") {
        $exitScript = $true
        break
    }

    # -- Search ----------------------------------------------------------------
    $searchResults = Search-Users -SearchTerm $searchTerm

    if (-not $searchResults -or $searchResults.Count -eq 0) {
        Write-Host "  No users found matching '$searchTerm'." -ForegroundColor Yellow
        continue
    }

    # -- Display results -------------------------------------------------------
    Write-Host ""
    Write-Host "  Found $($searchResults.Count) user(s):" -ForegroundColor Green
    Write-Host ""

    $i = 1
    foreach ($sr in $searchResults) {
        $enabledTag = if ($sr.AccountEnabled -eq $true) { "[Enabled]" } else { "[Disabled]" }
        $enabledColour = if ($sr.AccountEnabled -eq $true) { "Green" } else { "Red" }
        Write-Host "    [$i] " -ForegroundColor White -NoNewline
        Write-Host "$($sr.DisplayName)" -ForegroundColor White -NoNewline
        Write-Host " - $($sr.UPN) " -ForegroundColor DarkCyan -NoNewline
        Write-Host $enabledTag -ForegroundColor $enabledColour
        $i++
    }

    Write-Host ""
    Write-Host "    [0] Back to search" -ForegroundColor DarkGray
    Write-Host ""

    $userChoice = Read-Host "  Select a user (number)"

    if ($userChoice -eq "0" -or [string]::IsNullOrWhiteSpace($userChoice)) {
        continue
    }

    $selectedIndex = 0
    if (-not [int]::TryParse($userChoice, [ref]$selectedIndex)) {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
        continue
    }

    $searchArray = @($searchResults)
    if ($selectedIndex -lt 1 -or $selectedIndex -gt $searchArray.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
        continue
    }

    $selectedUser = $searchArray[$selectedIndex - 1]

    # -- User detail + action loop ---------------------------------------------
    $backToSearch = $false

    while (-not $backToSearch -and -not $exitScript) {
        $adUser = Show-UserDetail -User $selectedUser
        Show-UserDevices -User $selectedUser

        Write-Host ""
        Write-Host "  -- ACTIONS --" -ForegroundColor Yellow
        Write-Host "    [1] Reset password (AD) + Revoke Entra sessions"
        Write-Host "    [2] Require password change at next logon (AD)"
        Write-Host "    [3] Disable account (AD) + Revoke Entra sessions"
        Write-Host "    [4] Revoke Entra sessions only"
        Write-Host "    [5] Unlock AD account"
        Write-Host "    [6] Back to search"
        Write-Host "    [7] Exit"
        Write-Host ""

        $actionChoice = Read-Host "  Action"

        switch ($actionChoice) {
            "1" {
                if (-not $adConnected) {
                    Write-Host "  Active Directory is not connected. Cannot reset password." -ForegroundColor Red
                }
                else {
                    Invoke-ResetPasswordAndRevoke -User $selectedUser -ADUser $adUser
                }
            }
            "2" {
                if (-not $adConnected) {
                    Write-Host "  Active Directory is not connected. Cannot set password flag." -ForegroundColor Red
                }
                else {
                    Invoke-RequirePasswordChange -ADUser $adUser
                }
            }
            "3" {
                if (-not $adConnected) {
                    Write-Host "  AD not connected. Revoking Entra sessions only." -ForegroundColor Yellow
                }
                Invoke-DisableAndRevoke -User $selectedUser -ADUser $adUser
            }
            "4" {
                Write-Host ""
                $confirmRevoke = Read-Host "  Revoke all Entra sessions for $($selectedUser.DisplayName)? (Y/N)"
                if ($confirmRevoke -eq "Y" -or $confirmRevoke -eq "y") {
                    Write-Host "  Revoking Entra ID sessions..." -ForegroundColor Cyan -NoNewline
                    try {
                        $revokeUri = "https://graph.microsoft.com/v1.0/users/$($selectedUser.Id)/revokeSignInSessions"
                        Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ErrorAction Stop | Out-Null
                        Write-Host " Done" -ForegroundColor Green
                    }
                    catch {
                        Write-Host " FAILED" -ForegroundColor Red
                        Write-Warning "    Error: $_"
                    }
                }
                else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
            }
            "5" {
                if (-not $adConnected) {
                    Write-Host "  Active Directory is not connected. Cannot unlock." -ForegroundColor Red
                }
                elseif (-not $adUser) {
                    Write-Host "  No AD account found." -ForegroundColor Red
                }
                else {
                    Write-Host "  Unlocking AD account..." -ForegroundColor Cyan -NoNewline
                    try {
                        Unlock-ADAccount -Identity $adUser.SamAccountName -ErrorAction Stop
                        Write-Host " Done" -ForegroundColor Green
                    }
                    catch {
                        Write-Host " FAILED" -ForegroundColor Red
                        Write-Warning "    Error: $_"
                    }
                }
            }
            "6" {
                $backToSearch = $true
            }
            "7" {
                $exitScript = $true
            }
            default {
                Write-Host "  Invalid option." -ForegroundColor Yellow
            }
        }

        # After an action, offer to refresh or go back
        if (-not $backToSearch -and -not $exitScript) {
            Write-Host ""
            Write-Host "  Press Enter to refresh user details, or type 'B' to go back to search." -ForegroundColor DarkGray
            $postAction = Read-Host "  "
            if ($postAction -eq "B" -or $postAction -eq "b") {
                $backToSearch = $true
            }
        }
    }
}

# -- Cleanup -------------------------------------------------------------------
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Would you like to disconnect from services?" -ForegroundColor Cyan
Write-Host "  [1] Yes - disconnect from Graph (AD session is domain-based)"
Write-Host "  [2] No  - keep sessions active"
Write-Host ""
$disconnectChoice = Read-Host "Select an option (1/2)"

if ($disconnectChoice -eq "1") {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disconnected from Microsoft Graph." -ForegroundColor DarkGray
    Write-Host "Note: AD connectivity is domain-based and does not require disconnection." -ForegroundColor DarkGray
}
else {
    Write-Host "Sessions kept active." -ForegroundColor Green
    Write-Host "  Graph: Run 'Disconnect-MgGraph' when finished." -ForegroundColor DarkGray
}

# -- Clear variables -----------------------------------------------------------
Write-Host "Clearing script variables..." -ForegroundColor DarkGray

$variablesToClear = @(
    'context', 'ctx', 'needsConnect', 'sessionId', 'id',
    'currentScopes', 'hasUserWrite', 'hasUserRead', 'hasDeviceRead', 'missing',
    'adConnected', 'domain',
    'exitScript', 'backToSearch',
    'searchTerm', 'searchResults', 'searchArray',
    'userChoice', 'selectedIndex', 'selectedUser',
    'adUser', 'samAccount', 'domainDN', 'riskyUser',
    'actionChoice', 'postAction',
    'confirm', 'confirmRevoke', 'confirmDismiss', 'confirmCompromised',
    'password', 'securePassword', 'length', 'chars', 'rng', 'bytes',
    'revokeUri', 'body',
    'graphFilter', 'safeTerm', 'entraUsers', 'eu',
    'enabledTag', 'enabledColour',
    'groups', 'g',
    'disconnectChoice',
    'i', 'sr',
    'allDevices', 'registered', 'owned', 'dev', 'full', 'entry', 'd', 'odataType',
    'deviceIndex', 'deviceProperties',
    'dName', 'dOS', 'dOSVer', 'dMfr', 'dModel', 'dHardware',
    'dTrust', 'dProfile', 'dSource',
    'complianceText', 'complianceColour', 'managedText', 'managedColour',
    'enabledText', 'enabledColour', 'dRegistered', 'dLastSignIn',
    'staleWarning', 'daysSince'
)

foreach ($var in $variablesToClear) {
    Remove-Variable -Name $var -ErrorAction SilentlyContinue
}
Remove-Variable -Name 'variablesToClear' -ErrorAction SilentlyContinue

Write-Host "Done.`n" -ForegroundColor DarkGray
