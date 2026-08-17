#requires -Version 5.1

<#
.SYNOPSIS
    Enumerates what the *current user* (or a supplied domain account) is
    actually able to do - on this computer and in the domain - and builds an
    interactive HTML report that separates "normal for a standard account"
    from "higher than it should be", with a risk explanation and a
    remediation for every finding.

.DESCRIPTION
    This script is intended to be run from a domain-joined workstation or
    member server, by any authenticated domain user - it does not require
    local administrator rights or Domain Admin rights, although some
    sections return richer evidence when run elevated.

    It is entirely READ-ONLY / non-destructive. It never changes group
    membership, never changes permissions, never changes account settings.
    The only thing written to disk anywhere is a short-lived temporary file
    produced by "secedit /export" (to read the local User Rights Assignment
    policy), which is deleted again before the script exits, plus the
    evidence files this script itself writes under -OutputPath.

    Credentials:
      - Run interactively with no -Credential and you will be prompted for
        domain credentials once, via the normal Windows credential prompt.
        Press Cancel, or leave the username blank, to scan using your
        current, already-logged-on Windows identity instead (no password
        is asked for or used in that case).
      - Pass -Credential to scan a specific domain account non-interactively.
      - Pass -NoCredentialPrompt to skip the prompt entirely and always use
        the current Windows identity (useful for automation).
      - A supplied password is only ever held in memory for the lifetime of
        this script (to bind to LDAP as that account); it is never written
        to disk, logged, or included in any report.

    What "local machine" means here:
      Local group membership and the local User Rights Assignment policy
      are evaluated by comparing the scanned identity's full SID set (its
      own SID plus every domain group it belongs to, resolved through
      nested groups by Active Directory itself via the "tokenGroups"
      attribute) against local group members and the SIDs listed against
      each right in the local security policy. This does not require
      logging on as the scanned account - only knowing its SID.
      Live, currently-*enabled* token privileges (the "Local machine -
      live session" section) can only be read for the account actually
      running this PowerShell session, since that requires an active logon
      token; when a different -Credential is supplied this section is
      skipped and clearly marked as not applicable.

    What "in the domain" means here:
      - Every group the account is a transitive member of (via the
        constructed "tokenGroups" attribute), matched against a catalog of
        well-known privileged group SIDs/RIDs (Domain Admins, Enterprise
        Admins, Account Operators, Backup Operators, DnsAdmins, etc.) so it
        works across domains regardless of UI language.
      - Account configuration that affects security: UAC flags (password
        never expires, reversible encryption, delegation flags,
        pre-authentication), AdminCount, and any Service Principal Names
        (Kerberoastable) or constrained-delegation targets.
      - Active Directory permissions (ACLs) the account holds, directly or
        via group membership, on: the domain root, AdminSDHolder, the
        Group Policy Objects container (edit rights on existing GPOs), the
        account's own AD object, and its own computer object - including a
        specific check for the two "DCSync" replication rights and for
        password-reset rights. Pass -ScanOuAcls to additionally sweep every
        OU in the domain for the same dangerous rights (slower; capped by
        -MaxOusToScanAcls).

    This does NOT compute Windows' full effective/resultant access (for
    example it does not walk every OU's delegated ACL by default, and it
    does not attempt to simulate NTFS/share permissions on other
    computers). Treat it as a strong, fast first pass, not a formal
    penetration-test-grade access review.

.NOTES
    Anything this script could not read (access denied, unreachable domain
    controller, secedit failing without elevation, etc.) is recorded as an
    explicit "evidence gap" finding rather than silently skipped, so the
    report is honest about what it did and did not manage to check.

.EXAMPLE
    .\AD-Scan-on-domainjoined-pc.ps1
    Prompts for domain credentials (Cancel/blank = use the current logon).

.EXAMPLE
    .\AD-Scan-on-domainjoined-pc.ps1 -NoCredentialPrompt
    Scans the current, already-logged-on identity without any prompt.

.EXAMPLE
    .\AD-Scan-on-domainjoined-pc.ps1 -Credential (Get-Credential) -ScanOuAcls
    Scans a specific account and additionally sweeps every OU's ACL.

.EXAMPLE
    .\AD-Scan-on-domainjoined-pc.ps1 -OutputPath C:\Temp\MyPrivilegeReport -DomainController dc01.contoso.com
#>

[CmdletBinding()]
param (
    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential,

    [Parameter()]
    [switch]
    $NoCredentialPrompt,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $OutputPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $DomainController,

    [Parameter()]
    [switch]
    $ScanOuAcls,

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]
    $MaxOusToScanAcls = 300,

    [Parameter()]
    [ValidateRange(1, 2000)]
    [int]
    $MaxGposToScanAcls = 500
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

###########################################################################
# Generic helpers
###########################################################################

function Write-ScanLog {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch ($Level) {
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        default { "Gray" }
    }
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

function ConvertTo-LdapFilterLiteral {
    <#
        Escapes a value for safe inclusion in an LDAP search filter, per
        RFC 4515.
    #>
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $Escaped = $Value
    $Escaped = $Escaped.Replace("\", "\5c")
    $Escaped = $Escaped.Replace("*", "\2a")
    $Escaped = $Escaped.Replace("(", "\28")
    $Escaped = $Escaped.Replace(")", "\29")
    $Escaped = $Escaped.Replace([string][char]0, "\00")
    return $Escaped
}

function Get-BareAccountName {
    <#
        Extracts the bare sAMAccountName portion out of "DOMAIN\user",
        "user@domain.com" or a plain "user" string.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Name -match '^[^\\]+\\(.+)$') {
        return $Matches[1]
    }
    if ($Name -match '^([^@]+)@.+$') {
        return $Matches[1]
    }
    return $Name
}

function ConvertFrom-AdsLargeInteger {
    <#
        Converts an Integer8 (IADsLargeInteger COM) attribute value - as
        returned for attributes like pwdLastSet - into a [DateTime], or
        $null when the value represents "never" (0 or negative).
    #>
    param (
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    try {
        $HighPart = $Value.GetType().InvokeMember("HighPart", "GetProperty", $null, $Value, $null)
        $LowPart  = $Value.GetType().InvokeMember("LowPart", "GetProperty", $null, $Value, $null)
        $Int64Value = ([int64]$HighPart -shl 32) -bor ([uint32]$LowPart)
        if ($Int64Value -le 0) { return $null }
        return [DateTime]::FromFileTime($Int64Value)
    }
    catch {
        return $null
    }
}

###########################################################################
# Directory (LDAP/ADSI) helpers
###########################################################################

function New-BoundDirectoryEntry {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($Credential -and -not [string]::IsNullOrWhiteSpace($Credential.UserName)) {
        $NetworkCredential = $Credential.GetNetworkCredential()
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path,
            $Credential.UserName,
            $NetworkCredential.Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )
    }

    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function New-BoundSearcher {
    param (
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$SearchRoot,

        [Parameter(Mandatory)]
        [string]$Filter,

        [Parameter()]
        [string[]]$Properties = @(),

        [Parameter()]
        [System.DirectoryServices.SearchScope]$Scope = [System.DirectoryServices.SearchScope]::Subtree
    )

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($SearchRoot)
    $Searcher.Filter = $Filter
    $Searcher.SearchScope = $Scope
    $Searcher.PageSize = 1000
    if ($Properties.Count -gt 0) {
        [void]$Searcher.PropertiesToLoad.AddRange($Properties)
    }
    return $Searcher
}

function Get-DomainContext {
    param (
        [Parameter()]
        [string]$DomainController,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $RootPath = if ($DomainController) { "LDAP://$DomainController/RootDSE" } else { "LDAP://RootDSE" }
    $RootDse = New-BoundDirectoryEntry -Path $RootPath -Credential $Credential

    $DefaultNamingContext = [string]$RootDse.Properties["defaultNamingContext"][0]

    if ([string]::IsNullOrWhiteSpace($DefaultNamingContext)) {
        throw "Could not read defaultNamingContext from RootDSE - check connectivity, DNS resolution and credentials."
    }

    $ConfigurationNamingContext = $null
    if ($RootDse.Properties["configurationNamingContext"].Count) {
        $ConfigurationNamingContext = [string]$RootDse.Properties["configurationNamingContext"][0]
    }

    $DnsHostName = $null
    if ($RootDse.Properties["dnsHostName"].Count) {
        $DnsHostName = [string]$RootDse.Properties["dnsHostName"][0]
    }

    $DomainDnsName = ($DefaultNamingContext -replace "DC=", "" -replace ",", ".")
    $Server = if ($DomainController) { $DomainController } elseif ($DnsHostName) { $DnsHostName } else { $DomainDnsName }

    [PSCustomObject]@{
        Server                     = $Server
        DefaultNamingContext       = $DefaultNamingContext
        ConfigurationNamingContext = $ConfigurationNamingContext
        DomainDnsName              = $DomainDnsName
    }
}

function Find-AdTargetAccount {
    param (
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        $DomainContext,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $EscapedSam = ConvertTo-LdapFilterLiteral -Value $SamAccountName
    $SearchRootPath = "LDAP://$($DomainContext.Server)/$($DomainContext.DefaultNamingContext)"
    $SearchRoot = New-BoundDirectoryEntry -Path $SearchRootPath -Credential $Credential

    $Props = @(
        "distinguishedName", "objectSid", "sAMAccountName", "userPrincipalName",
        "displayName", "whenCreated", "pwdLastSet", "userAccountControl",
        "adminCount", "servicePrincipalName", "msDS-AllowedToDelegateTo",
        "primaryGroupID", "memberOf", "description"
    )

    $Searcher = New-BoundSearcher -SearchRoot $SearchRoot `
        -Filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$EscapedSam))" `
        -Properties $Props

    $Result = $Searcher.FindOne()
    if (-not $Result) { return $null }

    $Entry = $Result.GetDirectoryEntry()

    $ObjectSidBytes = $Entry.Properties["objectSid"][0]
    $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$ObjectSidBytes), 0)).Value

    $Spns = @()
    if ($Entry.Properties["servicePrincipalName"].Count) { $Spns = @($Entry.Properties["servicePrincipalName"]) }

    $DelegateTo = @()
    if ($Entry.Properties["msDS-AllowedToDelegateTo"].Count) { $DelegateTo = @($Entry.Properties["msDS-AllowedToDelegateTo"]) }

    $MemberOf = @()
    if ($Entry.Properties["memberOf"].Count) { $MemberOf = @($Entry.Properties["memberOf"]) }

    $WhenCreated = $null
    if ($Entry.Properties["whenCreated"].Count) { $WhenCreated = $Entry.Properties["whenCreated"][0] }

    $PwdLastSet = $null
    if ($Entry.Properties["pwdLastSet"].Count) {
        $PwdLastSet = ConvertFrom-AdsLargeInteger -Value $Entry.Properties["pwdLastSet"][0]
    }

    [PSCustomObject]@{
        DistinguishedName     = [string]$Entry.Properties["distinguishedName"][0]
        SamAccountName        = [string]$Entry.Properties["sAMAccountName"][0]
        ObjectSid             = $ObjectSid
        UserPrincipalName     = if ($Entry.Properties["userPrincipalName"].Count) { [string]$Entry.Properties["userPrincipalName"][0] } else { $null }
        DisplayName           = if ($Entry.Properties["displayName"].Count) { [string]$Entry.Properties["displayName"][0] } else { $null }
        WhenCreated            = $WhenCreated
        PwdLastSet            = $PwdLastSet
        UserAccountControl    = if ($Entry.Properties["userAccountControl"].Count) { [int]$Entry.Properties["userAccountControl"][0] } else { 0 }
        AdminCount            = if ($Entry.Properties["adminCount"].Count) { [int]$Entry.Properties["adminCount"][0] } else { 0 }
        ServicePrincipalNames = $Spns
        AllowedToDelegateTo   = $DelegateTo
        PrimaryGroupID        = if ($Entry.Properties["primaryGroupID"].Count) { [int]$Entry.Properties["primaryGroupID"][0] } else { $null }
        MemberOf              = $MemberOf
        Description           = if ($Entry.Properties["description"].Count) { [string]$Entry.Properties["description"][0] } else { $null }
    }
}

function Get-TokenGroupSids {
    <#
        Reads the constructed "tokenGroups" attribute for a DN - the same
        flattened, recursively-nested group SID set Windows computes for a
        logon token - so nested domain group membership does not need to
        be walked by hand.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        $DomainContext,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $Path = "LDAP://$($DomainContext.Server)/$DistinguishedName"
    $Entry = New-BoundDirectoryEntry -Path $Path -Credential $Credential
    $Entry.RefreshCache(@("tokenGroups"))

    $Sids = New-Object System.Collections.Generic.List[string]
    if ($Entry.Properties["tokenGroups"]) {
        foreach ($Value in $Entry.Properties["tokenGroups"]) {
            $Sids.Add((New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$Value), 0)).Value)
        }
    }
    return $Sids
}

function Resolve-SidDisplayName {
    param (
        [Parameter(Mandatory)]
        [string]$Sid
    )

    try {
        $Account = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount])
        return $Account.Value
    }
    catch {
        return $Sid
    }
}

###########################################################################
# Knowledge base: local User Rights Assignment / token privileges
###########################################################################

function Get-DangerousPrivilegeCatalog {
    <#
        Every right that can appear under [Privilege Rights] in a local
        security policy export (secedit /areas USER_RIGHTS), plus the
        classification used to build findings. Names are the
        language-independent "SeXxxPrivilege" / "SeXxxLogonRight" constants,
        matching what secedit and LookupPrivilegeName both return regardless
        of the OS display language.
    #>
    return [ordered]@{
        "SeTcbPrivilege" = @{
            Severity = "critical"; Baseline = "Not expected outside SYSTEM/LocalService."
            Risk = "Act as part of the operating system: lets the holder create tokens for any user without authenticating, and impersonate anyone. This is effectively full system control."
            Remediation = "Remove from every account except built-in service identities. Never assign to interactive or admin accounts."
        }
        "SeCreateTokenPrivilege" = @{
            Severity = "critical"; Baseline = "Not expected outside SYSTEM."
            Risk = "Create Token Object: lets the holder fabricate an arbitrary access token (any user, any group, any privilege), a direct path to becoming any account including Domain Admin equivalents locally."
            Remediation = "Remove from every non-SYSTEM account."
        }
        "SeLoadDriverPrivilege" = @{
            Severity = "critical"; Baseline = "Expected only for imaging/deployment/driver-management service accounts."
            Risk = "Load and Unload Device Drivers: allows loading a kernel-mode driver, a classic route to full kernel code execution, disabling security tooling, or exploiting a signed-but-vulnerable ('BYOVD') driver."
            Remediation = "Restrict to dedicated deployment accounts; remove from interactive/admin accounts and general service accounts."
        }
        "SeRestorePrivilege" = @{
            Severity = "critical"; Baseline = "Expected only for backup service accounts."
            Risk = "Restore Files and Directories: can overwrite any file or registry value while ignoring ACLs, including service binaries, protected system files and registry hives - a well-known local privilege-escalation and persistence primitive."
            Remediation = "Restrict to a dedicated backup service account; remove from interactive/admin accounts."
        }
        "SeBackupPrivilege" = @{
            Severity = "critical"; Baseline = "Expected only for backup service accounts."
            Risk = "Back Up Files and Directories: can read any file while ignoring ACLs, including the SAM/SYSTEM/NTDS.dit hives, enabling full offline credential extraction."
            Remediation = "Restrict to a dedicated backup service account; remove from interactive/admin accounts."
        }
        "SeDebugPrivilege" = @{
            Severity = "critical"; Baseline = "Expected only for administrators, debugging tools and EDR/AV service accounts."
            Risk = "Debug Programs: lets the holder open a handle to (almost) any process - including LSASS - and read/write its memory. Trivially leads to credential theft (LSASS dumping) and code injection into SYSTEM processes."
            Remediation = "Remove from standard user and low-privilege service accounts. Only grant to admins and to the specific tooling that genuinely needs it."
        }
        "SeTakeOwnershipPrivilege" = @{
            Severity = "high"; Baseline = "Expected only for administrators."
            Risk = "Take Ownership of Files or Other Objects: lets the holder take ownership of any securable object, and an object's owner can always grant themselves any permission on it afterwards - equivalent to full control everywhere."
            Remediation = "Remove from non-administrative accounts."
        }
        "SeSecurityPrivilege" = @{
            Severity = "high"; Baseline = "Expected only for administrators/audit accounts."
            Risk = "Manage Auditing and Security Log: can view and clear the Security event log and change audit policy, enabling attackers to read sensitive audit data or erase evidence of their activity."
            Remediation = "Restrict to a small, monitored set of administrative/audit accounts; alert on Security-log clears (event 1102)."
        }
        "SeRelabelPrivilege" = @{
            Severity = "high"; Baseline = "Not expected outside SYSTEM."
            Risk = "Modify an Object Label: can change the Mandatory Integrity Control (integrity level) label of a securable object, which can be used to bypass integrity-based protections."
            Remediation = "Remove from every non-SYSTEM account."
        }
        "SeEnableDelegationPrivilege" = @{
            Severity = "critical"; Baseline = "Expected only for Domain Admins-tier accounts, and normally only exercised on domain controllers."
            Risk = "Enable Computer and User Accounts to be Trusted for Delegation: lets the holder configure unconstrained/constrained delegation on other accounts - a domain-compromise primitive normally reserved for domain controllers."
            Remediation = "Remove from every workstation/member-server local policy; this right should not be meaningfully exercisable outside domain controllers."
        }
        "SeSyncAgentPrivilege" = @{
            Severity = "high"; Baseline = "Expected only for directory-synchronization service accounts (for example Azure AD Connect)."
            Risk = "Synchronize Directory Service Data: required to perform directory replication reads, and complements AD-level DCSync rights - holding it plus the matching AD replication permissions can extract every account's password hash."
            Remediation = "Restrict to the specific, documented synchronization service account; verify the matching AD replication rights (see the AD Object Permissions tab) are equally restricted."
        }
        "SeTrustedCredManAccessPrivilege" = @{
            Severity = "high"; Baseline = "Not expected outside a small set of credential-management tooling."
            Risk = "Access Credential Manager as a Trusted Caller: allows reading other users' stored Credential Manager secrets."
            Remediation = "Remove from general user and service accounts."
        }
        "SeDelegateSessionUserImpersonatePrivilege" = @{
            Severity = "high"; Baseline = "Expected only for Remote Desktop / session-broker style service accounts."
            Risk = "Impersonate other users' logged-on sessions on this system, similar in effect to token-impersonation privilege escalation."
            Remediation = "Restrict to the specific service that requires it (e.g. RDS infrastructure roles)."
        }
        "SeImpersonatePrivilege" = @{
            Severity = "high"; Baseline = "Expected for built-in service identities (LOCAL SERVICE, NETWORK SERVICE, IIS APPPOOL\\*) and legitimate Windows services."
            Risk = "Impersonate a Client After Authentication: the well-known enabler of 'Potato'-family local privilege escalation (PrintSpoofer, RoguePotato, GodPotato, etc.), letting a service-context foothold become SYSTEM."
            Remediation = "Do not grant to interactive user accounts or general-purpose service accounts that do not strictly require it."
        }
        "SeAssignPrimaryTokenPrivilege" = @{
            Severity = "high"; Baseline = "Expected for built-in service identities and service-hosting accounts."
            Risk = "Replace a Process Level Token: combined with impersonation rights, enables the same 'Potato'-style local privilege-escalation chains as SeImpersonatePrivilege."
            Remediation = "Do not grant to interactive user accounts."
        }
        "SeSystemEnvironmentPrivilege" = @{
            Severity = "high"; Baseline = "Expected only for administrators."
            Risk = "Modify Firmware Environment Values: can alter UEFI/firmware variables, with potential impact on boot security configuration."
            Remediation = "Remove from non-administrative accounts."
        }
        "SeManageVolumePrivilege" = @{
            Severity = "medium"; Baseline = "Expected only for administrators / storage-management tooling."
            Risk = "Perform Volume Maintenance Tasks: grants raw, low-level disk/volume access that can bypass normal file-ACL semantics for file-system operations such as defragmentation of system files."
            Remediation = "Remove from non-administrative accounts."
        }
        "SeMachineAccountPrivilege" = @{
            Severity = "medium"; Baseline = "Expected only where self-service workstation joining is intentionally delegated."
            Risk = "Add Workstations to Domain: lets the holder join new computer accounts to the domain, which (combined with the default 10-computer ms-DS-MachineAccountQuota) can be abused for relay/coercion or RBCD-based attacks against those new computer accounts."
            Remediation = "Restrict to a dedicated provisioning account/process; consider setting ms-DS-MachineAccountQuota to 0 domain-wide."
        }
        "SeCreateGlobalPrivilege" = @{
            Severity = "medium"; Baseline = "Granted by default to Administrators, SERVICE, LOCAL SERVICE and NETWORK SERVICE - normal for those identities."
            Risk = "Create Global Objects: can create objects in the global namespace shared by all sessions, relevant to certain session-isolation attacks/RDP host abuse scenarios."
            Remediation = "Confirm this account is one of the expected built-in service identities; otherwise review why it was added."
        }
        "SeCreateSymbolicLinkPrivilege" = @{
            Severity = "medium"; Baseline = "Granted by default to Administrators (and to standard users when Developer Mode is enabled)."
            Risk = "Create Symbolic Links: symbolic-link creation has been used as a building block in several local privilege-escalation and file-redirection attack chains."
            Remediation = "Confirm this is expected (Administrators, or Developer Mode intentionally enabled); otherwise remove."
        }
        "SeSystemtimePrivilege" = @{
            Severity = "medium"; Baseline = "Granted by default to Administrators and LOCAL SERVICE."
            Risk = "Change the System Time: can shift the system clock, which can disrupt Kerberos authentication (which is time-sensitive) or interfere with time-based log correlation/forensics."
            Remediation = "Confirm this is an expected administrative/service identity."
        }
        "SeLockMemoryPrivilege" = @{
            Severity = "medium"; Baseline = "Granted by default to LOCAL SERVICE/NETWORK SERVICE on some roles (e.g. SQL Server)."
            Risk = "Lock Pages in Memory: pins process memory so it cannot be paged to disk; abnormal for general accounts and mainly relevant to specific server workloads."
            Remediation = "Confirm this maps to a documented server workload account."
        }
        "SeRemoteShutdownPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators."
            Risk = "Force Shutdown from a Remote System: availability impact only (can remotely restart/shut down this computer)."
            Remediation = "Confirm this is an expected administrative account."
        }
        "SeShutdownPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Users on workstations, and to Administrators on servers."
            Risk = "Shut Down the System: availability impact only."
            Remediation = "Generally low priority; review only if present on unexpected server-role accounts."
        }
        "SeIncreaseBasePriorityPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators."
            Risk = "Increase Scheduling Priority: can starve other processes of CPU time (local denial-of-service potential) but has no direct privilege-escalation path."
            Remediation = "Low priority; confirm the account is an expected administrator."
        }
        "SeIncreaseQuotaPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators and LOCAL SERVICE/NETWORK SERVICE."
            Risk = "Adjust Memory Quotas for a Process: minor resource-management right, not directly a privilege-escalation path."
            Remediation = "Low priority."
        }
        "SeProfileSingleProcessPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators."
            Risk = "Profile Single Process: allows performance-profiling of other processes; low direct risk, minor information-disclosure potential."
            Remediation = "Low priority."
        }
        "SeSystemProfilePrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators."
            Risk = "Profile System Performance: system-wide performance profiling; low direct risk."
            Remediation = "Low priority."
        }
        "SeCreatePagefilePrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to Administrators."
            Risk = "Create a Pagefile: can create/resize the paging file; minor availability/disk-space impact only."
            Remediation = "Low priority."
        }
        "SeAuditPrivilege" = @{
            Severity = "low"; Baseline = "Granted by default to LOCAL SERVICE/NETWORK SERVICE."
            Risk = "Generate Security Audits: can write custom entries into the Security event log; low direct risk (log-noise/spoofing potential)."
            Remediation = "Confirm this maps to an expected service identity."
        }
        "SeUndockPrivilege" = @{
            Severity = "info"; Baseline = "Granted by default to Users - normal on laptops."
            Risk = "Remove Computer from Docking Station: physical/availability only."
            Remediation = "No action needed."
        }
        "SeRemoveComputerPrivilege" = @{
            Severity = "low"; Baseline = "Not granted to standard users by default."
            Risk = "Remove Computer from Docking Station (alternate right name on some builds): physical/availability only."
            Remediation = "Confirm expected; low priority."
        }
        "SeTimeZonePrivilege" = @{
            Severity = "info"; Baseline = "Granted by default to Users."
            Risk = "Change the Time Zone: display-only, does not affect the underlying UTC system clock."
            Remediation = "No action needed."
        }
        "SeIncreaseWorkingSetPrivilege" = @{
            Severity = "info"; Baseline = "Granted by default to Users."
            Risk = "Increase a Process Working Set: minor per-process memory tuning right."
            Remediation = "No action needed."
        }
        "SeChangeNotifyPrivilege" = @{
            Severity = "info"; Baseline = "Granted by default to Everyone/Users - required for ordinary file/folder navigation ('bypass traverse checking')."
            Risk = "No meaningful risk on its own."
            Remediation = "No action needed."
        }
        "SeInteractiveLogonRight" = @{
            Severity = "info"; Baseline = "Granted by default to Users/Administrators - required to log on at the console."
            Risk = "Governs whether the account may log on interactively at the local console. Expected for normal user/admin accounts."
            Remediation = "No action needed unless present on an account that should be service-only."
        }
        "SeNetworkLogonRight" = @{
            Severity = "info"; Baseline = "Granted by default to Users/Administrators - required for ordinary network access (SMB, RPC, etc.)."
            Risk = "Governs whether the account may authenticate to this computer over the network. Expected for normal accounts."
            Remediation = "No action needed."
        }
        "SeBatchLogonRight" = @{
            Severity = "info"; Baseline = "Expected for scheduled-task/batch service accounts."
            Risk = "Governs whether the account may log on as a scheduled/batch job."
            Remediation = "Confirm this maps to an expected scheduled-task account."
        }
        "SeServiceLogonRight" = @{
            Severity = "info"; Baseline = "Expected for Windows service accounts."
            Risk = "Governs whether the account may log on as a Windows service."
            Remediation = "Confirm this maps to an expected service account."
        }
        "SeRemoteInteractiveLogonRight" = @{
            Severity = "medium"; Baseline = "Expected for accounts that legitimately use Remote Desktop to this machine."
            Risk = "Governs whether the account may log on via Remote Desktop (RDP), which is meaningful network-facing attack surface."
            Remediation = "Confirm RDP access to this machine is expected for this identity; remove if not."
        }
        "SeDenyInteractiveLogonRight" = @{
            Severity = "secure"; Baseline = "A protective/deny right."
            Risk = "No risk - this explicitly blocks local console logon for the account, a hardening control."
            Remediation = "No action needed."
        }
        "SeDenyNetworkLogonRight" = @{
            Severity = "secure"; Baseline = "A protective/deny right."
            Risk = "No risk - this explicitly blocks network logon for the account, a hardening control."
            Remediation = "No action needed."
        }
        "SeDenyRemoteInteractiveLogonRight" = @{
            Severity = "secure"; Baseline = "A protective/deny right."
            Risk = "No risk - this explicitly blocks RDP logon for the account, a hardening control."
            Remediation = "No action needed."
        }
        "SeDenyBatchLogonRight" = @{
            Severity = "secure"; Baseline = "A protective/deny right."
            Risk = "No risk - this explicitly blocks batch-job logon for the account, a hardening control."
            Remediation = "No action needed."
        }
        "SeDenyServiceLogonRight" = @{
            Severity = "secure"; Baseline = "A protective/deny right."
            Risk = "No risk - this explicitly blocks service logon for the account, a hardening control."
            Remediation = "No action needed."
        }
        "SeCreatePermanentPrivilege" = @{
            Severity = "critical"; Baseline = "Not expected outside SYSTEM."
            Risk = "Create Permanent Shared Objects: can create kernel objects that persist and cannot be removed by normal means; essentially never legitimate for a non-SYSTEM account."
            Remediation = "Remove from every non-SYSTEM account."
        }
    }
}

function Get-UserRightsAssignment {
    <#
        Exports the local security policy's [Privilege Rights] section via
        secedit and parses it into a right-name -> SID-list map. Requires
        no elevation on most systems, but hardened systems may restrict it;
        failures are reported rather than treated as fatal.
    #>
    $TempFile = Join-Path $env:TEMP ("secpol-{0}.inf" -f ([guid]::NewGuid().ToString("N")))
    $Rights = [ordered]@{}
    $Available = $false
    $ErrorMessage = $null

    try {
        $null = & secedit.exe /export /cfg $TempFile /areas USER_RIGHTS 2>&1
        if (Test-Path -LiteralPath $TempFile) {
            $Lines = Get-Content -LiteralPath $TempFile -ErrorAction Stop
            $InSection = $false
            foreach ($Line in $Lines) {
                if ($Line -match '^\[Privilege Rights\]') { $InSection = $true; continue }
                if ($InSection -and $Line -match '^\[') { break }
                if ($InSection -and $Line -match '^(Se\w+)\s*=\s*(.*)$') {
                    $RightName = $Matches[1]
                    $RawList = $Matches[2]
                    $SidList = @(
                        $RawList -split "," |
                        ForEach-Object { $_.Trim().TrimStart("*") } |
                        Where-Object { $_ }
                    )
                    $Rights[$RightName] = $SidList
                }
            }
            $Available = $true
        }
        else {
            $ErrorMessage = "secedit did not produce an export file."
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
    }
    finally {
        if (Test-Path -LiteralPath $TempFile) {
            Remove-Item -LiteralPath $TempFile -Force -ErrorAction SilentlyContinue
        }
    }

    [PSCustomObject]@{
        Available = $Available
        Error     = $ErrorMessage
        Rights    = $Rights
    }
}

function Get-LiveTokenPrivileges {
    <#
        Reads the *currently enabled/present* privileges of the PowerShell
        process's own token via a small P/Invoke helper (language-
        independent - LookupPrivilegeName returns the constant "SeXxx"
        name regardless of OS display language). Only reflects the account
        actually running this session.
    #>
    try {
        if (-not ("PrivilegeScan.TokenPrivilegeReader" -as [type])) {
            Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace PrivilegeScan {
    public class TokenPrivilegeReader {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref int cchName);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        const int TokenPrivileges = 3;
        const uint TOKEN_QUERY = 0x0008;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;

        public static List<string[]> GetCurrentProcessPrivileges() {
            var result = new List<string[]>();
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out hToken)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                int len = 0;
                GetTokenInformation(hToken, TokenPrivileges, IntPtr.Zero, 0, out len);
                IntPtr buffer = Marshal.AllocHGlobal(len);
                try {
                    if (!GetTokenInformation(hToken, TokenPrivileges, buffer, len, out len)) {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    }
                    int count = Marshal.ReadInt32(buffer);
                    IntPtr arrayStart = (IntPtr)((long)buffer + IntPtr.Size);
                    int itemSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                    for (int i = 0; i < count; i++) {
                        IntPtr itemPtr = (IntPtr)((long)arrayStart + i * itemSize);
                        LUID_AND_ATTRIBUTES la = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(itemPtr, typeof(LUID_AND_ATTRIBUTES));
                        LUID luid = la.Luid;
                        var sb = new System.Text.StringBuilder(256);
                        int nameLen = sb.Capacity;
                        string name = "(unknown)";
                        if (LookupPrivilegeName(null, ref luid, sb, ref nameLen)) {
                            name = sb.ToString();
                        }
                        bool enabled = (la.Attributes & SE_PRIVILEGE_ENABLED) != 0;
                        bool enabledByDefault = (la.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
                        result.Add(new string[] { name, enabled ? "Enabled" : "Disabled", enabledByDefault.ToString() });
                    }
                } finally {
                    Marshal.FreeHGlobal(buffer);
                }
            } finally {
                CloseHandle(hToken);
            }
            return result;
        }
    }
}
"@
        }

        $Raw = [PrivilegeScan.TokenPrivilegeReader]::GetCurrentProcessPrivileges()
        $Items = foreach ($Row in $Raw) {
            [PSCustomObject]@{ Name = $Row[0]; State = $Row[1]; EnabledByDefault = [bool]::Parse($Row[2]) }
        }
        return [PSCustomObject]@{ Available = $true; Reason = $null; Items = @($Items) }
    }
    catch {
        return [PSCustomObject]@{ Available = $false; Reason = $_.Exception.Message; Items = @() }
    }
}

###########################################################################
# Knowledge base: local groups + domain groups (well-known SIDs)
###########################################################################

function Get-WellKnownSidCatalog {
    <#
        SID-suffix-keyed catalog covering both:
          - BUILTIN local groups (S-1-5-32-nnn) - identical on every
            Windows computer and every domain's BUILTIN container, so this
            same table is used for both the local-machine scan and for
            matching domain tokenGroups against BUILTIN domain-local groups.
          - Domain-relative RIDs (matched against "<domain SID>-nnn").
        Keyed by the RID/suffix number; entries also carry which scope
        (Local, Domain, Both) they are meaningful for.
    #>
    return [ordered]@{
        544 = @{ Name = "Administrators"; Scope = "Both"; Severity = "critical"; Baseline = "Expected for a small, documented set of administrators only."
                 Risk = "Full local administrative control: install software/drivers, read any file, modify any account, disable security tooling, and impersonate any locally logged-on user."
                 Remediation = "Remove standard users from this group; use Just-In-Time / Just-Enough-Admin (LAPS, PAW, PIM) instead of standing membership." }
        545 = @{ Name = "Users"; Scope = "Both"; Severity = "info"; Baseline = "Expected for every standard account."
                 Risk = "No elevated risk - this is the standard, unprivileged baseline group."
                 Remediation = "No action needed." }
        546 = @{ Name = "Guests"; Scope = "Both"; Severity = "low"; Baseline = "Should normally be empty."
                 Risk = "Guest-level access; low individual risk but membership here is unusual and worth a quick sanity check."
                 Remediation = "Confirm this membership is intentional." }
        547 = @{ Name = "Power Users"; Scope = "Both"; Severity = "medium"; Baseline = "Legacy group, largely neutered since Windows Vista; still worth reviewing."
                 Risk = "Historically near-administrative; on modern Windows its practical power is much reduced, but membership is still unusual and worth confirming."
                 Remediation = "Confirm this membership is intentional; prefer Administrators/Users only." }
        548 = @{ Name = "Account Operators"; Scope = "Both"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Can create, modify and delete most non-administrative user, group and computer accounts in the domain, including resetting their passwords - a common lateral-movement/privilege-escalation stepping stone."
                 Remediation = "Remove unless this is a documented, monitored helpdesk-tier role." }
        549 = @{ Name = "Server Operators"; Scope = "Both"; Severity = "high"; Baseline = "Not expected for standard users; only meaningful on domain controllers."
                 Risk = "Can log on locally to domain controllers, manage services, and back up/restore files there - a path to full domain controller (and therefore domain) compromise."
                 Remediation = "Remove unless this is a documented, monitored DC-operations role." }
        550 = @{ Name = "Print Operators"; Scope = "Both"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Can manage printers domain-wide and, on domain controllers, load print drivers - print-driver loading is a known route to SYSTEM code execution on a DC."
                 Remediation = "Remove unless this is a documented, monitored print-management role." }
        551 = @{ Name = "Backup Operators"; Scope = "Both"; Severity = "critical"; Baseline = "Expected only for a dedicated backup service account."
                 Risk = "Can back up and restore any file while ignoring ACLs (including SAM/SYSTEM/NTDS.dit), and can log on locally/shut down the system - functionally equivalent to full administrative control."
                 Remediation = "Remove standard/admin users; restrict to the specific backup service account." }
        552 = @{ Name = "Replicator"; Scope = "Both"; Severity = "medium"; Baseline = "Legacy File Replication Service group; rarely used on modern systems."
                 Risk = "Historically used for file replication; unusual/legacy membership worth confirming."
                 Remediation = "Confirm this membership is intentional and still required." }
        554 = @{ Name = "Pre-Windows 2000 Compatible Access"; Scope = "Domain"; Severity = "medium"; Baseline = "Should normally contain only 'Authenticated Users' or be empty."
                 Risk = "Grants read access to many user/group attributes (including logon-related attributes) to its members; historically abused for anonymous-ish enumeration when it includes Everyone/Anonymous."
                 Remediation = "Confirm this group's own membership is limited to the domain default." }
        555 = @{ Name = "Remote Desktop Users"; Scope = "Both"; Severity = "medium"; Baseline = "Expected for accounts that legitimately RDP into this machine."
                 Risk = "Can log on via Remote Desktop - meaningful network-facing attack surface, especially on servers."
                 Remediation = "Confirm RDP access to this machine is expected for this identity." }
        556 = @{ Name = "Network Configuration Operators"; Scope = "Both"; Severity = "medium"; Baseline = "Not expected for standard users."
                 Risk = "Can modify TCP/IP configuration (including DNS servers), which can be abused to redirect or intercept traffic."
                 Remediation = "Remove unless this is a documented network-operations role." }
        557 = @{ Name = "Incoming Forest Trust Builders"; Scope = "Domain"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Can create one-way incoming forest trusts, affecting cross-forest authentication trust boundaries."
                 Remediation = "Remove unless this is a documented, rarely-used trust-management role." }
        558 = @{ Name = "Performance Monitor Users"; Scope = "Both"; Severity = "low"; Baseline = "Expected for monitoring/APM service accounts."
                 Risk = "Can view performance counter data remotely - low direct risk, minor information disclosure."
                 Remediation = "Confirm this maps to an expected monitoring account." }
        559 = @{ Name = "Performance Log Users"; Scope = "Both"; Severity = "low"; Baseline = "Expected for monitoring/APM service accounts."
                 Risk = "Can manage performance counters/logs remotely - low direct risk."
                 Remediation = "Confirm this maps to an expected monitoring account." }
        560 = @{ Name = "Windows Authorization Access Group"; Scope = "Domain"; Severity = "low"; Baseline = "Should normally contain only Enterprise Domain Controllers."
                 Risk = "Grants read access to the tokenGroupsGlobalAndUniversal attribute of users, relevant to claims-based authorization; unusual membership is worth a quick check."
                 Remediation = "Confirm this membership is intentional." }
        561 = @{ Name = "Terminal Server License Servers"; Scope = "Domain"; Severity = "low"; Baseline = "Expected only for RD Licensing server computer accounts."
                 Risk = "Low direct risk; unusual for a user account to hold this."
                 Remediation = "Confirm this membership is intentional." }
        562 = @{ Name = "Distributed COM Users"; Scope = "Both"; Severity = "medium"; Baseline = "Not expected for standard users."
                 Risk = "Can launch, activate and access DCOM objects remotely on this machine, which is relevant to several lateral-movement and coercion techniques."
                 Remediation = "Remove unless a specific DCOM-based application requires it." }
        568 = @{ Name = "IIS_IUSRS"; Scope = "Local"; Severity = "info"; Baseline = "Expected only for the IIS worker-process identities."
                 Risk = "No elevated risk for the built-in IIS identities; unusual for a real user account."
                 Remediation = "Confirm this is the built-in IIS identity, not a real user." }
        569 = @{ Name = "Cryptographic Operators"; Scope = "Both"; Severity = "medium"; Baseline = "Not expected for standard users."
                 Risk = "Can perform cryptographic operations (including changing FIPS/algorithm-policy-relevant settings on some roles)."
                 Remediation = "Remove unless a specific, documented workload requires it." }
        573 = @{ Name = "Event Log Readers"; Scope = "Both"; Severity = "low"; Baseline = "Expected for SIEM/monitoring service accounts."
                 Risk = "Can read the local event logs, including the Security log - low direct risk, information-disclosure potential (reconnaissance)."
                 Remediation = "Confirm this maps to an expected monitoring account." }
        574 = @{ Name = "Certificate Service DCOM Access"; Scope = "Both"; Severity = "medium"; Baseline = "Expected only for accounts that need to request certificates over DCOM."
                 Risk = "Grants DCOM access to Certificate Services; unusual membership is worth reviewing given the sensitivity of certificate issuance."
                 Remediation = "Confirm this is a documented certificate-enrollment integration." }
        578 = @{ Name = "Hyper-V Administrators"; Scope = "Both"; Severity = "high"; Baseline = "Expected only for virtualization administrators."
                 Risk = "Full control over Hyper-V and every virtual machine hosted here, including any credentials/data inside those VMs and potential host-level impact."
                 Remediation = "Remove unless this is a documented virtualization-administrator role." }
        579 = @{ Name = "Access Control Assistance Operators"; Scope = "Both"; Severity = "low"; Baseline = "Not expected for standard users."
                 Risk = "Can query effective-permissions information for other users/objects - low direct risk, minor reconnaissance value."
                 Remediation = "Confirm this maps to an expected helpdesk/support role." }
        580 = @{ Name = "Remote Management Users"; Scope = "Both"; Severity = "medium"; Baseline = "Expected for accounts that legitimately use WinRM/PowerShell Remoting to this machine."
                 Risk = "Can connect to this machine via WinRM/PowerShell Remoting - meaningful remote-code-execution-adjacent attack surface."
                 Remediation = "Confirm remote-management access to this machine is expected for this identity." }
        582 = @{ Name = "Storage Replica Administrators"; Scope = "Both"; Severity = "medium"; Baseline = "Expected only for storage-replication administrators."
                 Risk = "Can manage Storage Replica configuration; unusual for a general account."
                 Remediation = "Confirm this is a documented storage-administration role." }
        583 = @{ Name = "Device Owners"; Scope = "Local"; Severity = "medium"; Baseline = "Not expected for standard domain users."
                 Risk = "Grants elevated local device-configuration rights similar in spirit to Power Users."
                 Remediation = "Confirm this membership is intentional." }
        512 = @{ Name = "Domain Admins"; Scope = "Domain"; Severity = "critical"; Baseline = "Expected for a small, documented set of domain administrators only."
                 Risk = "Full administrative control over the entire domain, including every computer, account and Group Policy Object in it."
                 Remediation = "Remove from standard accounts; use tiered administration (separate admin accounts, PAWs, JIT elevation) instead of standing membership." }
        519 = @{ Name = "Enterprise Admins"; Scope = "Domain"; Severity = "critical"; Baseline = "Expected only for forest-level administrators, and typically empty day-to-day."
                 Risk = "Full administrative control over every domain in the entire forest."
                 Remediation = "Remove standing membership; only populate transiently for the specific forest-level change being made." }
        518 = @{ Name = "Schema Admins"; Scope = "Domain"; Severity = "critical"; Baseline = "Expected only during schema changes, and typically empty otherwise."
                 Risk = "Can modify the Active Directory schema forest-wide - a mistake or malicious change here can affect every domain in the forest."
                 Remediation = "Remove standing membership; only populate transiently for the specific schema change being made." }
        517 = @{ Name = "Cert Publishers"; Scope = "Domain"; Severity = "medium"; Baseline = "Expected only for Certificate Authority computer accounts."
                 Risk = "Can publish certificates and certificate revocation lists to Active Directory objects on behalf of a CA."
                 Remediation = "Confirm membership is limited to actual CA computer accounts." }
        520 = @{ Name = "Group Policy Creator Owners"; Scope = "Domain"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Can create new Group Policy Objects, which - once linked to an OU by someone with link rights, or if the creator is later granted link rights - can be used to push settings (including scripts) to every affected computer/user."
                 Remediation = "Remove unless this is a documented, monitored GPO-management role." }
        526 = @{ Name = "Key Admins"; Scope = "Domain"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Can manage the msDS-KeyCredentialLink attribute on accounts, which enables 'Shadow Credentials' style attacks - adding an alternate authentication key to take over an account without knowing/changing its password."
                 Remediation = "Remove unless this is a documented, monitored role." }
        527 = @{ Name = "Enterprise Key Admins"; Scope = "Domain"; Severity = "high"; Baseline = "Not expected for standard users."
                 Risk = "Same as Key Admins, but forest-wide - enables 'Shadow Credentials' style account takeover across the forest."
                 Remediation = "Remove unless this is a documented, monitored role." }
        525 = @{ Name = "Protected Users"; Scope = "Domain"; Severity = "secure"; Baseline = "A protective group, not a privilege."
                 Risk = "No risk - membership here restricts this account to stronger authentication (Kerberos-only, no NTLM/DES, no delegation, non-cacheable credentials, shorter ticket lifetimes). This is a positive, protective finding."
                 Remediation = "No action needed; consider adding other privileged accounts to this group if they are not already members." }
        553 = @{ Name = "RAS and IAS Servers"; Scope = "Domain"; Severity = "medium"; Baseline = "Expected only for RRAS/NPS server computer accounts."
                 Risk = "Members can read remote-access properties of user accounts (dial-in permissions); unusual for a user account to hold this."
                 Remediation = "Confirm this membership is intentional." }
        498 = @{ Name = "Enterprise Read-only Domain Controllers"; Scope = "Domain"; Severity = "info"; Baseline = "Computer-account group for RODCs."
                 Risk = "No elevated risk for a real user account; unusual to see here."
                 Remediation = "Confirm this membership is intentional." }
        516 = @{ Name = "Domain Controllers"; Scope = "Domain"; Severity = "info"; Baseline = "Computer-account group for domain controllers."
                 Risk = "No elevated risk for a real user account; unusual to see here."
                 Remediation = "Confirm this membership is intentional." }
    }
}

function Get-NameBasedPrivilegedGroupCatalog {
    <#
        Groups that are commonly privileged but do not have a fixed
        well-known RID (their SID varies per domain/installation), matched
        by name instead. Best-effort: only covers a handful of very common,
        widely-recognized cases.
    #>
    return [ordered]@{
        "dnsadmins" = @{ DisplayName = "DnsAdmins"; Severity = "high"
            Risk = "Historically allowed loading an arbitrary DLL into the DNS Server service running as SYSTEM on domain controllers (CVE-2021-40469 and related techniques) - a well-documented privilege-escalation path to domain controller compromise."
            Remediation = "Remove unless this is a documented, monitored DNS-management role; ensure domain controllers are patched." }
        "organization management" = @{ DisplayName = "Organization Management (Exchange)"; Severity = "high"
            Risk = "The top-level Exchange administrative role group; typically has extensive rights over Exchange configuration and, depending on version/patch level, historically over Active Directory itself."
            Remediation = "Remove unless this is a documented Exchange-administrator role." }
        "exchange windows permissions" = @{ DisplayName = "Exchange Windows Permissions"; Severity = "critical"
            Risk = "Historically granted WriteDacl on the domain object in many Exchange deployments (pre-mitigation), which is a well-known path to full domain compromise for anyone who can add members to this group or who is already a member."
            Remediation = "Verify the WriteDacl-on-domain-object issue is mitigated (see the AD Object Permissions tab for a direct check), and remove unnecessary membership." }
        "domain\gpo administrators" = @{ DisplayName = "GPO Administrators"; Severity = "high"
            Risk = "Custom/organization-defined Group Policy administration group; broad GPO edit rights can affect every computer/user in scope."
            Remediation = "Confirm this is a documented, monitored role." }
    }
}

function Get-UacFlagCatalog {
    return [ordered]@{
        64       = @{ Name = "PASSWD_NOTREQD"; Severity = "high"; Note = "Windows will accept a blank password for this account." }
        128      = @{ Name = "ENCRYPTED_TEXT_PWD_ALLOWED"; Severity = "critical"; Note = "The password is stored using reversible encryption - effectively plaintext-equivalent on the domain controller." }
        524288   = @{ Name = "TRUSTED_FOR_DELEGATION"; Severity = "critical"; Note = "Unconstrained delegation: any service this account authenticates to can capture and replay its full Kerberos TGT to impersonate it anywhere in the domain." }
        1048576  = @{ Name = "NOT_DELEGATED"; Severity = "secure"; Note = "This account's credentials cannot be delegated/forwarded by services (protective control)." }
        2097152  = @{ Name = "USE_DES_KEY_ONLY"; Severity = "high"; Note = "Restricted to the DES encryption type for Kerberos - a weak, legacy cipher." }
        4194304  = @{ Name = "DONT_REQUIRE_PREAUTH"; Severity = "high"; Note = "Kerberos pre-authentication is disabled - the account is AS-REP roastable (an offline-crackable hash can be requested with no credentials at all)." }
        262144   = @{ Name = "TRUSTED_TO_AUTH_FOR_DELEGATION"; Severity = "high"; Note = "Protocol-transition constrained delegation is enabled. Combined with configured delegation targets, this can impersonate arbitrary users to those services." }
        65536    = @{ Name = "DONT_EXPIRE_PASSWORD"; Severity = "low"; Note = "Password never expires. Normal for a dedicated service account; unusual/worth reviewing for a standard interactive user account." }
        8388608  = @{ Name = "SMARTCARD_REQUIRED"; Severity = "secure"; Note = "Interactive logon requires a smart card (protective control)." }
        2        = @{ Name = "ACCOUNTDISABLE"; Severity = "info"; Note = "Account is currently disabled." }
        32       = @{ Name = "LOCKOUT"; Severity = "info"; Note = "Account is currently locked out." }
    }
}

###########################################################################
# Local group inventory
###########################################################################

function Get-LocalGroupCatalog {
    <#
        Enumerates every local group and its members. Falls back to the
        WinNT ADSI provider per-group when Get-LocalGroupMember fails (a
        known limitation: it throws on a group containing even one
        orphaned/unresolvable member SID), so one bad entry never aborts
        enumeration of the rest of the machine.
    #>
    $Groups = New-Object System.Collections.Generic.List[object]

    try {
        $LocalGroups = @(Get-LocalGroup -ErrorAction Stop)
    }
    catch {
        $LocalGroups = @()
        try {
            $Computer = [ADSI]"WinNT://."
            $LocalGroups = @(
                $Computer.PSBase.Children |
                Where-Object { $_.SchemaClassName -eq "Group" } |
                ForEach-Object { [PSCustomObject]@{ Name = $_.Name[0]; SID = $null } }
            )
        }
        catch {
            Write-ScanLog -Level "WARN" -Message "Could not enumerate local groups: $($_.Exception.Message)"
        }
    }

    foreach ($Group in $LocalGroups) {
        $GroupName = $Group.Name
        $GroupSid = $null
        if ($Group.PSObject.Properties.Match("SID").Count -and $Group.SID) {
            $GroupSid = $Group.SID.Value
        }

        $Members = New-Object System.Collections.Generic.List[object]

        try {
            $RawMembers = @(Get-LocalGroupMember -Group $GroupName -ErrorAction Stop)
            foreach ($Member in $RawMembers) {
                $Members.Add([PSCustomObject]@{
                    Name   = $Member.Name
                    Sid    = $Member.SID.Value
                    Class  = [string]$Member.ObjectClass
                    Source = [string]$Member.PrincipalSource
                })
            }
        }
        catch {
            try {
                $GroupDe = [ADSI]"WinNT://./$GroupName,group"
                foreach ($MemberPath in $GroupDe.Invoke("Members")) {
                    try {
                        $MemberDe = New-Object System.DirectoryServices.DirectoryEntry($MemberPath)
                        $MemberSid = $null
                        try {
                            $SidBytes = $MemberDe.InvokeGet("objectSid")
                            $MemberSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$SidBytes), 0)).Value
                        }
                        catch {}
                        $Members.Add([PSCustomObject]@{
                            Name   = ($MemberDe.Path -replace "^WinNT://", "").Replace("/", "\")
                            Sid    = $MemberSid
                            Class  = [string]$MemberDe.SchemaClassName
                            Source = "Unknown"
                        })
                    }
                    catch {}
                }
            }
            catch {
                Write-ScanLog -Level "WARN" -Message "Could not enumerate members of local group '$GroupName': $($_.Exception.Message)"
            }
        }

        $Groups.Add([PSCustomObject]@{
            Name    = $GroupName
            Sid     = $GroupSid
            Members = @($Members)
        })
    }

    return @($Groups)
}

###########################################################################
# Active Directory ACL scanning
###########################################################################

function Get-AceRiskClassification {
    param (
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [Parameter(Mandatory)]
        [Guid]$ObjectType
    )

    $DcSyncGuids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c"
    )
    $ForceChangePasswordGuid = "00299570-246d-11d0-a768-00aa006e0529"
    $ObjectTypeString = $ObjectType.ToString().ToLowerInvariant()
    $ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
        return [PSCustomObject]@{
            Severity = "critical"; Label = "Full control (GenericAll)"
            Risk = "Grants complete control over this object: read/modify every attribute, change permissions, and even take ownership. Equivalent to owning the object outright."
            Remediation = "Remove this ACE unless full control is explicitly required and documented. Prefer narrowly-scoped delegated permissions over GenericAll."
        }
    }
    if (($DcSyncGuids -contains $ObjectTypeString) -and $Rights.HasFlag($ExtendedRight)) {
        return [PSCustomObject]@{
            Severity = "critical"; Label = "Directory replication rights (DCSync)"
            Risk = "Can request directory replication data from a domain controller, including password hashes for every account in the domain. This makes full domain compromise a single non-interactive read away, with no need to touch a domain controller interactively."
            Remediation = "Remove this extended right from any account/group that is not a domain controller or an explicitly-authorized replication/backup service account. Monitor Directory Service event 4662 for use of these rights."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) {
        return [PSCustomObject]@{
            Severity = "critical"; Label = "Modify permissions (WriteDacl)"
            Risk = "Can modify this object's own permissions at any time - including granting yourself full control - regardless of what access is granted today."
            Remediation = "Remove this ACE unless there is a documented delegation reason. Treat WriteDacl as equivalent to full control."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) {
        return [PSCustomObject]@{
            Severity = "critical"; Label = "Take ownership (WriteOwner)"
            Risk = "Can take ownership of this object; an object's owner can always grant themselves any permission on it, even with no explicit ACE present. Equivalent to full control."
            Remediation = "Remove this ACE unless explicitly required. Treat WriteOwner as equivalent to full control."
        }
    }
    if (($ObjectTypeString -eq $ForceChangePasswordGuid) -and $Rights.HasFlag($ExtendedRight)) {
        return [PSCustomObject]@{
            Severity = "high"; Label = "Reset password (User-Force-Change-Password)"
            Risk = "Can reset this account's password without knowing the current one - a common account-takeover primitive, especially against privileged accounts."
            Remediation = "Remove this right unless it is a documented helpdesk/self-service delegation, and ensure it is never granted on privileged accounts."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)) {
        return [PSCustomObject]@{
            Severity = "high"; Label = "Write most attributes (GenericWrite)"
            Risk = "Can modify most attributes of this object. On a computer object this can be used to configure Resource-Based Constrained Delegation and impersonate any user - including Domain Admins - against services on that machine. On a user/group object it can be used to change logon scripts or SPNs."
            Remediation = "Remove this ACE unless a specific, documented delegation requires it. Prefer delegating write access to individual attributes instead of GenericWrite."
        }
    }
    if (($ObjectTypeString -eq ([Guid]::Empty.ToString())) -and $Rights.HasFlag($ExtendedRight)) {
        return [PSCustomObject]@{
            Severity = "critical"; Label = "All extended rights"
            Risk = "Granted every extended right on this object, which includes directory-replication (DCSync-equivalent) and password-reset rights."
            Remediation = "Remove this ACE and replace it with the specific extended right actually required, if any."
        }
    }
    if ($Rights.HasFlag($ExtendedRight)) {
        return [PSCustomObject]@{
            Severity = "medium"; Label = "Specific extended right"
            Risk = "Granted a specific extended right on this object (see the object-type GUID in the evidence column). Impact depends on which right this is."
            Remediation = "Confirm this delegation is documented and still required."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) {
        return [PSCustomObject]@{
            Severity = "medium"; Label = "Write a specific property"
            Risk = "Can modify a specific attribute of this object (see evidence for the attribute GUID). Impact depends on which attribute this is."
            Remediation = "Confirm this delegation is documented and still required."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::Delete) -or $Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree)) {
        return [PSCustomObject]@{
            Severity = "high"; Label = "Delete object"
            Risk = "Can delete this object (or its entire subtree) - a destructive capability, even though this scan itself never deletes anything."
            Remediation = "Confirm this delegation is documented and still required."
        }
    }
    if ($Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -or $Rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::DeleteChild)) {
        return [PSCustomObject]@{
            Severity = "medium"; Label = "Create/delete child objects"
            Risk = "Can create or delete objects inside this container (for example user or computer objects), depending on which object classes are covered."
            Remediation = "Confirm this delegation is documented and still required."
        }
    }

    return $null
}

function Get-AclFindingsForObject {
    param (
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        $DomainContext,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$TargetSidSet,

        [Parameter(Mandatory)]
        [string]$ObjectLabel,

        [Parameter()]
        [string]$ObjectKind = "Object"
    )

    $Results = New-Object System.Collections.Generic.List[object]

    try {
        $Path = "LDAP://$($DomainContext.Server)/$DistinguishedName"
        $Entry = New-BoundDirectoryEntry -Path $Path -Credential $Credential
        $Sd = $Entry.ObjectSecurity

        try {
            $OwnerRef = $Sd.GetOwner([System.Security.Principal.SecurityIdentifier])
            if ($OwnerRef -and $TargetSidSet.Contains($OwnerRef.Value)) {
                $Results.Add([PSCustomObject]@{
                    ObjectLabel = $ObjectLabel; ObjectKind = $ObjectKind; Dn = $DistinguishedName
                    Right = "Owner"; Severity = "high"
                    Risk = "You (or a group you belong to) own this object. An object's owner can always grant themselves any permission on it, even with no explicit access rule present."
                    Remediation = "Confirm ownership is expected; if not, have an administrator take ownership back and re-apply the intended permissions."
                    Evidence = "Owner SID: $($OwnerRef.Value)"
                })
            }
        }
        catch {}

        $Rules = $Sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($Rule in $Rules) {
            if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $TrusteeSid = $Rule.IdentityReference.Value
            if (-not $TargetSidSet.Contains($TrusteeSid)) { continue }

            $Classification = Get-AceRiskClassification -Rights $Rule.ActiveDirectoryRights -ObjectType $Rule.ObjectType
            if (-not $Classification) { continue }

            $Results.Add([PSCustomObject]@{
                ObjectLabel = $ObjectLabel; ObjectKind = $ObjectKind; Dn = $DistinguishedName
                Right = $Classification.Label; Severity = $Classification.Severity
                Risk = $Classification.Risk; Remediation = $Classification.Remediation
                Evidence = "Trustee SID: $TrusteeSid; Rights: $($Rule.ActiveDirectoryRights); ObjectType GUID: $($Rule.ObjectType)"
            })
        }
    }
    catch {
        $Results.Add([PSCustomObject]@{
            ObjectLabel = $ObjectLabel; ObjectKind = $ObjectKind; Dn = $DistinguishedName
            Right = "(scan failed)"; Severity = "unknown"
            Risk = "Could not read the security descriptor for this object: $($_.Exception.Message)"
            Remediation = "Re-run with an account that has read access to this object, or investigate the connectivity/permission error."
            Evidence = $_.Exception.Message
        })
    }

    return @($Results)
}

function Get-GpoAclFindings {
    param (
        [Parameter(Mandatory)]
        $DomainContext,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$TargetSidSet,

        [Parameter(Mandatory)]
        [int]$MaxGpos
    )

    $Results = New-Object System.Collections.Generic.List[object]

    try {
        $GpoContainerDn = "CN=Policies,CN=System,$($DomainContext.DefaultNamingContext)"
        $SearchRootPath = "LDAP://$($DomainContext.Server)/$GpoContainerDn"
        $SearchRoot = New-BoundDirectoryEntry -Path $SearchRootPath -Credential $Credential
        $Searcher = New-BoundSearcher -SearchRoot $SearchRoot -Filter "(objectClass=groupPolicyContainer)" `
            -Properties @("displayName", "distinguishedName") -Scope OneLevel

        $All = $Searcher.FindAll()
        $Count = 0
        foreach ($Item in $All) {
            $Count++
            if ($Count -gt $MaxGpos) {
                Write-ScanLog -Level "WARN" -Message "GPO ACL scan stopped after $MaxGpos GPOs (raise -MaxGposToScanAcls to scan more)."
                break
            }
            $Dn = [string]$Item.Properties["distinguishedName"][0]
            $Name = if ($Item.Properties["displayName"].Count) { [string]$Item.Properties["displayName"][0] } else { $Dn }

            $Findings = Get-AclFindingsForObject -DistinguishedName $Dn -DomainContext $DomainContext -Credential $Credential `
                -TargetSidSet $TargetSidSet -ObjectLabel "GPO: $Name" -ObjectKind "GroupPolicyObject"

            foreach ($Finding in $Findings) {
                if ($Finding.Severity -eq "unknown") { continue }
                $Finding.Risk = $Finding.Risk + " If this GPO is linked to any OU, this lets you modify settings that apply to every computer/user in that scope - including deploying a startup/logon script for code execution."
                $Results.Add($Finding)
            }
        }
        $All.Dispose()
    }
    catch {
        $Results.Add([PSCustomObject]@{
            ObjectLabel = "GPO container"; ObjectKind = "GroupPolicyObject"; Dn = ""
            Right = "(scan failed)"; Severity = "unknown"
            Risk = "Could not enumerate Group Policy objects: $($_.Exception.Message)"
            Remediation = ""; Evidence = $_.Exception.Message
        })
    }

    return @($Results)
}

function Get-OuAclFindings {
    param (
        [Parameter(Mandatory)]
        $DomainContext,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$TargetSidSet,

        [Parameter(Mandatory)]
        [int]$MaxOus
    )

    $Results = New-Object System.Collections.Generic.List[object]

    try {
        $SearchRootPath = "LDAP://$($DomainContext.Server)/$($DomainContext.DefaultNamingContext)"
        $SearchRoot = New-BoundDirectoryEntry -Path $SearchRootPath -Credential $Credential
        $Searcher = New-BoundSearcher -SearchRoot $SearchRoot -Filter "(objectClass=organizationalUnit)" `
            -Properties @("distinguishedName", "ou") -Scope Subtree

        $All = $Searcher.FindAll()
        $Count = 0
        foreach ($Item in $All) {
            $Count++
            if ($Count -gt $MaxOus) {
                Write-ScanLog -Level "WARN" -Message "OU ACL scan stopped after $MaxOus OUs (raise -MaxOusToScanAcls to scan more)."
                break
            }
            if (($Count % 25) -eq 0) { Write-ScanLog "Scanning OU ACLs... ($Count so far)" }

            $Dn = [string]$Item.Properties["distinguishedName"][0]
            $Findings = Get-AclFindingsForObject -DistinguishedName $Dn -DomainContext $DomainContext -Credential $Credential `
                -TargetSidSet $TargetSidSet -ObjectLabel "OU: $Dn" -ObjectKind "OrganizationalUnit"

            foreach ($Finding in $Findings) {
                if ($Finding.Severity -eq "unknown") { continue }
                $Results.Add($Finding)
            }
        }
        $All.Dispose()
    }
    catch {
        $Results.Add([PSCustomObject]@{
            ObjectLabel = "OU sweep"; ObjectKind = "OrganizationalUnit"; Dn = ""
            Right = "(scan failed)"; Severity = "unknown"
            Risk = "Could not enumerate organizational units: $($_.Exception.Message)"
            Remediation = ""; Evidence = $_.Exception.Message
        })
    }

    return @($Results)
}

###########################################################################
# Finding builder
###########################################################################

$script:FindingIdCounter = 0

function New-Finding {
    param (
        [Parameter(Mandatory)] [string]$Scope,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Item,
        [Parameter()] [string]$Status = "",
        [Parameter(Mandatory)] [string]$Severity,
        [Parameter()] [string]$Baseline = "",
        [Parameter()] [string]$Risk = "",
        [Parameter()] [string]$Remediation = "",
        [Parameter()] [string]$Evidence = ""
    )

    $script:FindingIdCounter++

    [PSCustomObject]@{
        id          = $script:FindingIdCounter
        scope       = $Scope
        category    = $Category
        item        = $Item
        status      = $Status
        severity    = $Severity
        baseline    = $Baseline
        risk        = $Risk
        remediation = $Remediation
        evidence    = $Evidence
    }
}

###########################################################################
# MAIN
###########################################################################

$SeverityRank = @{ critical = 0; high = 1; medium = 2; low = 3; info = 4; secure = 5; unknown = 6 }

Write-Host ""
Write-Host "=" * 78 -ForegroundColor Cyan
Write-Host "  PRIVILEGE & PERMISSIONS SCAN - domain-joined computer" -ForegroundColor Cyan
Write-Host "=" * 78 -ForegroundColor Cyan
Write-Host ""

#--------------------------------------------------------------------------
# Resolve output path (with a safe fallback if C:\temp is not writable)
#--------------------------------------------------------------------------

if (-not $OutputPath) {
    $DefaultRoot = Join-Path $env:SystemDrive "temp"
    $OutputPath = Join-Path $DefaultRoot ("Privilege-Scan-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop
    }
}
catch {
    $FallbackRoot = Join-Path $env:USERPROFILE ("Documents\Privilege-Scan-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    Write-ScanLog -Level "WARN" -Message "Could not create '$OutputPath' ($($_.Exception.Message)); falling back to '$FallbackRoot'."
    $OutputPath = $FallbackRoot
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
}

$CsvDirectory = Join-Path $OutputPath "CSV"
$null = New-Item -Path $CsvDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue

$TranscriptPath = Join-Path $OutputPath "PowerShell-Transcript.txt"
Start-Transcript -Path $TranscriptPath -Force | Out-Null

$Findings = New-Object System.Collections.Generic.List[object]
$Gaps = New-Object System.Collections.Generic.List[object]

try {
    Write-ScanLog "Output folder: $OutputPath"

    #-----------------------------------------------------------------
    # Elevation / domain-joined status
    #-----------------------------------------------------------------

    $CurrentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $IsElevated = $CurrentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-ScanLog "Elevated session: $IsElevated"

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $IsDomainJoined = [bool]$ComputerSystem.PartOfDomain
    Write-ScanLog "Domain-joined: $IsDomainJoined"

    #-----------------------------------------------------------------
    # Credential handling
    #-----------------------------------------------------------------

    $CurrentSessionIdentity = "$env:USERDOMAIN\$env:USERNAME"

    if (-not $PSBoundParameters.ContainsKey("Credential") -and -not $NoCredentialPrompt) {
        Write-ScanLog "Prompting for domain credentials (Cancel or leave the username blank to scan your current identity: $CurrentSessionIdentity)."
        $Credential = Get-Credential -Message "Domain credentials to scan (Cancel/blank username = use current logged-on identity: $CurrentSessionIdentity)" -UserName $CurrentSessionIdentity
    }

    $UseExplicitCredential = $false
    if ($Credential -and -not [string]::IsNullOrWhiteSpace($Credential.UserName) -and ($Credential.UserName -ne $CurrentSessionIdentity)) {
        $UseExplicitCredential = $true
    }
    elseif ($Credential -and -not [string]::IsNullOrWhiteSpace($Credential.UserName) -and $Credential.Password.Length -gt 0) {
        # Same username re-typed with a password - still treat as explicit so
        # the supplied password is actually used to bind (proves the account
        # can authenticate), rather than silently falling back to SSO.
        $UseExplicitCredential = $true
    }

    if ($UseExplicitCredential) {
        $TargetIdentityDisplay = $Credential.UserName
        Write-ScanLog "Scanning explicitly-supplied identity: $TargetIdentityDisplay"
    }
    else {
        $TargetIdentityDisplay = "$CurrentSessionIdentity (current logged-on session)"
        Write-ScanLog "Scanning current logged-on identity: $CurrentSessionIdentity"
    }

    $BareAccountName = if ($UseExplicitCredential) { Get-BareAccountName -Name $Credential.UserName } else { $env:USERNAME }

    #-----------------------------------------------------------------
    # Domain context + target account resolution
    #-----------------------------------------------------------------

    $DomainAvailable = $false
    $DomainContext = $null
    $TargetAccount = $null
    $TokenGroupSids = @()
    $TargetSidSet = New-Object System.Collections.Generic.HashSet[string]

    if (-not $IsDomainJoined) {
        $Gaps.Add([PSCustomObject]@{ Area = "Domain sections"; Reason = "This computer does not appear to be domain-joined; only local-machine sections were evaluated." })
        Write-ScanLog -Level "WARN" -Message "Computer is not domain-joined - skipping all domain-scope checks."
    }
    else {
        try {
            $DomainContext = Get-DomainContext -DomainController $DomainController -Credential $Credential
            Write-ScanLog "Domain contacted: $($DomainContext.DomainDnsName) via $($DomainContext.Server)"
            $DomainAvailable = $true
        }
        catch {
            $Gaps.Add([PSCustomObject]@{ Area = "Domain sections"; Reason = "Could not contact the domain ($($_.Exception.Message)); check connectivity, DNS and the supplied credentials." })
            Write-ScanLog -Level "ERROR" -Message "Could not contact the domain: $($_.Exception.Message)"
        }
    }

    if ($DomainAvailable) {
        try {
            $TargetAccount = Find-AdTargetAccount -SamAccountName $BareAccountName -DomainContext $DomainContext -Credential $Credential
            if (-not $TargetAccount) {
                $Gaps.Add([PSCustomObject]@{ Area = "Domain sections"; Reason = "Account '$BareAccountName' could not be found in Active Directory (bind succeeded, so credentials/connectivity are fine - the account itself was not found)." })
                Write-ScanLog -Level "WARN" -Message "Could not find AD account '$BareAccountName'."
            }
            else {
                Write-ScanLog "Resolved target account: $($TargetAccount.DistinguishedName)"
                $TokenGroupSids = @(Get-TokenGroupSids -DistinguishedName $TargetAccount.DistinguishedName -DomainContext $DomainContext -Credential $Credential)
                Write-ScanLog "Resolved $($TokenGroupSids.Count) effective domain group SID(s) via tokenGroups."

                [void]$TargetSidSet.Add($TargetAccount.ObjectSid)
                foreach ($Sid in $TokenGroupSids) { [void]$TargetSidSet.Add($Sid) }
                [void]$TargetSidSet.Add("S-1-1-0")   # Everyone
                [void]$TargetSidSet.Add("S-1-5-11")  # Authenticated Users
            }
        }
        catch {
            $Gaps.Add([PSCustomObject]@{ Area = "Domain sections"; Reason = "Failed to resolve the target account or its group membership: $($_.Exception.Message)" })
            Write-ScanLog -Level "ERROR" -Message "Failed to resolve target account: $($_.Exception.Message)"
        }
    }

    #-----------------------------------------------------------------
    # Local-only fallback SID set (no domain contact, or domain contact
    # failed): use the current session's own Windows token, which already
    # includes resolved domain group SIDs if this really is a domain logon.
    # Only meaningful when scanning the current identity.
    #-----------------------------------------------------------------

    if ($TargetSidSet.Count -eq 0 -and -not $UseExplicitCredential) {
        try {
            $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            [void]$TargetSidSet.Add($WindowsIdentity.User.Value)
            foreach ($Group in $WindowsIdentity.Groups) {
                [void]$TargetSidSet.Add($Group.Value)
            }
            Write-ScanLog "Domain lookup unavailable - using the current Windows logon token's SID set instead ($($TargetSidSet.Count) SIDs)."
        }
        catch {
            Write-ScanLog -Level "WARN" -Message "Could not read the current Windows logon token either: $($_.Exception.Message)"
        }
    }

    #-----------------------------------------------------------------
    # Domain group membership findings
    #-----------------------------------------------------------------

    $DomainGroupFindings = New-Object System.Collections.Generic.List[object]

    if ($DomainAvailable -and $TargetAccount) {
        $WellKnownCatalog = Get-WellKnownSidCatalog
        $NameCatalog = Get-NameBasedPrivilegedGroupCatalog
        $DomainSidPrefix = $TargetAccount.ObjectSid.Substring(0, $TargetAccount.ObjectSid.LastIndexOf("-"))

        $MatchedRids = New-Object System.Collections.Generic.HashSet[int]
        $UnmatchedSids = New-Object System.Collections.Generic.List[string]

        foreach ($Sid in $TokenGroupSids) {
            $Matched = $false
            foreach ($Rid in $WellKnownCatalog.Keys) {
                $CandidateSid = "S-1-5-32-$Rid"
                $CandidateDomainSid = "$DomainSidPrefix-$Rid"
                if ($Sid -eq $CandidateSid -or $Sid -eq $CandidateDomainSid) {
                    $Info = $WellKnownCatalog[$Rid]
                    $Finding = New-Finding -Scope "Domain" -Category "Privileged Group Membership" -Item $Info.Name -Status "Member" `
                        -Severity $Info.Severity -Baseline $Info.Baseline -Risk $Info.Risk -Remediation $Info.Remediation -Evidence "SID: $Sid"
                    $Findings.Add($Finding)
                    $DomainGroupFindings.Add($Finding)
                    $Matched = $true
                    break
                }
            }
            if (-not $Matched) { $UnmatchedSids.Add($Sid) }
        }

        # Name-based heuristic catalog, only for SIDs not already matched by
        # well-known RID. Resolving names is best-effort; failures are simply
        # skipped (not every unmatched SID needs a name-based check).
        foreach ($Sid in $UnmatchedSids) {
            $DisplayName = Resolve-SidDisplayName -Sid $Sid
            $BareName = (Get-BareAccountName -Name $DisplayName).ToLowerInvariant()
            if ($NameCatalog.Contains($BareName)) {
                $Info = $NameCatalog[$BareName]
                $Finding = New-Finding -Scope "Domain" -Category "Privileged Group Membership" -Item $Info.DisplayName -Status "Member" `
                    -Severity $Info.Severity -Baseline "Not a well-known SID; matched by name." -Risk $Info.Risk -Remediation $Info.Remediation -Evidence "SID: $Sid; resolved name: $DisplayName"
                $Findings.Add($Finding)
                $DomainGroupFindings.Add($Finding)
            }
        }

        if ($DomainGroupFindings.Count -eq 0) {
            $Finding = New-Finding -Scope "Domain" -Category "Privileged Group Membership" -Item "No privileged group membership detected" -Status "" `
                -Severity "secure" -Baseline "Expected for a standard user account." -Risk "No risk - no well-known privileged group membership was found for this account." -Remediation "No action needed."
            $Findings.Add($Finding)
        }
    }

    #-----------------------------------------------------------------
    # Account configuration findings (UAC flags, AdminCount, delegation, SPNs)
    #-----------------------------------------------------------------

    if ($DomainAvailable -and $TargetAccount) {
        $UacCatalog = Get-UacFlagCatalog
        foreach ($Bit in $UacCatalog.Keys) {
            if (($TargetAccount.UserAccountControl -band $Bit) -eq $Bit) {
                $Info = $UacCatalog[$Bit]
                if ($Info.Severity -in @("info")) { continue }
                $Findings.Add((New-Finding -Scope "Domain" -Category "Account Configuration" -Item $Info.Name -Status "Set" `
                    -Severity $Info.Severity -Risk $Info.Note -Remediation "Review whether this flag is required; remove it if not." `
                    -Evidence "userAccountControl = $($TargetAccount.UserAccountControl)"))
            }
        }

        if ($TargetAccount.AdminCount -eq 1 -and $DomainGroupFindings.Count -eq 0) {
            $Findings.Add((New-Finding -Scope "Domain" -Category "Account Configuration" -Item "Stale adminCount=1 (orphaned admin flag)" -Status "adminCount = 1" `
                -Severity "medium" -Baseline "Should normally match current privileged-group membership." `
                -Risk "This account was protected by AdminSDHolder at some point (adminCount=1) but no current privileged group membership was detected. SDProp does not automatically clear this flag or the restrictive ACL it applies, which can leave a stale, non-inheriting permission set on an account that should no longer be privileged." `
                -Remediation "If the account is genuinely no longer privileged, reset adminCount to 0 and re-enable ACL inheritance on the object." -Evidence "adminCount attribute = 1"))
        }

        if ($TargetAccount.ServicePrincipalNames.Count -gt 0) {
            $IsPrivileged = $DomainGroupFindings.Count -gt 0
            $Severity = if ($IsPrivileged) { "high" } else { "medium" }
            $Findings.Add((New-Finding -Scope "Domain" -Category "Kerberos" -Item "Service Principal Name(s) set (Kerberoastable)" -Status "$($TargetAccount.ServicePrincipalNames.Count) SPN(s)" `
                -Severity $Severity -Baseline "Expected for dedicated service accounts; unusual for a normal interactive user account." `
                -Risk "Any authenticated domain user can request a Kerberos service ticket for this account and attempt to crack its password hash offline (Kerberoasting), with no logon or elevated access required." `
                -Remediation "Use a group-managed service account (gMSA) where possible, or ensure a long random password and AES-only Kerberos encryption if an SPN must remain on a normal account." `
                -Evidence ($TargetAccount.ServicePrincipalNames -join "; ")))
        }

        if ($TargetAccount.AllowedToDelegateTo.Count -gt 0) {
            $ProtocolTransition = (($TargetAccount.UserAccountControl -band 262144) -eq 262144)
            $Severity = if ($ProtocolTransition) { "high" } else { "medium" }
            $Findings.Add((New-Finding -Scope "Domain" -Category "Delegation" -Item "Constrained delegation configured" -Status "$($TargetAccount.AllowedToDelegateTo.Count) target(s)" `
                -Severity $Severity -Baseline "Expected only for specific application/service accounts with a documented delegation need." `
                -Risk "This account can obtain Kerberos service tickets to the listed services on behalf of other users. $(if ($ProtocolTransition) { 'Protocol transition is enabled, so this can be triggered even without an initial Kerberos ticket from the impersonated user, widening the abuse window.' } else { 'Requires the impersonated user to have already authenticated to this account with Kerberos.' })" `
                -Remediation "Confirm every listed target service is still required; remove unused entries. Prefer resource-based constrained delegation configured on the target instead where possible." `
                -Evidence ($TargetAccount.AllowedToDelegateTo -join "; ")))
        }
    }

    #-----------------------------------------------------------------
    # AD object permission (ACL) findings
    #-----------------------------------------------------------------

    $AclFindings = New-Object System.Collections.Generic.List[object]

    if ($DomainAvailable -and $TargetAccount -and $TargetSidSet.Count -gt 0) {
        Write-ScanLog "Scanning AD object permissions (domain root, AdminSDHolder, GPOs, own objects)..."

        $ObjectsToScan = New-Object System.Collections.Generic.List[object]
        $ObjectsToScan.Add(@{ Dn = $DomainContext.DefaultNamingContext; Label = "Domain root"; Kind = "DomainRoot" })
        $ObjectsToScan.Add(@{ Dn = "CN=AdminSDHolder,CN=System,$($DomainContext.DefaultNamingContext)"; Label = "AdminSDHolder"; Kind = "AdminSDHolder" })
        $ObjectsToScan.Add(@{ Dn = $TargetAccount.DistinguishedName; Label = "Own user object ($($TargetAccount.SamAccountName))"; Kind = "OwnUser" })

        try {
            $ComputerAccount = Find-AdTargetAccount -SamAccountName "$($ComputerSystem.Name)$" -DomainContext $DomainContext -Credential $Credential -ErrorAction SilentlyContinue
        }
        catch { $ComputerAccount = $null }
        if ($ComputerAccount) {
            $ObjectsToScan.Add(@{ Dn = $ComputerAccount.DistinguishedName; Label = "Own computer object ($($ComputerSystem.Name))"; Kind = "OwnComputer" })
        }

        foreach ($ObjectSpec in $ObjectsToScan) {
            $Results = Get-AclFindingsForObject -DistinguishedName $ObjectSpec.Dn -DomainContext $DomainContext -Credential $Credential `
                -TargetSidSet $TargetSidSet -ObjectLabel $ObjectSpec.Label -ObjectKind $ObjectSpec.Kind

            foreach ($Result in $Results) {
                if ($Result.Severity -eq "unknown") {
                    $Gaps.Add([PSCustomObject]@{ Area = "AD Object Permissions: $($ObjectSpec.Label)"; Reason = $Result.Risk })
                    continue
                }
                if ($ObjectSpec.Kind -eq "AdminSDHolder") {
                    $Result.Risk = $Result.Risk + " This is the AdminSDHolder template object - any right here propagates to, and persists on, every current and future protected (privileged) account/group roughly every 60 minutes via SDProp, making it a powerful persistence/backdoor mechanism."
                }
                $AclFindings.Add($Result)
            }
        }

        $GpoFindings = Get-GpoAclFindings -DomainContext $DomainContext -Credential $Credential -TargetSidSet $TargetSidSet -MaxGpos $MaxGposToScanAcls
        foreach ($GpoFinding in $GpoFindings) {
            if ($GpoFinding.Severity -eq "unknown") {
                $Gaps.Add([PSCustomObject]@{ Area = "AD Object Permissions: GPO container"; Reason = $GpoFinding.Risk })
                continue
            }
            $AclFindings.Add($GpoFinding)
        }

        if ($ScanOuAcls) {
            Write-ScanLog "Sweeping OU permissions (this can take a while in large domains)..."
            $OuFindings = Get-OuAclFindings -DomainContext $DomainContext -Credential $Credential -TargetSidSet $TargetSidSet -MaxOus $MaxOusToScanAcls
            foreach ($OuFinding in $OuFindings) {
                if ($OuFinding.Severity -eq "unknown") {
                    $Gaps.Add([PSCustomObject]@{ Area = "AD Object Permissions: OU sweep"; Reason = $OuFinding.Risk })
                    continue
                }
                $AclFindings.Add($OuFinding)
            }
        }
        else {
            $Gaps.Add([PSCustomObject]@{ Area = "AD Object Permissions: OU sweep"; Reason = "Skipped by default for speed. Re-run with -ScanOuAcls to sweep every OU's ACL for dangerous rights held by this identity." })
        }

        foreach ($AclFinding in $AclFindings) {
            $Findings.Add((New-Finding -Scope "Domain" -Category "AD Object Permissions" -Item "$($AclFinding.ObjectLabel) - $($AclFinding.Right)" -Status $AclFinding.Right `
                -Severity $AclFinding.Severity -Risk $AclFinding.Risk -Remediation $AclFinding.Remediation -Evidence $AclFinding.Evidence))
        }

        if ($AclFindings.Count -eq 0) {
            $Findings.Add((New-Finding -Scope "Domain" -Category "AD Object Permissions" -Item "No dangerous AD permissions detected on scanned objects" -Status "" `
                -Severity "secure" -Risk "No risk - no GenericAll/GenericWrite/WriteDacl/WriteOwner/DCSync/password-reset rights were found for this identity on the domain root, AdminSDHolder, its own objects, or scanned GPOs." -Remediation "No action needed."))
        }

        $AclFindings.ToArray() | Export-Csv -Path (Join-Path $CsvDirectory "AD-Object-Permissions.csv") -NoTypeInformation -Encoding UTF8
    }
    else {
        $Gaps.Add([PSCustomObject]@{ Area = "AD Object Permissions"; Reason = "Skipped - domain contact or target account resolution did not succeed." })
    }

    #-----------------------------------------------------------------
    # Local group membership findings
    #-----------------------------------------------------------------

    Write-ScanLog "Enumerating local groups..."
    $LocalGroupInventory = @(Get-LocalGroupCatalog)
    $LocalGroupFindingRows = New-Object System.Collections.Generic.List[object]
    $LocalAdministratorsMembers = @()

    if ($TargetSidSet.Count -gt 0) {
        $WellKnownCatalog = Get-WellKnownSidCatalog

        foreach ($Group in $LocalGroupInventory) {
            $MatchedMember = $null
            foreach ($Member in $Group.Members) {
                if ($Member.Sid -and $TargetSidSet.Contains($Member.Sid)) { $MatchedMember = $Member; break }
            }

            if ($Group.Name -match '^Administrators$') {
                $LocalAdministratorsMembers = @($Group.Members)
            }

            if (-not $MatchedMember) { continue }

            $Info = $null
            if ($Group.Sid) {
                $Rid = [int]($Group.Sid.Substring($Group.Sid.LastIndexOf("-") + 1))
                if ($WellKnownCatalog.Contains($Rid)) { $Info = $WellKnownCatalog[$Rid] }
            }
            if (-not $Info) {
                $Info = @{ Severity = "medium"; Baseline = "Custom (non-built-in) local group."
                    Risk = "This is a custom local group, so its practical impact depends on how it is used (for example in local NTFS/share/service ACLs on this machine)."
                    Remediation = "Review what access this custom group actually grants on this machine and confirm it is expected." }
            }

            $Via = if ($MatchedMember.Sid -eq $TargetAccount.ObjectSid) { "Direct" } elseif ($TargetAccount -and $MatchedMember.Sid -eq $TargetAccount.ObjectSid) { "Direct" } else { "Via domain group: $(Resolve-SidDisplayName -Sid $MatchedMember.Sid)" }
            if (-not $TargetAccount) { $Via = "Direct (local identity match)" }

            $Finding = New-Finding -Scope "Local" -Category "Local Group Membership" -Item $Group.Name -Status "Member" `
                -Severity $Info.Severity -Baseline $Info.Baseline -Risk $Info.Risk -Remediation $Info.Remediation -Evidence "$Via; group SID: $($Group.Sid)"
            $Findings.Add($Finding)
            $LocalGroupFindingRows.Add($Finding)
        }

        if ($LocalGroupFindingRows.Count -eq 0) {
            $Findings.Add((New-Finding -Scope "Local" -Category "Local Group Membership" -Item "No notable local group membership detected" -Status "" `
                -Severity "secure" -Risk "No risk - this identity was not found in any enumerated local group (beyond the implicit Users/Everyone/Authenticated Users baseline)." -Remediation "No action needed."))
        }
    }
    else {
        $Gaps.Add([PSCustomObject]@{ Area = "Local Group Membership"; Reason = "Could not determine a SID set to match against local groups (domain lookup unavailable and no local logon token to fall back on)." })
    }

    $LocalGroupCsvRows = foreach ($Group in $LocalGroupInventory) {
        foreach ($Member in $Group.Members) {
            [PSCustomObject]@{ Group = $Group.Name; GroupSid = $Group.Sid; MemberName = $Member.Name; MemberSid = $Member.Sid; MemberClass = $Member.Class; Source = $Member.Source }
        }
    }
    @($LocalGroupCsvRows) | Export-Csv -Path (Join-Path $CsvDirectory "Local-Group-Membership.csv") -NoTypeInformation -Encoding UTF8

    #-----------------------------------------------------------------
    # Local User Rights Assignment
    #-----------------------------------------------------------------

    Write-ScanLog "Reading local User Rights Assignment policy (secedit)..."
    $UserRightsResult = Get-UserRightsAssignment
    $UserRightsRows = New-Object System.Collections.Generic.List[object]

    if (-not $UserRightsResult.Available) {
        $Gaps.Add([PSCustomObject]@{ Area = "User Rights Assignment"; Reason = "Could not read the local security policy via secedit: $($UserRightsResult.Error). $(if (-not $IsElevated) { 'Re-run this script elevated for full coverage.' })" })
        $Findings.Add((New-Finding -Scope "Local" -Category "User Rights Assignment" -Item "User Rights Assignment could not be read" -Status "" `
            -Severity "unknown" -Risk "The local security policy could not be exported, so User Rights Assignment could not be evaluated for this identity." `
            -Remediation "Re-run this script from an elevated PowerShell session." -Evidence $UserRightsResult.Error))
    }
    elseif ($TargetSidSet.Count -eq 0) {
        $Gaps.Add([PSCustomObject]@{ Area = "User Rights Assignment"; Reason = "Local security policy was read, but no SID set was available to match it against." })
    }
    else {
        $PrivilegeCatalog = Get-DangerousPrivilegeCatalog
        foreach ($RightName in $UserRightsResult.Rights.Keys) {
            $SidsForRight = @($UserRightsResult.Rights[$RightName])
            $MatchedSid = $SidsForRight | Where-Object { $TargetSidSet.Contains($_) } | Select-Object -First 1
            $Granted = [bool]$MatchedSid

            $Info = if ($PrivilegeCatalog.Contains($RightName)) { $PrivilegeCatalog[$RightName] } else {
                @{ Severity = "unknown"; Baseline = ""; Risk = "Unrecognized right name - not in this script's catalog."; Remediation = "Review manually." }
            }

            $Row = [PSCustomObject]@{
                Right       = $RightName
                Granted     = $Granted
                GrantedVia  = if ($Granted) { Resolve-SidDisplayName -Sid $MatchedSid } else { "" }
                Severity    = $Info.Severity
                Baseline    = $Info.Baseline
                Risk        = $Info.Risk
                Remediation = $Info.Remediation
            }
            $UserRightsRows.Add($Row)

            if ($Granted -and $Info.Severity -notin @("info", "secure")) {
                $Findings.Add((New-Finding -Scope "Local" -Category "User Rights Assignment" -Item $RightName -Status "Granted" `
                    -Severity $Info.Severity -Baseline $Info.Baseline -Risk $Info.Risk -Remediation $Info.Remediation -Evidence "Granted via: $($Row.GrantedVia)"))
            }
        }

        @($UserRightsRows) | Export-Csv -Path (Join-Path $CsvDirectory "User-Rights-Assignment.csv") -NoTypeInformation -Encoding UTF8
    }

    #-----------------------------------------------------------------
    # Live token privileges (current session only)
    #-----------------------------------------------------------------

    $LivePrivileges = [PSCustomObject]@{ Available = $false; Reason = "Not applicable: scanning a supplied credential, not the current logged-on session."; Items = @() }

    if (-not $UseExplicitCredential) {
        Write-ScanLog "Reading live token privileges of the current PowerShell session..."
        $LivePrivileges = Get-LiveTokenPrivileges
        if (-not $LivePrivileges.Available) {
            $Gaps.Add([PSCustomObject]@{ Area = "Local machine - live session"; Reason = "Could not read the current process token's privileges: $($LivePrivileges.Reason)" })
        }
    }
    else {
        $Gaps.Add([PSCustomObject]@{ Area = "Local machine - live session"; Reason = "Skipped: live, currently-enabled token privileges can only be read for the account actually running this session, not for a different supplied credential." })
    }

    #-----------------------------------------------------------------
    # Summary
    #-----------------------------------------------------------------

    $SeverityCounts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0; secure = 0; unknown = 0 }
    foreach ($Finding in $Findings) {
        if ($SeverityCounts.Contains($Finding.severity)) { $SeverityCounts[$Finding.severity]++ }
    }

    $OverallSeverity = "secure"
    foreach ($Key in @("critical", "high", "medium", "low")) {
        if ($SeverityCounts[$Key] -gt 0) { $OverallSeverity = $Key; break }
    }
    $OverallLabel = switch ($OverallSeverity) {
        "critical" { "Critical privilege issues found" }
        "high"     { "High-risk privilege issues found" }
        "medium"   { "Some elevated privileges to review" }
        "low"      { "Only minor items to review" }
        default    { "No elevated privileges found beyond baseline" }
    }

    Write-ScanLog "Scan complete. Findings by severity: $(($SeverityCounts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')"

    #-----------------------------------------------------------------
    # CSV exports
    #-----------------------------------------------------------------

    $Findings.ToArray() | Export-Csv -Path (Join-Path $CsvDirectory "All-Findings.csv") -NoTypeInformation -Encoding UTF8
    @($Gaps) | Export-Csv -Path (Join-Path $CsvDirectory "Evidence-Gaps.csv") -NoTypeInformation -Encoding UTF8

    #-----------------------------------------------------------------
    # Build dashboard JSON
    #-----------------------------------------------------------------

    $IdentityData = if ($TargetAccount) {
        $UacFlags = New-Object System.Collections.Generic.List[object]
        $UacCatalog = Get-UacFlagCatalog
        foreach ($Bit in $UacCatalog.Keys) {
            $Present = (($TargetAccount.UserAccountControl -band $Bit) -eq $Bit)
            $Info = $UacCatalog[$Bit]
            $UacFlags.Add([PSCustomObject]@{ name = $Info.Name; present = $Present; severity = $Info.Severity; note = $Info.Note })
        }

        [PSCustomObject]@{
            samAccountName = $TargetAccount.SamAccountName
            dn             = $TargetAccount.DistinguishedName
            upn            = $TargetAccount.UserPrincipalName
            displayName    = $TargetAccount.DisplayName
            sid            = $TargetAccount.ObjectSid
            whenCreated    = if ($TargetAccount.WhenCreated) { [string]$TargetAccount.WhenCreated } else { $null }
            pwdLastSet     = if ($TargetAccount.PwdLastSet) { [string]$TargetAccount.PwdLastSet } else { "Never / must change at next logon" }
            adminCount     = $TargetAccount.AdminCount
            spns           = @($TargetAccount.ServicePrincipalNames)
            delegateTo     = @($TargetAccount.AllowedToDelegateTo)
            uacValue       = $TargetAccount.UserAccountControl
            uacFlags       = @($UacFlags.ToArray())
        }
    } else { $null }

    $DashboardData = [PSCustomObject]@{
        generatedAt   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
        computerName  = $env:COMPUTERNAME
        domainJoined  = $IsDomainJoined
        domain        = if ($DomainContext) { $DomainContext.DomainDnsName } else { $null }
        domainController = if ($DomainContext) { $DomainContext.Server } else { $null }
        scan = [PSCustomObject]@{
            identityDisplay        = $TargetIdentityDisplay
            usedExplicitCredential = $UseExplicitCredential
            currentSessionIdentity = $CurrentSessionIdentity
            elevated                = $IsElevated
            domainAvailable         = $DomainAvailable
            outputFolder            = $OutputPath
            scannedOuAcls           = [bool]$ScanOuAcls
        }
        summary = [PSCustomObject]@{
            critical = $SeverityCounts["critical"]; high = $SeverityCounts["high"]; medium = $SeverityCounts["medium"]
            low = $SeverityCounts["low"]; info = $SeverityCounts["info"]; secure = $SeverityCounts["secure"]; unknown = $SeverityCounts["unknown"]
            gaps = $Gaps.Count
            overallSeverity = $OverallSeverity
            overallLabel    = $OverallLabel
        }
        identity      = $IdentityData
        localGroups   = @(
            $LocalGroupInventory | ForEach-Object {
                [PSCustomObject]@{
                    name = $_.Name; sid = $_.Sid
                    members = @($_.Members | ForEach-Object { [PSCustomObject]@{ name = $_.Name; sid = $_.Sid; class = $_.Class; source = $_.Source } })
                }
            }
        )
        localAdministrators = @($LocalAdministratorsMembers | ForEach-Object { [PSCustomObject]@{ name = $_.Name; sid = $_.Sid; class = $_.Class; source = $_.Source } })
        userRights    = @($UserRightsRows)
        livePrivileges = [PSCustomObject]@{
            available = $LivePrivileges.Available
            reason    = $LivePrivileges.Reason
            items     = @($LivePrivileges.Items | ForEach-Object { [PSCustomObject]@{ name = $_.Name; state = $_.State; enabledByDefault = $_.EnabledByDefault } })
        }
        findings      = @($Findings.ToArray())
        gaps          = @($Gaps.ToArray())
    }

    $DashboardJson = $DashboardData | ConvertTo-Json -Depth 15
    $DashboardJsonPath = Join-Path $OutputPath "Dashboard-Data.json"
    $DashboardJson | Set-Content -LiteralPath $DashboardJsonPath -Encoding UTF8
    $DashboardJsonSafe = $DashboardJson -replace "</script", "<\/script"

    #-----------------------------------------------------------------
    # HTML dashboard
    #-----------------------------------------------------------------

    Write-ScanLog "Building HTML dashboard..."

    $DashboardHtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Privilege &amp; Permissions Report - __IDENTITY__</title>
<style>
:root {
  --bg: #eef1f6;
  --surface: #ffffff;
  --surface-2: #f6f7fb;
  --border: #e5e8ef;
  --border-strong: #d5dae4;
  --text: #12141a;
  --text-2: #3c4250;
  --muted: #6b7280;
  --accent: #4f46e5;
  --accent-2: #6366f1;
  --accent-soft: #eef2ff;
  --secure: #16a34a;
  --secure-bg: #dcfce7;
  --partial: #b45309;
  --partial-bg: #fef3c7;
  --insecure: #dc2626;
  --insecure-bg: #fee2e2;
  --unknown: #6b7280;
  --unknown-bg: #e9ecf2;
  --critical: #b91c1c;
  --info: #2563eb;
  --radius: 14px;
  --radius-sm: 10px;
  --shadow-sm: 0 1px 2px rgba(17,24,39,.05), 0 1px 3px rgba(17,24,39,.04);
  --shadow-md: 0 6px 18px rgba(17,24,39,.08);
  --shadow-lg: 0 18px 40px rgba(17,24,39,.14);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: linear-gradient(180deg, #eef1f6 0%, #e8ecf3 100%);
  background-attachment: fixed;
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
header { padding: 28px 32px 24px; background: linear-gradient(120deg, #1e1b4b 0%, #4338ca 55%, #4f46e5 100%); color: #eef2ff; }
header h1 { margin: 0 0 6px 0; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }
header .meta { color: #c7d2fe; font-size: 13px; }
header .meta strong { color: #ffffff; font-weight: 600; }
.tabs {
  display: flex; gap: 6px; padding: 10px 24px; flex-wrap: wrap;
  position: sticky; top: 0; z-index: 30;
  background: rgba(255,255,255,0.82);
  backdrop-filter: saturate(180%) blur(12px);
  -webkit-backdrop-filter: saturate(180%) blur(12px);
  border-bottom: 1px solid var(--border);
}
.tab-btn {
  border: none; background: none; padding: 9px 15px; cursor: pointer;
  font-size: 13.5px; color: var(--text-2); font-weight: 500;
  border-radius: 999px; transition: background .15s ease, color .15s ease;
}
.tab-btn:hover { background: var(--surface-2); color: var(--text); }
.tab-btn.active { color: var(--accent); background: var(--accent-soft); font-weight: 600; }
.tab-panel { display: none; padding: 20px 32px 40px; }
.tab-panel.active { display: block; }
.controls { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
.controls input[type=text] { padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; min-width: 260px; font-size: 13px; }
.controls select { padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }
.controls label { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
.section-block { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px 20px; margin-bottom: 16px; box-shadow: var(--shadow-sm); }
.section-block h3 { margin: 0 0 12px; font-size: 15px; font-weight: 650; }
.kv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.kv-table td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.kv-table td:first-child { color: var(--muted); width: 260px; }
.tab-intro { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
.muted { color: var(--muted); font-size: 13px; }
code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
footer { padding: 20px 32px 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 20px; }
.table-wrap { overflow-x: auto; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th, .data-table td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-word; }
.data-table th { font-size: 12px; color: var(--muted); white-space: nowrap; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.sev-critical { background: #fee2e2; color: #b91c1c; }
.sev-high { background: var(--insecure-bg); color: var(--insecure); }
.sev-medium { background: var(--partial-bg); color: var(--partial); }
.sev-low { background: var(--unknown-bg); color: var(--unknown); }
.sev-info { background: #e0edff; color: var(--accent); }
.sev-secure { background: var(--secure-bg); color: var(--secure); }
.sev-unknown { background: var(--unknown-bg); color: var(--unknown); }
.check-overview { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 10px; margin-bottom: 20px; }
.check-card { display: block; text-decoration: none; color: inherit; background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: var(--radius-sm); padding: 12px 14px; box-shadow: var(--shadow-sm); transition: transform .12s ease, box-shadow .15s ease, border-color .15s ease; }
.check-card:hover { border-color: var(--accent); box-shadow: var(--shadow-md); transform: translateY(-2px); }
.check-card-value { font-size: 24px; font-weight: 700; }
.check-card-title { font-size: 12px; color: var(--muted); margin: 2px 0 8px; }
.check-card.sev-critical { border-left-color: #b91c1c; }
.check-card.sev-high { border-left-color: var(--insecure); }
.check-card.sev-medium { border-left-color: var(--partial); }
.check-card.sev-low { border-left-color: var(--unknown); }
.check-card.sev-info { border-left-color: var(--accent); }
.check-card.sev-secure { border-left-color: var(--secure); }
.check-card.sev-none { opacity: 0.55; }
.check-block { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); margin-bottom: 10px; overflow: hidden; box-shadow: var(--shadow-sm); scroll-margin-top: 84px; transition: box-shadow .15s ease, border-color .15s ease; }
.check-block:hover { box-shadow: var(--shadow-md); }
.check-block[open] { border-color: var(--border-strong); }
.check-block summary { padding: 14px 18px; cursor: pointer; display: flex; gap: 12px; align-items: center; list-style: none; flex-wrap: wrap; }
.check-block summary::-webkit-details-marker { display: none; }
.check-name { font-weight: 600; }
.check-count { margin-left: auto; }
.check-body { padding: 0 18px 18px; }
.check-desc { font-size: 13px; margin: 0 0 10px; }
.risk { font-size: 13px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 10px 12px; margin: 10px 0; }
.reco { font-size: 13px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 10px 12px; margin: 10px 0; }
.baseline { font-size: 13px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 10px 12px; margin: 10px 0; }
.ov-h { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin: 26px 0 12px; font-weight: 650; }
.ov-hero {
  display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap;
  border-radius: 18px; padding: 26px 28px; margin-bottom: 18px; color: #fff;
  box-shadow: var(--shadow-lg);
  background: linear-gradient(120deg, #334155 0%, #475569 100%);
}
.ov-hero.ov-critical { background: linear-gradient(120deg, #7f1d1d 0%, #b91c1c 100%); }
.ov-hero.ov-high { background: linear-gradient(120deg, #9a3412 0%, #dc2626 100%); }
.ov-hero.ov-medium { background: linear-gradient(120deg, #92400e 0%, #d97706 100%); }
.ov-hero.ov-low { background: linear-gradient(120deg, #3730a3 0%, #4f46e5 100%); }
.ov-hero.ov-secure { background: linear-gradient(120deg, #065f46 0%, #16a34a 100%); }
.ov-hero-eyebrow { text-transform: uppercase; letter-spacing: .08em; font-size: 11px; opacity: .82; font-weight: 600; }
.ov-hero-title { font-size: 25px; font-weight: 750; margin: 10px 0 6px; letter-spacing: -0.015em; }
.ov-hero-sub { font-size: 14px; opacity: .92; }
.ov-hero-meta { display: grid; gap: 12px; align-content: center; min-width: 210px; }
.ov-hero-meta > div { display: flex; flex-direction: column; }
.ov-hero-meta-k { font-size: 10.5px; text-transform: uppercase; letter-spacing: .06em; opacity: .75; }
.ov-hero-meta-v { font-size: 14px; font-weight: 600; }
.ov-sevrow { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.ov-sev { background: var(--surface); border: 1px solid var(--border); border-top: 3px solid var(--border-strong); border-radius: var(--radius); padding: 16px 18px; box-shadow: var(--shadow-sm); }
.ov-sev-top { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: var(--text-2); }
.ov-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--muted); display: inline-block; }
.ov-sev-num { font-size: 34px; font-weight: 750; line-height: 1.1; margin: 8px 0 2px; letter-spacing: -0.02em; }
.ov-sev-sub { font-size: 12px; color: var(--muted); }
.ov-sev.ov-empty { opacity: .58; }
.ov-critical { border-top-color: var(--critical); } .ov-critical .ov-dot { background: var(--critical); } .ov-critical .ov-sev-num { color: var(--critical); }
.ov-high { border-top-color: var(--insecure); } .ov-high .ov-dot { background: var(--insecure); } .ov-high .ov-sev-num { color: var(--insecure); }
.ov-medium { border-top-color: var(--partial); } .ov-medium .ov-dot { background: var(--partial); } .ov-medium .ov-sev-num { color: var(--partial); }
.ov-low { border-top-color: var(--muted); }
.ov-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr)); gap: 14px; }
.ov-metric { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; box-shadow: var(--shadow-sm); }
.ov-metric-val { font-size: 26px; font-weight: 750; letter-spacing: -0.02em; }
.ov-metric-lbl { font-size: 13px; color: var(--text-2); font-weight: 550; margin-top: 2px; }
.ov-metric-sub { font-size: 11.5px; color: var(--muted); margin-top: 2px; }
.ov-metric.ov-bad .ov-metric-val { color: var(--insecure); }
.ov-metric.ov-warn .ov-metric-val { color: var(--partial); }
.ov-metric.ov-ok .ov-metric-val { color: var(--secure); }
.ov-priorities { display: flex; flex-direction: column; gap: 8px; }
.ov-priority { display: flex; align-items: center; gap: 12px; text-decoration: none; color: inherit; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 12px 16px; box-shadow: var(--shadow-sm); transition: transform .12s ease, box-shadow .15s ease, border-color .15s ease; }
.ov-priority:hover { border-color: var(--accent); box-shadow: var(--shadow-md); transform: translateX(2px); }
.ov-priority-title { font-weight: 600; font-size: 14px; }
.ov-priority-cat { font-size: 11px; color: var(--muted); background: var(--surface-2); border: 1px solid var(--border); border-radius: 999px; padding: 1px 9px; }
.ov-priority-count { margin-left: auto; font-weight: 700; font-size: 15px; }
.ov-priority-arrow { color: var(--muted); font-size: 22px; line-height: 1; }
.ov-allclear { background: var(--secure-bg); color: #14532d; border: 1px solid #bbf7d0; border-radius: var(--radius); padding: 16px 18px; font-size: 14px; }
.gap-row { font-size: 13px; padding: 8px 10px; border-bottom: 1px solid var(--border); }
.gap-row strong { color: var(--text-2); }
@media (max-width: 720px) { .ov-hero { flex-direction: column; } }
</style>
</head>
<body>

<header>
  <h1>Privilege &amp; Permissions Report</h1>
  <div class="meta">Identity: <strong>__IDENTITY__</strong> &middot; Computer: <strong>__COMPUTER__</strong> &middot; Generated: __GENERATED_AT__</div>
</header>

<nav class="tabs">
  <button class="tab-btn active" data-tab="overview">Overview</button>
  <button class="tab-btn" data-tab="identity">Identity</button>
  <button class="tab-btn" data-tab="domaingroups">Domain Privileges</button>
  <button class="tab-btn" data-tab="aclfindings">AD Object Permissions</button>
  <button class="tab-btn" data-tab="local">Local Machine</button>
  <button class="tab-btn" data-tab="userrights">User Rights Assignment</button>
  <button class="tab-btn" data-tab="allfindings">All Findings</button>
  <button class="tab-btn" data-tab="evidence">Evidence &amp; Gaps</button>
</nav>

<section id="tab-overview" class="tab-panel active"><div id="overview-container"></div></section>
<section id="tab-identity" class="tab-panel"><div id="identity-container"></div></section>
<section id="tab-domaingroups" class="tab-panel"><div id="domaingroups-container"></div></section>
<section id="tab-aclfindings" class="tab-panel"><div id="aclfindings-container"></div></section>
<section id="tab-local" class="tab-panel"><div id="local-container"></div></section>
<section id="tab-userrights" class="tab-panel"><div id="userrights-container"></div></section>

<section id="tab-allfindings" class="tab-panel">
  <div class="controls">
    <input type="text" id="findings-search" placeholder="Search item, category, risk..." />
    <select id="findings-severity">
      <option value="all">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
      <option value="secure">Secure / positive</option>
    </select>
    <select id="findings-scope">
      <option value="all">All scopes</option>
      <option value="Domain">Domain</option>
      <option value="Local">Local</option>
    </select>
  </div>
  <div id="allfindings-container"></div>
</section>

<section id="tab-evidence" class="tab-panel"><div id="evidence-container"></div></section>

<footer>
  This report reflects a point-in-time, read-only enumeration of what the scanned identity can do, both on this
  computer and in the domain. Local group membership and User Rights Assignment are computed by matching the
  scanned identity's full SID set (its own SID plus every domain group it belongs to, resolved by Active Directory
  itself through the constructed "tokenGroups" attribute) against local group members and local policy - this does
  not require logging on as the account. Live, currently-enabled token privileges can only be captured for the
  account actually running the scan session, and are skipped when a different credential is supplied. AD object
  permission findings cover the domain root, AdminSDHolder, existing Group Policy Objects, and the account's own
  user/computer objects by default; a full OU sweep is only performed when the script is run with -ScanOuAcls.
  Anything this scan could not read is listed on the "Evidence &amp; Gaps" tab rather than silently treated as
  absent - treat those as unknowns, not as a clean bill of health.
</footer>

<script>
const data = __DASHBOARD_JSON__;

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4, secure: 5, unknown: 6 };
const severityLabel = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', secure: 'Secure / positive', unknown: 'Unknown / gap' };

function sevBadge(sev) {
  const s = sev && severityLabel[sev] ? sev : 'unknown';
  return '<span class="sev sev-' + esc(s) + '">' + esc(severityLabel[s]) + '</span>';
}

function activateTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.add('active');
}
document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => activateTab(btn.dataset.tab)));

function openFinding(id) {
  const el = document.getElementById('finding-' + id);
  if (el) { el.open = true; el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}

function findingBlock(f, idPrefix) {
  return '<details class="check-block" id="' + esc(idPrefix) + '-' + f.id + '">' +
    '<summary><span class="check-name">' + esc(f.item) + '</span>' + sevBadge(f.severity) +
    '<span class="check-count muted">' + esc(f.category) + '</span></summary>' +
    '<div class="check-body">' +
    (f.status ? '<p class="check-desc"><strong>Status:</strong> ' + esc(f.status) + '</p>' : '') +
    (f.baseline ? '<div class="baseline"><strong>Normal baseline:</strong> ' + esc(f.baseline) + '</div>' : '') +
    (f.risk ? '<div class="risk"><strong>Risk:</strong> ' + esc(f.risk) + '</div>' : '') +
    (f.remediation ? '<div class="reco"><strong>Remediation:</strong> ' + esc(f.remediation) + '</div>' : '') +
    (f.evidence ? '<p class="muted">Evidence: <code>' + esc(f.evidence) + '</code></p>' : '') +
    '</div></details>';
}

function renderOverview() {
  const s = data.summary;
  const sc = data.scan;
  let vCls = s.overallSeverity === 'secure' ? 'secure' : s.overallSeverity;
  if (!['critical','high','medium','low','secure'].includes(vCls)) vCls = 'low';

  let html = '<div class="ov-hero ov-' + esc(vCls) + '">' +
    '<div class="ov-hero-main">' +
    '<div class="ov-hero-eyebrow">Privilege posture</div>' +
    '<div class="ov-hero-title">' + esc(s.overallLabel) + '</div>' +
    '<div class="ov-hero-sub">Scanned identity: ' + esc(sc.identityDisplay) + '</div>' +
    '</div>' +
    '<div class="ov-hero-meta">' +
    '<div><span class="ov-hero-meta-k">Computer</span><span class="ov-hero-meta-v">' + esc(data.computerName) + '</span></div>' +
    '<div><span class="ov-hero-meta-k">Domain</span><span class="ov-hero-meta-v">' + esc(data.domain || 'not domain-joined') + '</span></div>' +
    '<div><span class="ov-hero-meta-k">Generated</span><span class="ov-hero-meta-v">' + esc(data.generatedAt) + '</span></div>' +
    '</div></div>';

  html += '<div class="ov-h">Findings by severity</div><div class="ov-sevrow">';
  ['critical', 'high', 'medium', 'low'].forEach(k => {
    const n = s[k] || 0;
    html += '<div class="ov-sev ov-' + k + (n ? '' : ' ov-empty') + '">' +
      '<div class="ov-sev-top"><span class="ov-dot"></span>' + severityLabel[k] + '</div>' +
      '<div class="ov-sev-num">' + n + '</div>' +
      '<div class="ov-sev-sub">' + (n ? 'finding' + (n === 1 ? '' : 's') : 'None') + '</div></div>';
  });
  html += '</div>';

  html += '<div class="ov-h">Scan details</div><div class="ov-metrics">';
  const metric = (value, label, sub, tone) => '<div class="ov-metric' + (tone ? ' ov-' + tone : '') + '">' +
    '<div class="ov-metric-val">' + esc(value) + '</div><div class="ov-metric-lbl">' + esc(label) + '</div>' +
    (sub ? '<div class="ov-metric-sub">' + esc(sub) + '</div>' : '') + '</div>';
  metricsHtml: {
    html += metric(sc.elevated ? 'Yes' : 'No', 'Running elevated', null, sc.elevated ? 'ok' : 'warn');
    html += metric(sc.domainAvailable ? 'Yes' : 'No', 'Domain contacted', sc.domainAvailable ? data.domainController : '', sc.domainAvailable ? 'ok' : 'bad');
    html += metric(s.secure, 'Positive / secure findings', null, 'ok');
    html += metric(s.gaps, 'Evidence gaps', 'see Evidence & Gaps tab', s.gaps > 0 ? 'warn' : 'ok');
    html += metric(sc.scannedOuAcls ? 'Yes' : 'No', 'Full OU ACL sweep run', sc.scannedOuAcls ? '' : 'run with -ScanOuAcls', null);
  }
  html += '</div>';

  const flagged = (data.findings || []).filter(f => f.severity !== 'secure' && f.severity !== 'info' && f.severity !== 'unknown')
    .slice().sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

  html += '<div class="ov-h">Top priorities</div>';
  if (!flagged.length) {
    html += '<div class="ov-allclear">Nothing needs attention right now beyond the normal baseline. Every finding is still available on the other tabs.</div>';
  } else {
    html += '<div class="ov-priorities">';
    flagged.slice(0, 15).forEach(f => {
      html += '<a class="ov-priority" href="#" data-jump data-id="' + f.id + '">' +
        sevBadge(f.severity) + '<span class="ov-priority-title">' + esc(f.item) + '</span>' +
        '<span class="ov-priority-cat">' + esc(f.category) + '</span>' +
        '<span class="ov-priority-arrow">&rsaquo;</span></a>';
    });
    html += '</div>';
    if (flagged.length > 15) html += '<p class="muted">+ ' + (flagged.length - 15) + ' more - see the All Findings tab.</p>';
  }

  document.getElementById('overview-container').innerHTML = html;
}

function renderIdentity() {
  const container = document.getElementById('identity-container');
  const id = data.identity;
  const sc = data.scan;

  let html = '<div class="section-block"><h3>Scan identity</h3><table class="kv-table">' +
    '<tr><td>Scanned as</td><td>' + esc(sc.identityDisplay) + '</td></tr>' +
    '<tr><td>Used explicitly-supplied credential</td><td>' + (sc.usedExplicitCredential ? 'Yes' : 'No (current logon)') + '</td></tr>' +
    '<tr><td>Current logged-on session</td><td>' + esc(sc.currentSessionIdentity) + '</td></tr>' +
    '<tr><td>Running elevated</td><td>' + (sc.elevated ? 'Yes' : 'No') + '</td></tr>' +
    '</table></div>';

  if (!id) {
    html += '<div class="section-block"><p class="muted">No Active Directory account object was resolved for this identity (domain unavailable, or the account was not found).</p></div>';
    document.getElementById('identity-container').innerHTML = html;
    return;
  }

  html += '<div class="section-block"><h3>Active Directory account</h3><table class="kv-table">' +
    '<tr><td>sAMAccountName</td><td>' + esc(id.samAccountName) + '</td></tr>' +
    '<tr><td>User Principal Name</td><td>' + esc(id.upn) + '</td></tr>' +
    '<tr><td>Display name</td><td>' + esc(id.displayName) + '</td></tr>' +
    '<tr><td>Distinguished name</td><td><code>' + esc(id.dn) + '</code></td></tr>' +
    '<tr><td>SID</td><td><code>' + esc(id.sid) + '</code></td></tr>' +
    '<tr><td>Created</td><td>' + esc(id.whenCreated) + '</td></tr>' +
    '<tr><td>Password last set</td><td>' + esc(id.pwdLastSet) + '</td></tr>' +
    '<tr><td>adminCount</td><td>' + esc(id.adminCount) + '</td></tr>' +
    '<tr><td>Service Principal Names</td><td>' + (id.spns.length ? id.spns.map(esc).join('<br/>') : '<span class="muted">none</span>') + '</td></tr>' +
    '<tr><td>Constrained delegation targets</td><td>' + (id.delegateTo.length ? id.delegateTo.map(esc).join('<br/>') : '<span class="muted">none</span>') + '</td></tr>' +
    '</table></div>';

  const setFlags = id.uacFlags.filter(f => f.present);
  html += '<div class="section-block"><h3>Account control flags</h3>';
  if (!setFlags.length) {
    html += '<p class="muted">No notable userAccountControl flags are set.</p>';
  } else {
    html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>Flag</th><th>Severity</th><th>Meaning</th></tr></thead><tbody>' +
      setFlags.map(f => '<tr><td><code>' + esc(f.name) + '</code></td><td>' + sevBadge(f.severity) + '</td><td>' + esc(f.note) + '</td></tr>').join('') +
      '</tbody></table></div>';
  }
  html += '</div>';

  document.getElementById('identity-container').innerHTML = html;
}

function renderCategoryTab(containerId, category, intro, emptyText) {
  const container = document.getElementById(containerId);
  const items = (data.findings || []).filter(f => f.category === category);

  let html = intro ? '<p class="tab-intro">' + esc(intro) + '</p>' : '';

  if (!items.length) {
    html += '<p class="muted">' + esc(emptyText || 'No findings in this category.') + '</p>';
    container.innerHTML = html;
    return;
  }

  const sorted = items.slice().sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  html += sorted.map(f => findingBlock(f, containerId)).join('');
  container.innerHTML = html;
}

function renderAclFindings() {
  renderCategoryTab('aclfindings-container', 'AD Object Permissions',
    'Active Directory permissions (ACLs) this identity holds - directly or via group membership - on the domain root, AdminSDHolder, existing Group Policy Objects, and its own user/computer objects. A full OU sweep only runs with -ScanOuAcls.',
    'No dangerous AD object permissions were found.');
}

function renderDomainGroups() {
  renderCategoryTab('domaingroups-container', 'Privileged Group Membership',
    'Every well-known privileged local/domain group this identity belongs to, resolved through nested group membership by Active Directory itself (the "tokenGroups" attribute), plus a small catalog of commonly-privileged named groups (DnsAdmins, Exchange groups, etc.).',
    'No privileged group membership was found for this identity.');

  // Also fold in Account Configuration / Kerberos / Delegation findings underneath, since they describe the account itself.
  const extra = (data.findings || []).filter(f => ['Account Configuration', 'Kerberos', 'Delegation'].includes(f.category));
  if (extra.length) {
    const sorted = extra.slice().sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
    const container = document.getElementById('domaingroups-container');
    container.innerHTML += '<div class="ov-h">Account configuration &amp; Kerberos</div>' + sorted.map(f => findingBlock(f, 'domaingroups-container')).join('');
  }
}

function renderLocal() {
  const container = document.getElementById('local-container');
  let html = '<p class="tab-intro">Local group membership and live token privileges on this computer (' + esc(data.computerName) + ').</p>';

  const groupFindings = (data.findings || []).filter(f => f.category === 'Local Group Membership').slice().sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  html += '<div class="ov-h">Local group membership</div>';
  html += groupFindings.length ? groupFindings.map(f => findingBlock(f, 'local')).join('') : '<p class="muted">No local group membership findings.</p>';

  html += '<div class="ov-h">Local Administrators group - full membership</div>';
  const admins = data.localAdministrators || [];
  html += '<div class="section-block">' + (admins.length
    ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>SID</th><th>Type</th><th>Source</th></tr></thead><tbody>' +
      admins.map(a => '<tr><td>' + esc(a.name) + '</td><td><code>' + esc(a.sid) + '</code></td><td>' + esc(a.class) + '</td><td>' + esc(a.source) + '</td></tr>').join('') +
      '</tbody></table></div>'
    : '<p class="muted">Could not be enumerated.</p>') + '</div>';

  html += '<div class="ov-h">Live token privileges (current session only)</div><div class="section-block">';
  const live = data.livePrivileges;
  if (!live.available) {
    html += '<p class="muted">' + esc(live.reason || 'Not available.') + '</p>';
  } else {
    const enabled = live.items.filter(i => i.state === 'Enabled');
    html += '<p class="muted">' + enabled.length + ' of ' + live.items.length + ' assigned privileges are currently enabled in this session\'s token. This reflects only the account actually running this script right now.</p>';
    html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>Privilege</th><th>State</th><th>Enabled by default</th></tr></thead><tbody>' +
      live.items.map(i => '<tr><td><code>' + esc(i.name) + '</code></td><td>' + esc(i.state) + '</td><td>' + (i.enabledByDefault ? 'Yes' : 'No') + '</td></tr>').join('') +
      '</tbody></table></div>';
  }
  html += '</div>';

  container.innerHTML = html;
}

function renderUserRights() {
  const container = document.getElementById('userrights-container');
  const rows = data.userRights || [];
  let html = '<p class="tab-intro">The local User Rights Assignment policy on ' + esc(data.computerName) + ', read via secedit, matched against this identity\'s full SID set. Rows this identity is granted are shown first.</p>';

  if (!rows.length) {
    html += '<p class="muted">User Rights Assignment could not be read - see the Evidence &amp; Gaps tab.</p>';
    container.innerHTML = html;
    return;
  }

  const granted = rows.filter(r => r.Granted).sort((a, b) => severityRank[a.Severity] - severityRank[b.Severity]);
  const notGranted = rows.filter(r => !r.Granted).sort((a, b) => a.Right.localeCompare(b.Right));

  const rowHtml = r => '<tr><td><code>' + esc(r.Right) + '</code></td><td>' + sevBadge(r.Severity) + '<td>' + (r.Granted ? 'Yes' : 'No') + '</td><td>' + esc(r.GrantedVia) + '</td><td>' + esc(r.Risk) + '</td><td>' + esc(r.Remediation) + '</td></tr>';

  html += '<div class="ov-h">Granted to this identity (' + granted.length + ')</div>';
  html += '<div class="table-wrap"><table class="data-table"><thead><tr><th>Right</th><th>Severity</th><th>Granted</th><th>Via</th><th>Risk</th><th>Remediation</th></tr></thead><tbody>' +
    (granted.length ? granted.map(rowHtml).join('') : '<tr><td colspan="6" class="muted">No rights matched this identity.</td></tr>') + '</tbody></table></div>';

  html += '<div class="ov-h">Not granted (' + notGranted.length + ')</div>';
  html += '<details class="check-block"><summary><span class="check-name">Show full local policy</span></summary><div class="check-body">' +
    '<div class="table-wrap"><table class="data-table"><thead><tr><th>Right</th><th>Severity if granted</th></tr></thead><tbody>' +
    notGranted.map(r => '<tr><td><code>' + esc(r.Right) + '</code></td><td>' + sevBadge(r.Severity) + '</td></tr>').join('') +
    '</tbody></table></div></div></details>';

  container.innerHTML = html;
}

function renderAllFindings(searchText, severityFilter, scopeFilter) {
  const container = document.getElementById('allfindings-container');
  const term = (searchText || '').trim().toLowerCase();

  let items = (data.findings || []).slice();
  if (severityFilter && severityFilter !== 'all') items = items.filter(f => f.severity === severityFilter);
  if (scopeFilter && scopeFilter !== 'all') items = items.filter(f => f.scope === scopeFilter);
  if (term) items = items.filter(f => (f.item + ' ' + f.category + ' ' + f.risk + ' ' + f.evidence).toLowerCase().includes(term));

  items.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

  if (!items.length) {
    container.innerHTML = '<p class="muted">No findings match the current filters.</p>';
    return;
  }

  container.innerHTML = '<p class="muted">' + items.length + ' finding(s)</p>' + items.map(f => findingBlock(f, 'all')).join('');
}

function renderEvidence() {
  const container = document.getElementById('evidence-container');
  let html = '<div class="section-block"><h3>Scan metadata</h3><table class="kv-table">' +
    '<tr><td>Output folder</td><td><code>' + esc(data.scan.outputFolder) + '</code></td></tr>' +
    '<tr><td>Domain controller used</td><td>' + esc(data.domainController || '') + '</td></tr>' +
    '<tr><td>Generated</td><td>' + esc(data.generatedAt) + '</td></tr>' +
    '</table></div>';

  html += '<div class="section-block"><h3>Evidence gaps (' + (data.gaps || []).length + ')</h3>';
  if (!data.gaps || !data.gaps.length) {
    html += '<p class="muted">No gaps recorded - every section this script attempts was successfully evaluated.</p>';
  } else {
    html += data.gaps.map(g => '<div class="gap-row"><strong>' + esc(g.Area) + ':</strong> ' + esc(g.Reason) + '</div>').join('');
  }
  html += '</div>';

  html += '<div class="section-block"><h3>Evidence files</h3><ul>' +
    '<li><code>Dashboard-Data.json</code> - the raw data behind this report</li>' +
    '<li><code>CSV\\All-Findings.csv</code></li>' +
    '<li><code>CSV\\AD-Object-Permissions.csv</code></li>' +
    '<li><code>CSV\\Local-Group-Membership.csv</code></li>' +
    '<li><code>CSV\\User-Rights-Assignment.csv</code></li>' +
    '<li><code>CSV\\Evidence-Gaps.csv</code></li>' +
    '<li><code>PowerShell-Transcript.txt</code></li>' +
    '</ul></div>';

  container.innerHTML = html;
}

document.body.addEventListener('click', e => {
  const jump = e.target.closest('[data-jump]');
  if (jump) {
    e.preventDefault();
    activateTab('allfindings');
    window.requestAnimationFrame(() => openFinding(jump.dataset.id));
  }
});

const findingsSearch = document.getElementById('findings-search');
const findingsSeverity = document.getElementById('findings-severity');
const findingsScope = document.getElementById('findings-scope');
[findingsSearch, findingsSeverity, findingsScope].forEach(el => {
  el.addEventListener('input', () => renderAllFindings(findingsSearch.value, findingsSeverity.value, findingsScope.value));
  el.addEventListener('change', () => renderAllFindings(findingsSearch.value, findingsSeverity.value, findingsScope.value));
});

renderOverview();
renderIdentity();
renderDomainGroups();
renderAclFindings();
renderLocal();
renderUserRights();
renderAllFindings('', 'all', 'all');
renderEvidence();
</script>
</body>
</html>
'@

    $DashboardHtml = $DashboardHtmlTemplate.Replace("__DASHBOARD_JSON__", $DashboardJsonSafe)
    $DashboardHtml = $DashboardHtml.Replace("__GENERATED_AT__", $DashboardData.generatedAt)
    $DashboardHtml = $DashboardHtml.Replace("__IDENTITY__", $TargetIdentityDisplay)
    $DashboardHtml = $DashboardHtml.Replace("__COMPUTER__", $env:COMPUTERNAME)

    $DashboardHtmlPath = Join-Path $OutputPath "Privilege-Assessment-Dashboard.html"
    $DashboardHtml | Set-Content -LiteralPath $DashboardHtmlPath -Encoding UTF8

    Write-ScanLog "Dashboard written to: $DashboardHtmlPath"

    #-----------------------------------------------------------------
    # Human-readable summary
    #-----------------------------------------------------------------

    $SummaryPath = Join-Path $OutputPath "SCAN-SUMMARY.txt"
    $SummaryLines = New-Object System.Collections.Generic.List[string]
    $SummaryLines.Add("PRIVILEGE & PERMISSIONS SCAN")
    $SummaryLines.Add("============================")
    $SummaryLines.Add("")
    $SummaryLines.Add("Scan time        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')")
    $SummaryLines.Add("Scanned identity  : $TargetIdentityDisplay")
    $SummaryLines.Add("Computer          : $env:COMPUTERNAME")
    $SummaryLines.Add("Domain            : $(if ($DomainContext) { $DomainContext.DomainDnsName } else { 'not domain-joined / unavailable' })")
    $SummaryLines.Add("Elevated session  : $IsElevated")
    $SummaryLines.Add("")
    $SummaryLines.Add("FINDINGS BY SEVERITY")
    $SummaryLines.Add("---------------------")
    foreach ($Key in $SeverityCounts.Keys) { $SummaryLines.Add("$Key : $($SeverityCounts[$Key])") }
    $SummaryLines.Add("")
    $SummaryLines.Add("EVIDENCE GAPS: $($Gaps.Count)")
    $SummaryLines.Add("------------------")
    foreach ($Gap in $Gaps) { $SummaryLines.Add("- $($Gap.Area): $($Gap.Reason)") }
    $SummaryLines.Add("")
    $SummaryLines.Add("EVIDENCE FILES")
    $SummaryLines.Add("--------------")
    $SummaryLines.Add("Privilege-Assessment-Dashboard.html (open in a browser)")
    $SummaryLines.Add("Dashboard-Data.json")
    $SummaryLines.Add("CSV\All-Findings.csv")
    $SummaryLines.Add("CSV\AD-Object-Permissions.csv")
    $SummaryLines.Add("CSV\Local-Group-Membership.csv")
    $SummaryLines.Add("CSV\User-Rights-Assignment.csv")
    $SummaryLines.Add("CSV\Evidence-Gaps.csv")
    $SummaryLines.Add("PowerShell-Transcript.txt")

    $SummaryLines | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    #-----------------------------------------------------------------
    # Final banner
    #-----------------------------------------------------------------

    $BannerRule = "=" * 78
    Write-Host ""
    Write-Host $BannerRule -ForegroundColor Green
    Write-Host "  SCAN COMPLETE" -ForegroundColor Green
    Write-Host $BannerRule -ForegroundColor Green
    Write-Host "  Output folder : $OutputPath"
    Write-Host "  Dashboard     : $DashboardHtmlPath"
    Write-Host "  Summary       : $SummaryPath"
    Write-Host $BannerRule -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-ScanLog -Level "ERROR" -Message $_.Exception.Message
    throw
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
