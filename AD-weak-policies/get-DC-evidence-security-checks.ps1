#requires -Version 5.1
#requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Exports audit evidence for Group Policy settings related to:
    - SMB signing enforcement
    - NTLMv1 prevention
    - GPO links and structural scope
    - Security filtering (including resolved group membership)
    - WMI filtering
    - Group Policy inheritance

    In addition, the script collects:
    - Domain information and a full domain controller inventory
      (shown on the dashboard "Domain overview" cover tab)
    - A cumulative privileged-account inventory: every account that is a
      member of any administrative group or of Protected Users, cross-
      referenced against those groups and against the Protected Users
      group (checkmark matrix per account)
    - Recursive privileged group membership, including groups that are
      nested inside privileged groups (with the nesting path recorded)
    - The default domain password policy and any fine-grained password
      policies (PSOs)

    Also produces a single-file interactive HTML dashboard that lets you
    trace, per GPO and per OU/domain, whether a weak setting is mitigated,
    which security groups it applies to, and (on hover) who is in those
    groups. The dashboard now opens with a domain overview cover tab and
    contains dedicated tabs for privileged access and password policy.

.DESCRIPTION
    This script is intended to be executed from a domain controller or a
    management system with the ActiveDirectory and GroupPolicy modules.

    The script uses language-independent registry paths and values instead
    of localized Group Policy display names. Privileged groups are located
    by well-known SID/RID rather than by display name for the same reason.
    This makes it suitable for domains containing systems with different
    operating system languages.

    Security Options configured through Group Policy are read directly from
    GptTmpl.inf files in SYSVOL.

    The script produces:
    - CSV summaries
    - Per-GPO HTML and XML reports
    - Raw GptTmpl.inf evidence
    - Direct GPO link information
    - Structural inherited scope information
    - Security filtering information, plus resolved group membership
    - WMI filter information
    - Domain information and domain controller inventory
    - Recursive privileged group membership (including nested groups)
    - A cumulative privileged-account x administrative groups matrix,
      including Protected Users membership status
    - Default and fine-grained password policy evidence
    - A record of OUs/domain containers where inheritance could not be
      evaluated, even after retries
    - An interactive HTML dashboard (AUDIT-DASHBOARD.html) combining all
      of the above so findings can be traced by GPO or by OU, with
      hover tooltips showing group membership
    - SHA-256 hashes for all evidence files
    - A PowerShell transcript
    - A human-readable audit summary

.NOTES
    Run from an elevated Windows PowerShell session.

    Structural scope does not automatically mean that a GPO applies to every
    object below a link. Security filtering, WMI filtering, loopback processing,
    disabled GPO sections, and client-side processing can affect final policy
    application. The dashboard surfaces configured settings, structural
    scope and security filtering; it does not compute final effective
    (resultant) policy.

    Get-GPInheritance is called once per domain/OU target. In larger domains
    this can trigger transient failures from the underlying GPMC COM layer
    or from AD Web Services load ("Could not evaluate inheritance on this
    object. Verify that the property exists."). This script adds a small
    delay between calls and retries failed targets a configurable number of
    times before giving up and recording the target as a gap in evidence.

    Group membership resolution calls Get-ADGroupMember for every group
    used in security filtering. For very large groups (e.g. Domain Users,
    Domain Computers) this can be slow; only the first
    -MaxGroupMembersToDisplay members are embedded in the dashboard, but
    the full list is still written to CSV. Use -ResolveGroupMembership:$false
    to skip this step entirely.

    Privileged group membership is resolved recursively through the group
    "Members" attribute (not Get-ADGroupMember), so a single unresolvable
    member - for example a foreign security principal from a trusted
    forest - does not abort enumeration of the whole group. Unresolvable
    members are recorded with object type "unresolved". Members located in
    other domains of the forest may not resolve against the selected
    domain controller; they are recorded as unresolved rather than
    silently dropped. Enterprise Admins, Schema Admins and Enterprise Key
    Admins live in the forest root domain; in a child domain these lookups
    can fail and are then recorded as unresolved groups (an evidence gap,
    not an empty group).

    The Protected Users group and the Key Admins groups only exist at
    certain domain/forest functional levels. When a group does not exist,
    it is reported as "not resolved" instead of failing the run.

    Enumerating fine-grained password policies typically requires
    Domain Admins-level read permissions on the Password Settings
    Container. A failure there is recorded as an evidence gap.

    For computer-specific proof, supplement this domain-level evidence with:
        gpresult.exe /h GPResult.html
    or:
        Get-GPResultantSetOfPolicy

.EXAMPLE
    .\Export-GpoSecurityEvidence.ps1

.EXAMPLE
    .\Export-GpoSecurityEvidence.ps1 -OutputPath C:\AuditEvidence\GPO

.EXAMPLE
    .\Export-GpoSecurityEvidence.ps1 `
        -OutputPath C:\AuditEvidence\GPO `
        -DomainController DC01.contoso.com

.EXAMPLE
    .\Export-GpoSecurityEvidence.ps1 `
        -InheritanceQueryDelayMs 500 `
        -InheritanceQueryRetryCount 3 `
        -MaxGroupMembersToDisplay 100

.EXAMPLE
    .\Export-GpoSecurityEvidence.ps1 -ResolveGroupMembership:$false
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (
        Join-Path -Path $PWD -ChildPath (
            "GPO-Security-Evidence-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
        )
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DomainController,

    [Parameter()]
    [ValidateRange(0, 60000)]
    [int]$InheritanceQueryDelayMs = 250,

    [Parameter()]
    [ValidateRange(0, 10)]
    [int]$InheritanceQueryRetryCount = 2,

    [Parameter()]
    [ValidateRange(0, 60000)]
    [int]$GpoQueryDelayMs = 50,

    [Parameter()]
    [bool]$ResolveGroupMembership = $true,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxGroupMembersToDisplay = 50,

    [Parameter()]
    [ValidateRange(0, 60000)]
    [int]$GroupMembershipQueryDelayMs = 100,

    [Parameter()]
    [ValidateRange(1, 25)]
    [int]$MaxGroupNestingDepth = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

###########################################################################
# Helper functions
###########################################################################

function Write-AuditLog {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
}

function New-SafeFileName {
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Name
    )

    $InvalidCharacters = [System.IO.Path]::GetInvalidFileNameChars()
    $SafeName = $Name

    foreach ($Character in $InvalidCharacters) {
        $SafeName = $SafeName.Replace([string]$Character, "_")
    }

    if ([string]::IsNullOrWhiteSpace($SafeName)) {
        return "Unnamed"
    }

    return $SafeName
}

function ConvertTo-StringValue {
    param (
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [string]$Value
}

function ConvertTo-TimeSpanDays {
    <#
        Converts a TimeSpan-typed password policy value to a number of
        days, rounded to two decimals. A value of 0 means "not set /
        never" in Active Directory password policy semantics.
    #>
    param (
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 0
    }

    try {
        return [Math]::Round(([TimeSpan]$Value).TotalDays, 2)
    }
    catch {
        return 0
    }
}

function ConvertTo-TimeSpanMinutes {
    param (
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 0
    }

    try {
        return [Math]::Round(([TimeSpan]$Value).TotalMinutes, 2)
    }
    catch {
        return 0
    }
}

function Get-InfRegistryValue {
    param (
        [Parameter(Mandatory)]
        [string[]]$Content,

        [Parameter(Mandatory)]
        [string]$RegistryPath,

        [Parameter(Mandatory)]
        [string]$ValueName
    )

    $Target = "{0}\{1}" -f $RegistryPath.TrimEnd("\"), $ValueName
    $InRegistrySection = $false

    foreach ($Line in $Content) {
        $TrimmedLine = $Line.Trim()

        if ($TrimmedLine -match '^\[(.+)\]$') {
            $SectionName = $Matches[1]
            $InRegistrySection = (
                $SectionName -ieq "Registry Values"
            )

            continue
        }

        if (-not $InRegistrySection) {
            continue
        }

        if (
            [string]::IsNullOrWhiteSpace($TrimmedLine) -or
            $TrimmedLine.StartsWith(";")
        ) {
            continue
        }

        $SeparatorIndex = $TrimmedLine.IndexOf("=")

        if ($SeparatorIndex -lt 1) {
            continue
        }

        $ConfiguredName = $TrimmedLine.Substring(
            0,
            $SeparatorIndex
        ).Trim()

        if ($ConfiguredName -ine $Target) {
            continue
        }

        $RawData = $TrimmedLine.Substring(
            $SeparatorIndex + 1
        ).Trim()

        $DataParts = $RawData -split ",", 2
        $RegistryType = $DataParts[0]
        $RegistryData = ""

        if ($DataParts.Count -gt 1) {
            $RegistryData = $DataParts[1].Trim().Trim('"')
        }

        return [PSCustomObject]@{
            Found        = $true
            RegistryPath = $RegistryPath
            ValueName    = $ValueName
            RegistryType = $RegistryType
            RegistryData = $RegistryData
            RawEntry     = $TrimmedLine
        }
    }

    return [PSCustomObject]@{
        Found        = $false
        RegistryPath = $RegistryPath
        ValueName    = $ValueName
        RegistryType = ""
        RegistryData = ""
        RawEntry     = ""
    }
}

function Get-NtlmInterpretation {
    param (
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return [PSCustomObject]@{
            Status         = "Not configured"
            ClientBehavior = "Not determined from this GPO"
            ServerBehavior = "Not determined from this GPO"
            AuditConclusion = "This GPO does not explicitly configure LmCompatibilityLevel"
        }
    }

    $IntegerValue = 0

    if (-not [int]::TryParse([string]$Value, [ref]$IntegerValue)) {
        return [PSCustomObject]@{
            Status          = "Unknown"
            ClientBehavior  = "Unrecognized value"
            ServerBehavior  = "Unrecognized value"
            AuditConclusion = "Manual review required"
        }
    }

    switch ($IntegerValue) {
        0 {
            return [PSCustomObject]@{
                Status          = "Insecure"
                ClientBehavior  = "Sends LM and NTLM responses"
                ServerBehavior  = "Accepts LM, NTLM and NTLMv2"
                AuditConclusion = "NTLMv1 is allowed"
            }
        }

        1 {
            return [PSCustomObject]@{
                Status          = "Insecure"
                ClientBehavior  = "Sends LM and NTLM; uses NTLMv2 session security when negotiated"
                ServerBehavior  = "Accepts LM, NTLM and NTLMv2"
                AuditConclusion = "NTLMv1 is allowed"
            }
        }

        2 {
            return [PSCustomObject]@{
                Status          = "Insecure"
                ClientBehavior  = "Sends NTLM responses"
                ServerBehavior  = "Accepts LM, NTLM and NTLMv2"
                AuditConclusion = "NTLMv1 is allowed"
            }
        }

        3 {
            return [PSCustomObject]@{
                Status          = "Partial protection"
                ClientBehavior  = "Sends NTLMv2 responses only"
                ServerBehavior  = "Accepts LM, NTLM and NTLMv2"
                AuditConclusion = "Outbound NTLMv1 is prevented, but inbound NTLMv1 may still be accepted"
            }
        }

        4 {
            return [PSCustomObject]@{
                Status          = "Partial protection"
                ClientBehavior  = "Sends NTLMv2 responses only"
                ServerBehavior  = "Refuses LM but accepts NTLM and NTLMv2"
                AuditConclusion = "Outbound NTLMv1 is prevented, but inbound NTLMv1 may still be accepted"
            }
        }

        5 {
            return [PSCustomObject]@{
                Status          = "Enforced"
                ClientBehavior  = "Sends NTLMv2 responses only"
                ServerBehavior  = "Refuses LM and NTLM; accepts NTLMv2"
                AuditConclusion = "LM and NTLMv1 are prevented for both outbound and inbound authentication"
            }
        }

        default {
            return [PSCustomObject]@{
                Status          = "Unknown"
                ClientBehavior  = "Unknown"
                ServerBehavior  = "Unknown"
                AuditConclusion = "LmCompatibilityLevel is outside the expected range of 0 through 5"
            }
        }
    }
}

function Get-XmlText {
    param (
        [Parameter()]
        $Node,

        [Parameter(Mandatory)]
        [string]$ChildLocalName
    )

    if ($null -eq $Node) {
        return ""
    }

    $Child = $Node.SelectSingleNode(
        "./*[local-name()='$ChildLocalName']"
    )

    if ($null -eq $Child) {
        return ""
    }

    return $Child.InnerText
}

function Get-FindingSeverity {
    <#
        Classifies a configured setting as:
          secure   - the setting fully mitigates the weakness
          partial  - the setting partially mitigates the weakness
          insecure - the setting does not mitigate the weakness
          unknown  - the value could not be classified
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter()]
        [AllowEmptyString()]
        [string]$RegistryData,

        [Parameter()]
        [bool]$Enforced
    )

    if ($Category -eq "SMB signing") {
        if ($Enforced) {
            return [PSCustomObject]@{ Severity = "secure"; Label = "Signing required" }
        }

        return [PSCustomObject]@{ Severity = "insecure"; Label = "Signing not required" }
    }

    if ($Category -eq "NTLMv1") {
        switch ($RegistryData) {
            "5" { return [PSCustomObject]@{ Severity = "secure"; Label = "LM/NTLMv1 refused" } }
            "4" { return [PSCustomObject]@{ Severity = "partial"; Label = "Outbound NTLMv1 prevented only" } }
            "3" { return [PSCustomObject]@{ Severity = "partial"; Label = "Outbound NTLMv1 prevented only" } }
            "2" { return [PSCustomObject]@{ Severity = "insecure"; Label = "NTLMv1 allowed" } }
            "1" { return [PSCustomObject]@{ Severity = "insecure"; Label = "NTLMv1 allowed" } }
            "0" { return [PSCustomObject]@{ Severity = "insecure"; Label = "NTLMv1 allowed" } }
            default { return [PSCustomObject]@{ Severity = "unknown"; Label = "Unrecognized value" } }
        }
    }

    return [PSCustomObject]@{ Severity = "unknown"; Label = "Unclassified" }
}

function Get-RecursiveGroupMembership {
    <#
        Resolves a group's membership recursively using the "Members"
        attribute rather than Get-ADGroupMember, so that a single
        unresolvable member (for example a foreign security principal
        from a trusted forest, or an orphaned member reference) does not
        abort enumeration of the whole group.

        Returns:
          DirectMembers - the immediate members of the group
          NestedGroups  - every group encountered at any depth, together
                          with the nesting path through which it was
                          reached ("Direct" or "GroupA > GroupB")
          Members       - a flattened, de-duplicated list of all
                          non-group members (users, computers, gMSAs,
                          unresolved principals) with the nesting path
                          recorded per member. When a member is reachable
                          through multiple paths, the first path found is
                          recorded.

        Cycles in group nesting are detected and broken via a visited-set;
        depth is additionally capped by -MaxDepth as a safety net.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$GroupIdentity,

        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter()]
        [ValidateRange(0, 60000)]
        [int]$DelayMs = 0,

        [Parameter()]
        [ValidateRange(1, 25)]
        [int]$MaxDepth = 10
    )

    $Result = [PSCustomObject]@{
        Found         = $false
        GroupName     = ""
        GroupDn       = ""
        GroupSid      = ""
        Error         = ""
        DirectMembers = @()
        NestedGroups  = @()
        Members       = @()
    }

    try {
        $Group = Get-ADGroup `
            -Identity $GroupIdentity `
            -Server $Server `
            -Properties Members `
            -ErrorAction Stop
    }
    catch {
        $Result.Error = $_.Exception.Message
        return $Result
    }

    $Result.Found = $true
    $Result.GroupName = [string]$Group.Name
    $Result.GroupDn = [string]$Group.DistinguishedName
    $Result.GroupSid = [string]$Group.SID.Value

    $VisitedGroups = @{}
    $VisitedGroups[[string]$Group.DistinguishedName] = $true

    $MemberMap = @{}
    $DirectMembers = New-Object System.Collections.Generic.List[object]
    $NestedGroups = New-Object System.Collections.Generic.List[object]

    $Queue = New-Object System.Collections.Generic.Queue[object]
    $Queue.Enqueue(
        [PSCustomObject]@{
            MemberDns = @($Group.Members)
            Via       = ""
            Depth     = 0
        }
    )

    while ($Queue.Count -gt 0) {
        $Current = $Queue.Dequeue()

        foreach ($MemberDn in @($Current.MemberDns)) {
            $MemberDnString = [string]$MemberDn
            $MemberName = ""
            $MemberSam = ""
            $MemberClass = ""
            $MemberSid = ""
            $Resolved = $true

            try {
                $MemberObject = Get-ADObject `
                    -Identity $MemberDnString `
                    -Server $Server `
                    -Properties objectClass, sAMAccountName, objectSid `
                    -ErrorAction Stop

                $MemberName = [string]$MemberObject.Name
                $MemberClass = [string]$MemberObject.objectClass

                if (
                    $MemberObject.PSObject.Properties.Match("sAMAccountName").Count -gt 0 -and
                    $null -ne $MemberObject.sAMAccountName
                ) {
                    $MemberSam = [string]$MemberObject.sAMAccountName
                }

                if (
                    $MemberObject.PSObject.Properties.Match("objectSid").Count -gt 0 -and
                    $null -ne $MemberObject.objectSid
                ) {
                    $MemberSid = [string]$MemberObject.objectSid.Value
                }
            }
            catch {
                # For example a foreign security principal from a trusted
                # forest, a member in another domain of the forest that the
                # selected DC cannot resolve, or an orphaned member
                # reference. Record it as unresolved instead of failing
                # the whole group.
                $Resolved = $false
                $MemberClass = "unresolved"
                $MemberName = (($MemberDnString -split ",", 2)[0]) -replace '^CN=', ''
            }

            $ViaLabel = "Direct"

            if (-not [string]::IsNullOrEmpty([string]$Current.Via)) {
                $ViaLabel = [string]$Current.Via
            }

            if ($Current.Depth -eq 0) {
                $DirectMembers.Add(
                    [PSCustomObject]@{
                        Name           = $MemberName
                        SamAccountName = $MemberSam
                        ObjectClass    = $MemberClass
                        Dn             = $MemberDnString
                    }
                )
            }

            if ($MemberClass -ieq "group") {
                $NestedGroupError = ""
                $NestedGroupExpanded = $false

                if (
                    -not $VisitedGroups.ContainsKey($MemberDnString) -and
                    $Current.Depth -lt $MaxDepth
                ) {
                    $VisitedGroups[$MemberDnString] = $true

                    try {
                        $NestedGroup = Get-ADGroup `
                            -Identity $MemberDnString `
                            -Server $Server `
                            -Properties Members `
                            -ErrorAction Stop

                        $NextVia = $MemberName

                        if (-not [string]::IsNullOrEmpty([string]$Current.Via)) {
                            $NextVia = "{0} > {1}" -f [string]$Current.Via, $MemberName
                        }

                        $Queue.Enqueue(
                            [PSCustomObject]@{
                                MemberDns = @($NestedGroup.Members)
                                Via       = $NextVia
                                Depth     = ($Current.Depth + 1)
                            }
                        )

                        $NestedGroupExpanded = $true
                    }
                    catch {
                        $NestedGroupError = $_.Exception.Message
                    }
                }

                $NestedGroups.Add(
                    [PSCustomObject]@{
                        Name     = $MemberName
                        Dn       = $MemberDnString
                        Via      = $ViaLabel
                        Expanded = $NestedGroupExpanded
                        Error    = $NestedGroupError
                    }
                )
            }
            else {
                if (-not $MemberMap.ContainsKey($MemberDnString)) {
                    $MemberMap[$MemberDnString] = [PSCustomObject]@{
                        Name           = $MemberName
                        SamAccountName = $MemberSam
                        ObjectClass    = $MemberClass
                        Sid            = $MemberSid
                        Dn             = $MemberDnString
                        Via            = $ViaLabel
                        Resolved       = $Resolved
                    }
                }
            }
        }

        if ($DelayMs -gt 0) {
            Start-Sleep -Milliseconds $DelayMs
        }
    }

    $Result.DirectMembers = @($DirectMembers.ToArray())
    $Result.NestedGroups = @($NestedGroups.ToArray())
    $Result.Members = @($MemberMap.Values | Sort-Object Name)

    return $Result
}

###########################################################################
# Validate required modules
###########################################################################

foreach ($RequiredModule in @("ActiveDirectory", "GroupPolicy")) {
    if (-not (Get-Module -ListAvailable -Name $RequiredModule)) {
        throw "Required module '$RequiredModule' is not installed."
    }

    Import-Module $RequiredModule -ErrorAction Stop
}

###########################################################################
# Prepare evidence directories
###########################################################################

$Directories = @{
    Root       = $OutputPath
    GpoHtml    = Join-Path $OutputPath "GPO-Reports-HTML"
    GpoXml     = Join-Path $OutputPath "GPO-Reports-XML"
    RawPolicy  = Join-Path $OutputPath "Raw-GptTmpl-INF"
    Csv        = Join-Path $OutputPath "CSV"
    Metadata   = Join-Path $OutputPath "Metadata"
}

foreach ($Directory in $Directories.Values) {
    if (-not (Test-Path -LiteralPath $Directory)) {
        $null = New-Item `
            -Path $Directory `
            -ItemType Directory `
            -Force
    }
}

$TranscriptPath = Join-Path $Directories.Metadata "PowerShell-Transcript.txt"
Start-Transcript -Path $TranscriptPath -Force | Out-Null

try {
    Write-AuditLog "Starting Group Policy security evidence collection."

    #######################################################################
    # Determine domain and domain controller
    #######################################################################

    if ($DomainController) {
        $Domain = Get-ADDomain -Server $DomainController
    }
    else {
        $Domain = Get-ADDomain

        # Get-ADDomainController -Discover has been observed to return a
        # HostName property typed as ADPropertyValueCollection rather than
        # a plain string in some environments, which Get-GPO/-Server then
        # rejects. Get-ADDomain's PDCEmulator property is always a plain
        # string, so it is used here instead - avoiding both the type
        # issue and an extra AD query.
        $DomainController = [string]$Domain.PDCEmulator
    }

    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        throw "Could not determine a domain controller to use. Specify one explicitly with -DomainController."
    }

    $DomainDnsRoot = $Domain.DNSRoot
    $DomainDistinguishedName = $Domain.DistinguishedName

    Write-AuditLog "Domain: $DomainDnsRoot"
    Write-AuditLog "Domain controller: $DomainController"
    Write-AuditLog "Inheritance query delay: ${InheritanceQueryDelayMs}ms, retries: $InheritanceQueryRetryCount"
    Write-AuditLog "Group membership resolution: $ResolveGroupMembership"

    #######################################################################
    # Record collection metadata
    #######################################################################

    $CollectorOperatingSystem = Get-CimInstance `
        -ClassName Win32_OperatingSystem

    $Metadata = [PSCustomObject]@{
        CollectionStart       = Get-Date
        CollectorComputer     = $env:COMPUTERNAME
        CollectorUser         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        CollectorOS           = $CollectorOperatingSystem.Caption
        CollectorOSVersion    = $CollectorOperatingSystem.Version
        PowerShellVersion     = $PSVersionTable.PSVersion.ToString()
        Domain                = $DomainDnsRoot
        DomainDistinguishedName = $DomainDistinguishedName
        DomainController      = $DomainController
        Forest                = $Domain.Forest
        DomainMode            = $Domain.DomainMode
        PDCEmulator           = $Domain.PDCEmulator
        InheritanceQueryDelayMs      = $InheritanceQueryDelayMs
        InheritanceQueryRetryCount   = $InheritanceQueryRetryCount
        GpoQueryDelayMs              = $GpoQueryDelayMs
        ResolveGroupMembership       = $ResolveGroupMembership
        MaxGroupMembersToDisplay     = $MaxGroupMembersToDisplay
        GroupMembershipQueryDelayMs  = $GroupMembershipQueryDelayMs
        MaxGroupNestingDepth         = $MaxGroupNestingDepth
    }

    $Metadata |
        Export-Csv `
            -Path (Join-Path $Directories.Metadata "Collection-Metadata.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Registry targets
    #######################################################################

    $PolicyTargets = @(
        [PSCustomObject]@{
            Category     = "SMB signing"
            Setting      = "SMB server signing required"
            RegistryPath = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"
            ValueName    = "RequireSecuritySignature"
        },
        [PSCustomObject]@{
            Category     = "SMB signing"
            Setting      = "SMB client signing required"
            RegistryPath = "MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
            ValueName    = "RequireSecuritySignature"
        },
        [PSCustomObject]@{
            Category     = "NTLMv1"
            Setting      = "LAN Manager authentication level"
            RegistryPath = "MACHINE\System\CurrentControlSet\Control\Lsa"
            ValueName    = "LmCompatibilityLevel"
        }
    )

    #######################################################################
    # Retrieve all GPOs
    #######################################################################

    $Gpos = @(
        Get-GPO `
            -All `
            -Domain $DomainDnsRoot `
            -Server $DomainController |
        Sort-Object DisplayName
    )

    Write-AuditLog "Found $($Gpos.Count) Group Policy Objects."

    $PolicyResults = New-Object System.Collections.Generic.List[object]
    $RelevantGpoIds = New-Object System.Collections.Generic.HashSet[string]
    $GptTmplAccessErrors = New-Object System.Collections.Generic.List[object]

    #######################################################################
    # Inspect every GPO
    #######################################################################

    foreach ($Gpo in $Gpos) {
        $GpoGuid = $Gpo.Id.ToString()
        $SafeGpoName = New-SafeFileName -Name $Gpo.DisplayName
        $ReportBaseName = "{0}--{1}" -f $SafeGpoName, $GpoGuid

        Write-AuditLog "Inspecting GPO: $($Gpo.DisplayName)"

        $XmlReportPath = Join-Path `
            $Directories.GpoXml `
            ($ReportBaseName + ".xml")

        $HtmlReportPath = Join-Path `
            $Directories.GpoHtml `
            ($ReportBaseName + ".html")

        Get-GPOReport `
            -Guid $Gpo.Id `
            -Domain $DomainDnsRoot `
            -Server $DomainController `
            -ReportType Xml `
            -Path $XmlReportPath

        Get-GPOReport `
            -Guid $Gpo.Id `
            -Domain $DomainDnsRoot `
            -Server $DomainController `
            -ReportType Html `
            -Path $HtmlReportPath

        # Use the explicitly selected domain controller for SYSVOL too.
        # This keeps GPO metadata and raw policy evidence tied to the same DC.
        $GptTmplUncPath = (
            "\\{0}\SYSVOL\{1}\Policies\{{{2}}}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -f
            $DomainController,
            $DomainDnsRoot,
            $GpoGuid
        )

        $InfContent = @()
        $InfAvailable = $false
        $RawInfPath = ""

        try {
            if (Test-Path -LiteralPath $GptTmplUncPath) {
                $InfContent = @(
                    Get-Content `
                        -LiteralPath $GptTmplUncPath `
                        -Encoding Unicode
                )

                $InfAvailable = $true
                $RawInfPath = Join-Path `
                    $Directories.RawPolicy `
                    ($ReportBaseName + "--GptTmpl.inf")

                Copy-Item `
                    -LiteralPath $GptTmplUncPath `
                    -Destination $RawInfPath `
                    -Force
            }
        }
        catch {
            # SYSVOL access can fail for an individual GPO (e.g. delegated
            # ACLs restricting read access, DFS-R replication lag, or a
            # transient share issue) without anything being wrong with the
            # rest of the domain. Treat this GPO's GptTmpl.inf as
            # unavailable and keep going, rather than letting
            # Set-StrictMode/$ErrorActionPreference abort the whole run.
            Write-AuditLog `
                -Level "WARNING" `
                -Message (
                    "Could not access GptTmpl.inf for GPO '{0}': {1}" -f
                    $Gpo.DisplayName,
                    $_.Exception.Message
                )

            $InfAvailable = $false
            $InfContent = @()
            $RawInfPath = ""

            $GptTmplAccessErrors.Add(
                [PSCustomObject]@{
                    GpoName    = $Gpo.DisplayName
                    GpoId      = $GpoGuid
                    SourceFile = $GptTmplUncPath
                    Error      = $_.Exception.Message
                }
            )
        }

        foreach ($Target in $PolicyTargets) {
            if ($InfAvailable) {
                $ConfiguredValue = Get-InfRegistryValue `
                    -Content $InfContent `
                    -RegistryPath $Target.RegistryPath `
                    -ValueName $Target.ValueName
            }
            else {
                $ConfiguredValue = [PSCustomObject]@{
                    Found        = $false
                    RegistryPath = $Target.RegistryPath
                    ValueName    = $Target.ValueName
                    RegistryType = ""
                    RegistryData = ""
                    RawEntry     = ""
                }
            }

            if (-not $ConfiguredValue.Found) {
                continue
            }

            $null = $RelevantGpoIds.Add($GpoGuid)

            $Enforced = $false
            $Interpretation = ""
            $ClientBehavior = ""
            $ServerBehavior = ""

            if ($Target.Category -eq "SMB signing") {
                $Enforced = (
                    [string]$ConfiguredValue.RegistryData -eq "1"
                )

                if ($Enforced) {
                    $Interpretation = "SMB signing is required"
                }
                else {
                    $Interpretation = "SMB signing is not required by this setting"
                }
            }
            elseif ($Target.Category -eq "NTLMv1") {
                $NtlmResult = Get-NtlmInterpretation `
                    -Value $ConfiguredValue.RegistryData

                $Interpretation = $NtlmResult.AuditConclusion
                $ClientBehavior = $NtlmResult.ClientBehavior
                $ServerBehavior = $NtlmResult.ServerBehavior
                $Enforced = (
                    [string]$ConfiguredValue.RegistryData -eq "5"
                )
            }

            $PolicyResults.Add(
                [PSCustomObject]@{
                    GpoName          = $Gpo.DisplayName
                    GpoId            = $GpoGuid
                    GpoStatus        = $Gpo.GpoStatus
                    CreationTime     = $Gpo.CreationTime
                    ModificationTime = $Gpo.ModificationTime
                    Category         = $Target.Category
                    Setting          = $Target.Setting
                    RegistryPath     = $Target.RegistryPath
                    ValueName        = $Target.ValueName
                    RegistryType     = $ConfiguredValue.RegistryType
                    RegistryData     = $ConfiguredValue.RegistryData
                    Enforced         = $Enforced
                    Interpretation   = $Interpretation
                    ClientBehavior   = $ClientBehavior
                    ServerBehavior   = $ServerBehavior
                    RawEntry         = $ConfiguredValue.RawEntry
                    SourceFile       = $GptTmplUncPath
                    HtmlReport       = $HtmlReportPath
                    XmlReport        = $XmlReportPath
                }
            )
        }

        Start-Sleep -Milliseconds $GpoQueryDelayMs
    }

    #######################################################################
    # Export configured security settings
    #######################################################################

    $PolicyResultsPath = Join-Path `
        $Directories.Csv `
        "Configured-Security-Policies.csv"

    $PolicyResults |
        Sort-Object Category, GpoName, Setting |
        Export-Csv `
            -Path $PolicyResultsPath `
            -NoTypeInformation `
            -Encoding UTF8

    $GptTmplAccessErrors |
        Sort-Object GpoName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "GptTmpl-Access-Errors.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    if ($GptTmplAccessErrors.Count -gt 0) {
        Write-AuditLog `
            -Level "WARNING" `
            -Message (
                "GptTmpl.inf could not be read for {0} GPO(s). See CSV\GptTmpl-Access-Errors.csv. Configured-setting evidence for those GPOs is incomplete." -f
                $GptTmplAccessErrors.Count
            )
    }

    #######################################################################
    # Collect direct links from GPO XML reports
    #
    # This method uses XML element names and distinguished names rather
    # than localized Group Policy display text.
    #######################################################################

    $DirectLinkResults = New-Object System.Collections.Generic.List[object]

    foreach ($Gpo in $Gpos) {
        $GpoGuid = $Gpo.Id.ToString()

        if (-not $RelevantGpoIds.Contains($GpoGuid)) {
            continue
        }

        $SafeGpoName = New-SafeFileName -Name $Gpo.DisplayName
        $ReportBaseName = "{0}--{1}" -f $SafeGpoName, $GpoGuid
        $XmlReportPath = Join-Path `
            $Directories.GpoXml `
            ($ReportBaseName + ".xml")

        [xml]$GpoReportXml = Get-Content `
            -LiteralPath $XmlReportPath `
            -Raw

        $LinkNodes = @(
            $GpoReportXml.SelectNodes(
                "//*[local-name()='LinksTo']/*[local-name()='SOM']"
            )
        )

        if ($LinkNodes.Count -eq 0) {
            $DirectLinkResults.Add(
                [PSCustomObject]@{
                    GpoName      = $Gpo.DisplayName
                    GpoId        = $GpoGuid
                    LinkTarget   = ""
                    Enabled      = ""
                    Enforced     = ""
                    LinkStatus   = "No direct links found"
                }
            )

            continue
        }

        foreach ($LinkNode in $LinkNodes) {
            $LinkTarget = Get-XmlText `
                -Node $LinkNode `
                -ChildLocalName "Path"

            $LinkEnabled = Get-XmlText `
                -Node $LinkNode `
                -ChildLocalName "Enabled"

            $LinkEnforced = Get-XmlText `
                -Node $LinkNode `
                -ChildLocalName "NoOverride"

            $DirectLinkResults.Add(
                [PSCustomObject]@{
                    GpoName      = $Gpo.DisplayName
                    GpoId        = $GpoGuid
                    LinkTarget   = $LinkTarget
                    Enabled      = $LinkEnabled
                    Enforced     = $LinkEnforced
                    LinkStatus   = "Direct link"
                }
            )
        }
    }

    $DirectLinkResults |
        Sort-Object GpoName, LinkTarget |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Relevant-GPO-Direct-Links.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Collect structural effective scope
    #
    # InheritedGpoLinks represents the GPOs structurally applicable to a
    # domain or OU after link enablement, enforcement and inheritance
    # blocking have been evaluated.
    #
    # Security filtering and WMI filtering must still be evaluated
    # separately.
    #
    # Get-GPInheritance is called once per target below. A short delay is
    # inserted after every call, and failed calls are retried with a longer
    # backoff, to reduce transient "Could not evaluate inheritance" errors
    # caused by repeated rapid calls against the GPMC/ADWS layer. Targets
    # that still fail after all retries are recorded as evidence gaps
    # rather than silently skipped.
    #######################################################################

    $ScopeTargets = New-Object System.Collections.Generic.List[string]
    $ScopeTargets.Add($DomainDistinguishedName)

    $OrganizationalUnits = @(
        Get-ADOrganizationalUnit `
            -Filter * `
            -Server $DomainController `
            -Properties DistinguishedName |
        Sort-Object DistinguishedName
    )

    foreach ($OrganizationalUnit in $OrganizationalUnits) {
        $ScopeTargets.Add($OrganizationalUnit.DistinguishedName)
    }

    Write-AuditLog (
        "Evaluating Group Policy inheritance for {0} domain/OU targets." -f
        $ScopeTargets.Count
    )

    $StructuralScopeResults = New-Object System.Collections.Generic.List[object]
    $InheritanceErrorResults = New-Object System.Collections.Generic.List[object]

    foreach ($ScopeTarget in $ScopeTargets) {
        $Attempt = 0
        $Succeeded = $false
        $LastErrorMessage = ""
        $Inheritance = $null

        do {
            $Attempt++

            try {
                $Inheritance = Get-GPInheritance `
                    -Target $ScopeTarget `
                    -Domain $DomainDnsRoot `
                    -Server $DomainController

                # Get-GPInheritance occasionally returns an object that is
                # missing expected members (a known transient GPMC/ADWS
                # issue). Validate it here, inside the try block, so an
                # incomplete object is treated the same as any other
                # failure - retried, and eventually logged as an evidence
                # gap - instead of throwing an unhandled
                # PropertyNotFoundStrict error later that would abort the
                # whole script under Set-StrictMode.
                if ($null -eq $Inheritance) {
                    throw "Get-GPInheritance returned no object for this target."
                }

                $InheritancePropertyNames = @(
                    $Inheritance.PSObject.Properties.Name
                )

                # Depending on the installed GroupPolicy/GPMC version, the
                # container identity can be exposed as ContainerName, Name,
                # or Path. Accept all three representations.
                $HasContainerIdentity = (
                    $InheritancePropertyNames -contains "ContainerName" -or
                    $InheritancePropertyNames -contains "Name" -or
                    $InheritancePropertyNames -contains "Path"
                )

                $HasInheritedLinks = (
                    $InheritancePropertyNames -contains "InheritedGpoLinks"
                )

                if (-not $HasContainerIdentity -or -not $HasInheritedLinks) {
                    $AvailableProperties = $InheritancePropertyNames -join ", "

                    throw (
                        "Get-GPInheritance returned an object without the required properties " +
                        "for target '$ScopeTarget'. Available properties: $AvailableProperties"
                    )
                }

                $Succeeded = $true
            }
            catch {
                $LastErrorMessage = $_.Exception.Message

                if ($Attempt -le $InheritanceQueryRetryCount) {
                    Write-AuditLog `
                        -Level "WARNING" `
                        -Message (
                            "Retry {0} of {1} for '{2}' after error: {3}" -f
                            $Attempt,
                            $InheritanceQueryRetryCount,
                            $ScopeTarget,
                            $LastErrorMessage
                        )

                    Start-Sleep -Milliseconds ($InheritanceQueryDelayMs * 4)
                }
            }
        } while (-not $Succeeded -and $Attempt -le $InheritanceQueryRetryCount)

        if ($Succeeded) {
            $ResolvedContainerName = ""
            $ResolvedContainerType = ""

            if ($Inheritance.PSObject.Properties.Match("ContainerName").Count -gt 0) {
                $ResolvedContainerName = [string]$Inheritance.ContainerName
            }
            elseif ($Inheritance.PSObject.Properties.Match("Name").Count -gt 0) {
                $ResolvedContainerName = [string]$Inheritance.Name
            }
            elseif ($Inheritance.PSObject.Properties.Match("Path").Count -gt 0) {
                $ResolvedContainerName = [string]$Inheritance.Path
            }

            if ($Inheritance.PSObject.Properties.Match("ContainerType").Count -gt 0) {
                $ResolvedContainerType = [string]$Inheritance.ContainerType
            }

            $InheritedLinks = @($Inheritance.InheritedGpoLinks)

            foreach ($InheritedLink in $InheritedLinks) {
                try {
                    if (
                        $null -eq $InheritedLink -or
                        -not ($InheritedLink.PSObject.Properties.Match("GpoId").Count)
                    ) {
                        Write-AuditLog `
                            -Level "WARNING" `
                            -Message "Skipped a malformed InheritedGpoLinks entry for '$ScopeTarget'."

                        continue
                    }

                    $InheritedGpoGuid = $InheritedLink.GpoId.ToString()

                    if (-not $RelevantGpoIds.Contains($InheritedGpoGuid)) {
                        continue
                    }

                    $StructuralScopeResults.Add(
                        [PSCustomObject]@{
                            ScopeTarget          = $ScopeTarget
                            ContainerName        = $ResolvedContainerName
                            ContainerType        = $ResolvedContainerType
                            InheritanceBlocked   = $Inheritance.GpoInheritanceBlocked
                            GpoName              = $InheritedLink.DisplayName
                            GpoId                = $InheritedGpoGuid
                            LinkOrder            = $InheritedLink.Order
                            LinkEnabled          = $InheritedLink.Enabled
                            LinkEnforced         = $InheritedLink.Enforced
                            StructuralResult     = "Included in InheritedGpoLinks"
                            SecurityFilterNote   = "Security and WMI filtering not evaluated in this row"
                        }
                    )
                }
                catch {
                    Write-AuditLog `
                        -Level "WARNING" `
                        -Message (
                            "Skipped a malformed GPO link entry for '{0}': {1}" -f
                            $ScopeTarget,
                            $_.Exception.Message
                        )
                }
            }
        }
        else {
            Write-AuditLog `
                -Level "WARNING" `
                -Message (
                    "Could not evaluate inheritance for '{0}' after {1} attempt(s): {2}" -f
                    $ScopeTarget,
                    $Attempt,
                    $LastErrorMessage
                )

            $InheritanceErrorResults.Add(
                [PSCustomObject]@{
                    ScopeTarget = $ScopeTarget
                    Attempts    = $Attempt
                    Error       = $LastErrorMessage
                }
            )
        }

        Start-Sleep -Milliseconds $InheritanceQueryDelayMs
    }

    $StructuralScopeResults |
        Sort-Object GpoName, ScopeTarget |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Relevant-GPO-Structural-Scope.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    $InheritanceErrorResults |
        Sort-Object ScopeTarget |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Inheritance-Evaluation-Errors.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    if ($InheritanceErrorResults.Count -gt 0) {
        Write-AuditLog `
            -Level "WARNING" `
            -Message (
                "{0} of {1} domain/OU targets could not be evaluated for inheritance. See CSV\Inheritance-Evaluation-Errors.csv." -f
                $InheritanceErrorResults.Count,
                $ScopeTargets.Count
            )
    }

    #######################################################################
    # Collect GPO permissions and security filtering evidence
    #######################################################################

    $PermissionResults = New-Object System.Collections.Generic.List[object]

    foreach ($Gpo in $Gpos) {
        $GpoGuid = $Gpo.Id.ToString()

        if (-not $RelevantGpoIds.Contains($GpoGuid)) {
            continue
        }

        $Permissions = @(
            Get-GPPermission `
                -Guid $Gpo.Id `
                -All `
                -Domain $DomainDnsRoot `
                -Server $DomainController
        )

        foreach ($Permission in $Permissions) {
            $PermissionResults.Add(
                [PSCustomObject]@{
                    GpoName             = $Gpo.DisplayName
                    GpoId               = $GpoGuid
                    TrusteeName         = $Permission.Trustee.Name
                    TrusteeDomain       = $Permission.Trustee.Domain
                    TrusteeSid          = $Permission.Trustee.Sid.Value
                    TrusteeType         = $Permission.Trustee.SidType
                    Permission          = $Permission.Permission
                    Inherited           = $Permission.Inherited
                    AppliesToGpo        = (
                        $Permission.Permission -eq "GpoApply"
                    )
                }
            )
        }
    }

    $PermissionResults |
        Sort-Object GpoName, Permission, TrusteeName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Relevant-GPO-Permissions.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Resolve group membership for security filtering trustees
    #
    # This lets the dashboard show, on hover, who is inside a group that a
    # GPO's settings are security-filtered to. Only trustees of type
    # "Group" with Apply permission are resolved; well-known/built-in
    # principals (e.g. Authenticated Users) are not AD group objects and
    # cannot be resolved this way.
    #######################################################################

    $GroupMembershipResults = New-Object System.Collections.Generic.List[object]
    $GroupMembershipCache = @{}

    if ($ResolveGroupMembership) {
        $UniqueGroupTrustees = @(
            $PermissionResults |
            Where-Object { $_.TrusteeType -eq "Group" -and $_.AppliesToGpo } |
            Select-Object TrusteeSid, TrusteeName -Unique
        )

        Write-AuditLog "Resolving membership for $($UniqueGroupTrustees.Count) security-filtering group(s)."

        foreach ($GroupTrustee in $UniqueGroupTrustees) {
            if (
                [string]::IsNullOrWhiteSpace($GroupTrustee.TrusteeSid) -or
                $GroupMembershipCache.ContainsKey($GroupTrustee.TrusteeSid)
            ) {
                continue
            }

            try {
                $Members = @(
                    Get-ADGroupMember `
                        -Identity $GroupTrustee.TrusteeSid `
                        -Server $DomainController `
                        -ErrorAction Stop |
                    Sort-Object Name
                )

                $DisplayMembers = @(
                    $Members |
                    Select-Object -First $MaxGroupMembersToDisplay |
                    ForEach-Object {
                        [PSCustomObject]@{
                            name = $_.Name
                            type = $_.objectClass
                        }
                    }
                )

                $GroupMembershipCache[$GroupTrustee.TrusteeSid] = [PSCustomObject]@{
                    resolved   = $true
                    totalCount = $Members.Count
                    members    = $DisplayMembers
                    truncated  = ($Members.Count -gt $MaxGroupMembersToDisplay)
                    error      = ""
                }

                if ($Members.Count -eq 0) {
                    $GroupMembershipResults.Add(
                        [PSCustomObject]@{
                            GroupTrusteeName = $GroupTrustee.TrusteeName
                            GroupTrusteeSid  = $GroupTrustee.TrusteeSid
                            MemberName       = ""
                            MemberType       = ""
                        }
                    )
                }
                else {
                    foreach ($Member in $Members) {
                        $GroupMembershipResults.Add(
                            [PSCustomObject]@{
                                GroupTrusteeName = $GroupTrustee.TrusteeName
                                GroupTrusteeSid  = $GroupTrustee.TrusteeSid
                                MemberName       = $Member.Name
                                MemberType       = $Member.objectClass
                            }
                        )
                    }
                }
            }
            catch {
                $GroupMembershipCache[$GroupTrustee.TrusteeSid] = [PSCustomObject]@{
                    resolved   = $false
                    totalCount = 0
                    members    = @()
                    truncated  = $false
                    error      = $_.Exception.Message
                }

                $GroupMembershipResults.Add(
                    [PSCustomObject]@{
                        GroupTrusteeName = $GroupTrustee.TrusteeName
                        GroupTrusteeSid  = $GroupTrustee.TrusteeSid
                        MemberName       = ""
                        MemberType       = ""
                    }
                )

                Write-AuditLog `
                    -Level "WARNING" `
                    -Message (
                        "Could not resolve membership for group '{0}': {1}" -f
                        $GroupTrustee.TrusteeName,
                        $_.Exception.Message
                    )
            }

            Start-Sleep -Milliseconds $GroupMembershipQueryDelayMs
        }
    }
    else {
        Write-AuditLog "Group membership resolution skipped (-ResolveGroupMembership:`$false)."
    }

    $GroupMembershipResults |
        Sort-Object GroupTrusteeName, MemberName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Relevant-GPO-Security-Filtering-Group-Members.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Collect WMI filter evidence
    #######################################################################

    $WmiFilterResults = New-Object System.Collections.Generic.List[object]

    foreach ($Gpo in $Gpos) {
        $GpoGuid = $Gpo.Id.ToString()

        if (-not $RelevantGpoIds.Contains($GpoGuid)) {
            continue
        }

        $WmiFilterName = ""
        $WmiFilterPath = ""

        try {
            if ($null -ne $Gpo.WmiFilter) {
                $WmiFilterName = ConvertTo-StringValue `
                    -Value $Gpo.WmiFilter.Name

                $WmiFilterPath = ConvertTo-StringValue `
                    -Value $Gpo.WmiFilter.Path
            }
        }
        catch {
            $WmiFilterName = "See XML/HTML GPO report"
            $WmiFilterPath = ""
        }

        $WmiFilterResults.Add(
            [PSCustomObject]@{
                GpoName       = $Gpo.DisplayName
                GpoId         = $GpoGuid
                WmiFilterName = $WmiFilterName
                WmiFilterPath = $WmiFilterPath
                ReviewReport  = (
                    "Review the corresponding XML or HTML report for complete WMI filter evidence"
                )
            }
        )
    }

    $WmiFilterResults |
        Sort-Object GpoName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Relevant-GPO-WMI-Filters.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Collect domain information and domain controller inventory
    #
    # This feeds the "Domain overview" cover tab of the dashboard and the
    # Domain-Information / Domain-Controllers CSV evidence files.
    #######################################################################

    Write-AuditLog "Collecting domain and domain controller information."

    $Forest = Get-ADForest -Server $DomainController

    $DomainControllerInventory = @(
        Get-ADDomainController `
            -Filter * `
            -Server $DomainController |
        Sort-Object HostName |
        ForEach-Object {
            [PSCustomObject]@{
                Name                   = ConvertTo-StringValue -Value $_.Name
                HostName               = ConvertTo-StringValue -Value $_.HostName
                IPv4Address            = ConvertTo-StringValue -Value $_.IPv4Address
                Site                   = ConvertTo-StringValue -Value $_.Site
                OperatingSystem        = ConvertTo-StringValue -Value $_.OperatingSystem
                OperatingSystemVersion = ConvertTo-StringValue -Value $_.OperatingSystemVersion
                IsGlobalCatalog        = [bool]$_.IsGlobalCatalog
                IsReadOnly             = [bool]$_.IsReadOnly
                OperationMasterRoles   = (
                    @($_.OperationMasterRoles | ForEach-Object { [string]$_ }) -join ", "
                )
            }
        }
    )

    Write-AuditLog "Found $($DomainControllerInventory.Count) domain controller(s)."

    $DomainControllerInventory |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Domain-Controllers.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    $DomainInformation = [PSCustomObject]@{
        DnsRoot               = $DomainDnsRoot
        NetBiosName           = ConvertTo-StringValue -Value $Domain.NetBIOSName
        DistinguishedName     = $DomainDistinguishedName
        DomainSid             = [string]$Domain.DomainSID.Value
        DomainMode            = ConvertTo-StringValue -Value $Domain.DomainMode
        ForestName            = ConvertTo-StringValue -Value $Forest.Name
        ForestMode            = ConvertTo-StringValue -Value $Forest.ForestMode
        PdcEmulator           = ConvertTo-StringValue -Value $Domain.PDCEmulator
        RidMaster             = ConvertTo-StringValue -Value $Domain.RIDMaster
        InfrastructureMaster  = ConvertTo-StringValue -Value $Domain.InfrastructureMaster
        SchemaMaster          = ConvertTo-StringValue -Value $Forest.SchemaMaster
        DomainNamingMaster    = ConvertTo-StringValue -Value $Forest.DomainNamingMaster
        DomainControllerCount = $DomainControllerInventory.Count
    }

    $DomainInformation |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Domain-Information.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Collect password policy evidence
    #
    # The default domain password policy is read via
    # Get-ADDefaultDomainPasswordPolicy; fine-grained password policies
    # (PSOs) are enumerated separately. Reading PSOs typically requires
    # Domain Admins-level permissions; failures are recorded as evidence
    # gaps rather than aborting the run.
    #######################################################################

    Write-AuditLog "Collecting password policy information."

    $DefaultPasswordPolicyDashboard = $null
    $DefaultPasswordPolicyError = ""

    try {
        $DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy `
            -Server $DomainController `
            -ErrorAction Stop

        $DefaultPasswordPolicyDashboard = [PSCustomObject]@{
            minPasswordLength           = [int]$DefaultPasswordPolicy.MinPasswordLength
            complexityEnabled           = [bool]$DefaultPasswordPolicy.ComplexityEnabled
            passwordHistoryCount        = [int]$DefaultPasswordPolicy.PasswordHistoryCount
            maxPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $DefaultPasswordPolicy.MaxPasswordAge
            minPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $DefaultPasswordPolicy.MinPasswordAge
            lockoutThreshold            = [int]$DefaultPasswordPolicy.LockoutThreshold
            lockoutDurationMinutes      = ConvertTo-TimeSpanMinutes -Value $DefaultPasswordPolicy.LockoutDuration
            lockoutObservationMinutes   = ConvertTo-TimeSpanMinutes -Value $DefaultPasswordPolicy.LockoutObservationWindow
            reversibleEncryptionEnabled = [bool]$DefaultPasswordPolicy.ReversibleEncryptionEnabled
            distinguishedName           = ConvertTo-StringValue -Value $DefaultPasswordPolicy.DistinguishedName
        }

        [PSCustomObject]@{
            PolicyType                  = "Default domain password policy"
            MinPasswordLength           = $DefaultPasswordPolicyDashboard.minPasswordLength
            ComplexityEnabled           = $DefaultPasswordPolicyDashboard.complexityEnabled
            PasswordHistoryCount        = $DefaultPasswordPolicyDashboard.passwordHistoryCount
            MaxPasswordAgeDays          = $DefaultPasswordPolicyDashboard.maxPasswordAgeDays
            MinPasswordAgeDays          = $DefaultPasswordPolicyDashboard.minPasswordAgeDays
            LockoutThreshold            = $DefaultPasswordPolicyDashboard.lockoutThreshold
            LockoutDurationMinutes      = $DefaultPasswordPolicyDashboard.lockoutDurationMinutes
            LockoutObservationMinutes   = $DefaultPasswordPolicyDashboard.lockoutObservationMinutes
            ReversibleEncryptionEnabled = $DefaultPasswordPolicyDashboard.reversibleEncryptionEnabled
            DistinguishedName           = $DefaultPasswordPolicyDashboard.distinguishedName
        } |
            Export-Csv `
                -Path (Join-Path $Directories.Csv "Password-Policy.csv") `
                -NoTypeInformation `
                -Encoding UTF8
    }
    catch {
        $DefaultPasswordPolicyError = $_.Exception.Message

        Write-AuditLog `
            -Level "WARNING" `
            -Message (
                "Could not read the default domain password policy: {0}" -f
                $DefaultPasswordPolicyError
            )
    }

    $FineGrainedPolicyDashboard = New-Object System.Collections.Generic.List[object]
    $FineGrainedPolicyCsvRows = New-Object System.Collections.Generic.List[object]
    $FineGrainedPolicyError = ""

    try {
        $FineGrainedPolicies = @(
            Get-ADFineGrainedPasswordPolicy `
                -Filter * `
                -Server $DomainController `
                -ErrorAction Stop |
            Sort-Object Precedence, Name
        )

        foreach ($FineGrainedPolicy in $FineGrainedPolicies) {
            $AppliesToNames = New-Object System.Collections.Generic.List[string]
            $AppliesToDns = @()

            if (
                $FineGrainedPolicy.PSObject.Properties.Match("AppliesTo").Count -gt 0 -and
                $null -ne $FineGrainedPolicy.AppliesTo
            ) {
                $AppliesToDns = @($FineGrainedPolicy.AppliesTo)
            }

            foreach ($AppliesToDn in $AppliesToDns) {
                try {
                    $AppliesToObject = Get-ADObject `
                        -Identity ([string]$AppliesToDn) `
                        -Server $DomainController `
                        -ErrorAction Stop

                    $AppliesToNames.Add([string]$AppliesToObject.Name)
                }
                catch {
                    # Keep the raw DN if the target cannot be resolved.
                    $AppliesToNames.Add([string]$AppliesToDn)
                }
            }

            $FineGrainedPolicyDashboard.Add(
                [PSCustomObject]@{
                    name                        = ConvertTo-StringValue -Value $FineGrainedPolicy.Name
                    precedence                  = [int]$FineGrainedPolicy.Precedence
                    appliesTo                   = @($AppliesToNames.ToArray())
                    minPasswordLength           = [int]$FineGrainedPolicy.MinPasswordLength
                    complexityEnabled           = [bool]$FineGrainedPolicy.ComplexityEnabled
                    passwordHistoryCount        = [int]$FineGrainedPolicy.PasswordHistoryCount
                    maxPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $FineGrainedPolicy.MaxPasswordAge
                    minPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $FineGrainedPolicy.MinPasswordAge
                    lockoutThreshold            = [int]$FineGrainedPolicy.LockoutThreshold
                    lockoutDurationMinutes      = ConvertTo-TimeSpanMinutes -Value $FineGrainedPolicy.LockoutDuration
                    lockoutObservationMinutes   = ConvertTo-TimeSpanMinutes -Value $FineGrainedPolicy.LockoutObservationWindow
                    reversibleEncryptionEnabled = [bool]$FineGrainedPolicy.ReversibleEncryptionEnabled
                }
            )

            $FineGrainedPolicyCsvRows.Add(
                [PSCustomObject]@{
                    PolicyType                  = "Fine-grained password policy"
                    Name                        = ConvertTo-StringValue -Value $FineGrainedPolicy.Name
                    Precedence                  = [int]$FineGrainedPolicy.Precedence
                    AppliesTo                   = ($AppliesToNames.ToArray() -join "; ")
                    MinPasswordLength           = [int]$FineGrainedPolicy.MinPasswordLength
                    ComplexityEnabled           = [bool]$FineGrainedPolicy.ComplexityEnabled
                    PasswordHistoryCount        = [int]$FineGrainedPolicy.PasswordHistoryCount
                    MaxPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $FineGrainedPolicy.MaxPasswordAge
                    MinPasswordAgeDays          = ConvertTo-TimeSpanDays -Value $FineGrainedPolicy.MinPasswordAge
                    LockoutThreshold            = [int]$FineGrainedPolicy.LockoutThreshold
                    LockoutDurationMinutes      = ConvertTo-TimeSpanMinutes -Value $FineGrainedPolicy.LockoutDuration
                    LockoutObservationMinutes   = ConvertTo-TimeSpanMinutes -Value $FineGrainedPolicy.LockoutObservationWindow
                    ReversibleEncryptionEnabled = [bool]$FineGrainedPolicy.ReversibleEncryptionEnabled
                }
            )
        }

        Write-AuditLog "Found $($FineGrainedPolicyDashboard.Count) fine-grained password policy object(s)."
    }
    catch {
        $FineGrainedPolicyError = $_.Exception.Message

        Write-AuditLog `
            -Level "WARNING" `
            -Message (
                "Could not enumerate fine-grained password policies (this typically requires Domain Admins-level read access): {0}" -f
                $FineGrainedPolicyError
            )
    }

    $FineGrainedPolicyCsvRows |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Fine-Grained-Password-Policies.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Collect privileged group membership and Protected Users evidence
    #
    # Groups are located by well-known SID/RID so the collection is
    # language independent. Membership is resolved recursively via the
    # "Members" attribute; nested groups are recorded together with the
    # nesting path so a reviewer can see through which intermediate group
    # a member was reached.
    #
    # The dashboard's "Privileged access" tab shows a cumulative inventory
    # of every account that is (directly or via nesting) a member of any
    # administrative group or of the built-in Protected Users group, with
    # one column per administrative group and a final column indicating
    # whether the account is in Protected Users.
    #######################################################################

    Write-AuditLog "Collecting privileged group and Protected Users membership."

    $DomainSid = [string]$Domain.DomainSID.Value
    $RootDomainSid = ""

    if ($Forest.RootDomain -ieq $DomainDnsRoot) {
        $RootDomainSid = $DomainSid
    }
    else {
        try {
            $RootDomain = Get-ADDomain -Identity $Forest.RootDomain
            $RootDomainSid = [string]$RootDomain.DomainSID.Value
        }
        catch {
            Write-AuditLog `
                -Level "WARNING" `
                -Message (
                    "Could not resolve the forest root domain '{0}'; Enterprise Admins, Schema Admins and Enterprise Key Admins will be skipped: {1}" -f
                    $Forest.RootDomain,
                    $_.Exception.Message
                )
        }
    }

    # Column/definition order below is also the column order of the
    # privileged-account inventory in the dashboard and CSV.
    $PrivilegedGroupDefinitions = New-Object System.Collections.Generic.List[object]

    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Domain Admins"; Identity = "$DomainSid-512" }
    )

    if (-not [string]::IsNullOrWhiteSpace($RootDomainSid)) {
        $PrivilegedGroupDefinitions.Add(
            [PSCustomObject]@{ DisplayName = "Enterprise Admins"; Identity = "$RootDomainSid-519" }
        )
        $PrivilegedGroupDefinitions.Add(
            [PSCustomObject]@{ DisplayName = "Schema Admins"; Identity = "$RootDomainSid-518" }
        )
    }

    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Administrators (built-in)"; Identity = "S-1-5-32-544" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Account Operators"; Identity = "S-1-5-32-548" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Server Operators"; Identity = "S-1-5-32-549" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Backup Operators"; Identity = "S-1-5-32-551" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Print Operators"; Identity = "S-1-5-32-550" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Group Policy Creator Owners"; Identity = "$DomainSid-520" }
    )
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "Key Admins"; Identity = "$DomainSid-526" }
    )

    if (-not [string]::IsNullOrWhiteSpace($RootDomainSid)) {
        $PrivilegedGroupDefinitions.Add(
            [PSCustomObject]@{ DisplayName = "Enterprise Key Admins"; Identity = "$RootDomainSid-527" }
        )
    }

    # DnsAdmins has no well-known SID; it is located by sAMAccountName,
    # which is not localized. If it does not exist (no DNS role in the
    # domain) this is recorded as "not resolved".
    $PrivilegedGroupDefinitions.Add(
        [PSCustomObject]@{ DisplayName = "DnsAdmins"; Identity = "DnsAdmins" }
    )

    $PrivilegedGroupResults = New-Object System.Collections.Generic.List[object]
    $PrivilegedGroupMemberCsvRows = New-Object System.Collections.Generic.List[object]
    $PrivilegedGroupNestedCsvRows = New-Object System.Collections.Generic.List[object]

    foreach ($GroupDefinition in $PrivilegedGroupDefinitions) {
        Write-AuditLog "Resolving privileged group: $($GroupDefinition.DisplayName)"

        $Resolution = Get-RecursiveGroupMembership `
            -GroupIdentity $GroupDefinition.Identity `
            -Server $DomainController `
            -DelayMs $GroupMembershipQueryDelayMs `
            -MaxDepth $MaxGroupNestingDepth

        if (-not $Resolution.Found) {
            Write-AuditLog `
                -Level "WARNING" `
                -Message (
                    "Privileged group '{0}' could not be resolved: {1}" -f
                    $GroupDefinition.DisplayName,
                    $Resolution.Error
                )
        }

        $PrivilegedGroupResults.Add(
            [PSCustomObject]@{
                DisplayName = $GroupDefinition.DisplayName
                Resolution  = $Resolution
            }
        )

        foreach ($Member in @($Resolution.Members)) {
            $PrivilegedGroupMemberCsvRows.Add(
                [PSCustomObject]@{
                    GroupDisplayName     = $GroupDefinition.DisplayName
                    GroupName            = $Resolution.GroupName
                    GroupSid             = $Resolution.GroupSid
                    MemberName           = $Member.Name
                    MemberSamAccountName = $Member.SamAccountName
                    MemberType           = $Member.ObjectClass
                    MembershipPath       = $Member.Via
                    MemberDn             = $Member.Dn
                }
            )
        }

        foreach ($NestedGroup in @($Resolution.NestedGroups)) {
            $PrivilegedGroupNestedCsvRows.Add(
                [PSCustomObject]@{
                    GroupDisplayName = $GroupDefinition.DisplayName
                    GroupName        = $Resolution.GroupName
                    NestedGroupName  = $NestedGroup.Name
                    NestedVia        = $NestedGroup.Via
                    Expanded         = $NestedGroup.Expanded
                    ExpansionError   = $NestedGroup.Error
                    NestedGroupDn    = $NestedGroup.Dn
                }
            )
        }
    }

    $PrivilegedGroupMemberCsvRows |
        Sort-Object GroupDisplayName, MemberName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Privileged-Group-Members.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    $PrivilegedGroupNestedCsvRows |
        Sort-Object GroupDisplayName, NestedGroupName |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Privileged-Group-Nested-Groups.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    #######################################################################
    # Resolve the Protected Users group (well-known RID 525) and build the
    # Protected Users x administrative groups matrix
    #######################################################################

    $ProtectedUsersResolution = Get-RecursiveGroupMembership `
        -GroupIdentity "$DomainSid-525" `
        -Server $DomainController `
        -DelayMs $GroupMembershipQueryDelayMs `
        -MaxDepth $MaxGroupNestingDepth

    if (-not $ProtectedUsersResolution.Found) {
        Write-AuditLog `
            -Level "WARNING" `
            -Message (
                "The Protected Users group could not be resolved (it requires a Windows Server 2012 R2 or higher domain functional level): {0}" -f
                $ProtectedUsersResolution.Error
            )
    }
    else {
        Write-AuditLog (
            "Protected Users contains {0} resolved member(s) ({1} direct entr(y/ies), {2} nested group(s))." -f
            @($ProtectedUsersResolution.Members).Count,
            @($ProtectedUsersResolution.DirectMembers).Count,
            @($ProtectedUsersResolution.NestedGroups).Count
        )
    }

    $MatrixGroupNames = New-Object System.Collections.Generic.List[string]
    $AdminMembershipLookup = @{}

    foreach ($PrivilegedGroup in $PrivilegedGroupResults) {
        if (-not $PrivilegedGroup.Resolution.Found) {
            continue
        }

        $MatrixGroupNames.Add($PrivilegedGroup.DisplayName)
        $MembershipLookup = @{}

        foreach ($Member in @($PrivilegedGroup.Resolution.Members)) {
            if (-not $MembershipLookup.ContainsKey($Member.Dn)) {
                $MembershipLookup[$Member.Dn] = [string]$Member.Via
            }
        }

        $AdminMembershipLookup[$PrivilegedGroup.DisplayName] = $MembershipLookup
    }

    #######################################################################
    # Build a Protected Users membership lookup (member DN -> nesting path)
    # so protection status can be shown as a column on the cumulative
    # privileged-account inventory below.
    #######################################################################

    $ProtectedUsersLookup = @{}

    if ($ProtectedUsersResolution.Found) {
        foreach ($ProtectedMember in @($ProtectedUsersResolution.Members)) {
            if (-not $ProtectedUsersLookup.ContainsKey($ProtectedMember.Dn)) {
                $ProtectedUsersLookup[$ProtectedMember.Dn] = [string]$ProtectedMember.Via
            }
        }
    }

    #######################################################################
    # Build the cumulative privileged-account inventory: the de-duplicated
    # union of every member of every administrative group and of the
    # Protected Users group, with one column per administrative group and a
    # final "in Protected Users" column. Protected Users is treated as one
    # of the groups, so an account that is only in Protected Users is still
    # listed (with empty administrative-group columns).
    #######################################################################

    $PrivilegedUserInfo = @{}

    foreach ($PrivilegedGroup in $PrivilegedGroupResults) {
        if (-not $PrivilegedGroup.Resolution.Found) {
            continue
        }

        foreach ($Member in @($PrivilegedGroup.Resolution.Members)) {
            if (-not $PrivilegedUserInfo.ContainsKey($Member.Dn)) {
                $PrivilegedUserInfo[$Member.Dn] = $Member
            }
        }
    }

    if ($ProtectedUsersResolution.Found) {
        foreach ($ProtectedMember in @($ProtectedUsersResolution.Members)) {
            if (-not $PrivilegedUserInfo.ContainsKey($ProtectedMember.Dn)) {
                $PrivilegedUserInfo[$ProtectedMember.Dn] = $ProtectedMember
            }
        }
    }

    $PrivilegedUserMatrix = New-Object System.Collections.Generic.List[object]
    $PrivilegedUserMatrixCsvRows = New-Object System.Collections.Generic.List[object]

    foreach ($PrivilegedUser in @($PrivilegedUserInfo.Values | Sort-Object Name)) {
        $Memberships = [ordered]@{}

        $CsvRow = [ordered]@{
            UserName       = $PrivilegedUser.Name
            SamAccountName = $PrivilegedUser.SamAccountName
            ObjectType     = $PrivilegedUser.ObjectClass
        }

        foreach ($MatrixGroupName in $MatrixGroupNames) {
            $MembershipLookup = $AdminMembershipLookup[$MatrixGroupName]

            if ($MembershipLookup.ContainsKey($PrivilegedUser.Dn)) {
                $Via = [string]$MembershipLookup[$PrivilegedUser.Dn]

                $Memberships[$MatrixGroupName] = [PSCustomObject]@{
                    member = $true
                    via    = $Via
                }

                if ($Via -eq "Direct") {
                    $CsvRow[$MatrixGroupName] = "Yes (direct)"
                }
                else {
                    $CsvRow[$MatrixGroupName] = "Yes (via $Via)"
                }
            }
            else {
                $Memberships[$MatrixGroupName] = [PSCustomObject]@{
                    member = $false
                    via    = ""
                }

                $CsvRow[$MatrixGroupName] = "No"
            }
        }

        #######################################################################
        # Protection status (final "Protected Users" column)
        #######################################################################

        if (-not $ProtectedUsersResolution.Found) {
            $ProtectedCell = [PSCustomObject]@{
                member   = $false
                via      = ""
                resolved = $false
            }

            $CsvRow["ProtectedUsers"] = "Unknown (group not resolved)"
        }
        elseif ($ProtectedUsersLookup.ContainsKey($PrivilegedUser.Dn)) {
            $ProtectedVia = [string]$ProtectedUsersLookup[$PrivilegedUser.Dn]

            $ProtectedCell = [PSCustomObject]@{
                member   = $true
                via      = $ProtectedVia
                resolved = $true
            }

            if ($ProtectedVia -eq "Direct") {
                $CsvRow["ProtectedUsers"] = "Yes (direct)"
            }
            else {
                $CsvRow["ProtectedUsers"] = "Yes (via $ProtectedVia)"
            }
        }
        else {
            $ProtectedCell = [PSCustomObject]@{
                member   = $false
                via      = ""
                resolved = $true
            }

            $CsvRow["ProtectedUsers"] = "No"
        }

        $PrivilegedUserMatrix.Add(
            [PSCustomObject]@{
                name        = $PrivilegedUser.Name
                sam         = $PrivilegedUser.SamAccountName
                objectClass = $PrivilegedUser.ObjectClass
                memberships = $Memberships
                protected   = $ProtectedCell
            }
        )

        $PrivilegedUserMatrixCsvRows.Add([PSCustomObject]$CsvRow)
    }

    $PrivilegedUserMatrixCsvRows |
        Export-Csv `
            -Path (Join-Path $Directories.Csv "Privileged-Account-Membership-Matrix.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    $ProtectedUsersMemberCount = 0

    if ($ProtectedUsersResolution.Found) {
        $ProtectedUsersMemberCount = @($ProtectedUsersResolution.Members).Count
    }

    $ResolvedPrivilegedGroupCount = @(
        $PrivilegedGroupResults | Where-Object { $_.Resolution.Found }
    ).Count

    #######################################################################
    # Build interactive HTML dashboard
    #
    # Combines configured findings, structural scope, security filtering
    # (with resolved group membership), domain information, privileged
    # access evidence and password policy into a single browsable file so
    # a reviewer can trace, per GPO and per OU/domain, whether a weak
    # setting is mitigated and who it applies to.
    #######################################################################

    Write-AuditLog "Building interactive audit dashboard."

    $FindingsByGpoId = @{}
    $SecureFindingCount = 0
    $PartialFindingCount = 0
    $InsecureFindingCount = 0
    $UnknownFindingCount = 0

    foreach ($PolicyResult in $PolicyResults) {
        $SeverityInfo = Get-FindingSeverity `
            -Category $PolicyResult.Category `
            -RegistryData $PolicyResult.RegistryData `
            -Enforced $PolicyResult.Enforced

        switch ($SeverityInfo.Severity) {
            "secure"   { $SecureFindingCount++ }
            "partial"  { $PartialFindingCount++ }
            "insecure" { $InsecureFindingCount++ }
            default    { $UnknownFindingCount++ }
        }

        $FindingEntry = [PSCustomObject]@{
            category       = $PolicyResult.Category
            setting        = $PolicyResult.Setting
            registryPath   = $PolicyResult.RegistryPath
            valueName      = $PolicyResult.ValueName
            registryData   = $PolicyResult.RegistryData
            severity       = $SeverityInfo.Severity
            label          = $SeverityInfo.Label
            interpretation = $PolicyResult.Interpretation
            clientBehavior = $PolicyResult.ClientBehavior
            serverBehavior = $PolicyResult.ServerBehavior
        }

        if (-not $FindingsByGpoId.ContainsKey($PolicyResult.GpoId)) {
            $FindingsByGpoId[$PolicyResult.GpoId] = New-Object System.Collections.Generic.List[object]
        }

        $FindingsByGpoId[$PolicyResult.GpoId].Add($FindingEntry)
    }

    $FilteringByGpoId = @{}

    foreach ($PermissionResult in $PermissionResults) {
        $FilterEntry = [PSCustomObject]@{
            trustee      = $PermissionResult.TrusteeName
            sid          = $PermissionResult.TrusteeSid
            domain       = $PermissionResult.TrusteeDomain
            type         = $PermissionResult.TrusteeType
            permission   = $PermissionResult.Permission
            appliesToGpo = $PermissionResult.AppliesToGpo
            inherited    = $PermissionResult.Inherited
        }

        if (-not $FilteringByGpoId.ContainsKey($PermissionResult.GpoId)) {
            $FilteringByGpoId[$PermissionResult.GpoId] = New-Object System.Collections.Generic.List[object]
        }

        $FilteringByGpoId[$PermissionResult.GpoId].Add($FilterEntry)
    }

    $DashboardGpos = New-Object System.Collections.Generic.List[object]

    foreach ($Gpo in $Gpos) {
        $GpoGuid = $Gpo.Id.ToString()

        if (-not $RelevantGpoIds.Contains($GpoGuid)) {
            continue
        }

        $GpoFindings = @()
        if ($FindingsByGpoId.ContainsKey($GpoGuid)) {
            $GpoFindings = $FindingsByGpoId[$GpoGuid].ToArray()
        }

        $GpoDirectLinks = @(
            $DirectLinkResults |
            Where-Object { $_.GpoId -eq $GpoGuid -and $_.LinkStatus -eq "Direct link" } |
            ForEach-Object {
                [PSCustomObject]@{
                    target   = $_.LinkTarget
                    enabled  = $_.Enabled
                    enforced = $_.Enforced
                }
            }
        )

        $GpoScope = @(
            $StructuralScopeResults |
            Where-Object { $_.GpoId -eq $GpoGuid } |
            ForEach-Object {
                [PSCustomObject]@{
                    target             = $_.ScopeTarget
                    containerName      = $_.ContainerName
                    containerType      = $_.ContainerType
                    inheritanceBlocked = [string]$_.InheritanceBlocked
                    linkEnabled        = [string]$_.LinkEnabled
                    linkEnforced       = [string]$_.LinkEnforced
                }
            }
        )

        $GpoFiltering = @()
        if ($FilteringByGpoId.ContainsKey($GpoGuid)) {
            $GpoFiltering = $FilteringByGpoId[$GpoGuid].ToArray()
        }

        $GpoWmiFilterRow = $WmiFilterResults | Where-Object { $_.GpoId -eq $GpoGuid } | Select-Object -First 1
        $GpoWmiFilter = $null

        if ($GpoWmiFilterRow -and -not [string]::IsNullOrWhiteSpace($GpoWmiFilterRow.WmiFilterName)) {
            $GpoWmiFilter = [PSCustomObject]@{
                name = $GpoWmiFilterRow.WmiFilterName
                path = $GpoWmiFilterRow.WmiFilterPath
            }
        }

        $DashboardGpos.Add(
            [PSCustomObject]@{
                gpoId             = $GpoGuid
                gpoName           = $Gpo.DisplayName
                gpoStatus         = [string]$Gpo.GpoStatus
                modificationTime  = [string]$Gpo.ModificationTime
                findings          = $GpoFindings
                directLinks       = $GpoDirectLinks
                structuralScope   = $GpoScope
                securityFiltering = $GpoFiltering
                wmiFilter         = $GpoWmiFilter
            }
        )
    }

    $DashboardScopeTargets = New-Object System.Collections.Generic.List[object]
    $ScopeTargetGroups = @($StructuralScopeResults | Group-Object ScopeTarget)

    foreach ($ScopeTargetGroup in $ScopeTargetGroups) {
        $FirstRow = $ScopeTargetGroup.Group[0]

        $LinkedGpos = @(
            $ScopeTargetGroup.Group |
            ForEach-Object {
                $StructuralRow = $_
                $RowGpoFindings = @()

                if ($FindingsByGpoId.ContainsKey($StructuralRow.GpoId)) {
                    $RowGpoFindings = $FindingsByGpoId[$StructuralRow.GpoId].ToArray()
                }

                $RowGpoFiltering = @()

                if ($FilteringByGpoId.ContainsKey($StructuralRow.GpoId)) {
                    $RowGpoFiltering = @(
                        $FilteringByGpoId[$StructuralRow.GpoId].ToArray() |
                        Where-Object { $_.appliesToGpo }
                    )
                }

                [PSCustomObject]@{
                    gpoId        = $StructuralRow.GpoId
                    gpoName      = $StructuralRow.GpoName
                    linkEnabled  = [string]$StructuralRow.LinkEnabled
                    linkEnforced = [string]$StructuralRow.LinkEnforced
                    findings     = $RowGpoFindings
                    filtering    = $RowGpoFiltering
                }
            }
        )

        $DashboardScopeTargets.Add(
            [PSCustomObject]@{
                target             = $ScopeTargetGroup.Name
                containerName      = $FirstRow.ContainerName
                containerType      = $FirstRow.ContainerType
                inheritanceBlocked = [string]$FirstRow.InheritanceBlocked
                linkedGpos         = $LinkedGpos
                evaluationFailed   = $false
                evaluationError    = ""
            }
        )
    }

    foreach ($InheritanceError in $InheritanceErrorResults) {
        $DashboardScopeTargets.Add(
            [PSCustomObject]@{
                target             = $InheritanceError.ScopeTarget
                containerName      = ""
                containerType      = ""
                inheritanceBlocked = ""
                linkedGpos         = @()
                evaluationFailed   = $true
                evaluationError    = $InheritanceError.Error
            }
        )
    }

    #######################################################################
    # Assemble the new dashboard sections (domain overview, privileged
    # access, password policy)
    #######################################################################

    $DashboardDomainInfo = [PSCustomObject]@{
        dnsRoot              = $DomainInformation.DnsRoot
        netBiosName          = $DomainInformation.NetBiosName
        distinguishedName    = $DomainInformation.DistinguishedName
        domainSid            = $DomainInformation.DomainSid
        domainMode           = $DomainInformation.DomainMode
        forestName           = $DomainInformation.ForestName
        forestMode           = $DomainInformation.ForestMode
        pdcEmulator          = $DomainInformation.PdcEmulator
        ridMaster            = $DomainInformation.RidMaster
        infrastructureMaster = $DomainInformation.InfrastructureMaster
        schemaMaster         = $DomainInformation.SchemaMaster
        domainNamingMaster   = $DomainInformation.DomainNamingMaster
        domainControllers    = @(
            $DomainControllerInventory |
            ForEach-Object {
                [PSCustomObject]@{
                    name                   = $_.Name
                    hostName               = $_.HostName
                    ipv4Address            = $_.IPv4Address
                    site                   = $_.Site
                    operatingSystem        = $_.OperatingSystem
                    operatingSystemVersion = $_.OperatingSystemVersion
                    isGlobalCatalog        = $_.IsGlobalCatalog
                    isReadOnly             = $_.IsReadOnly
                    operationMasterRoles   = $_.OperationMasterRoles
                }
            }
        )
    }

    $DashboardPrivilegedGroups = @(
        $PrivilegedGroupResults |
        ForEach-Object {
            $Resolution = $_.Resolution
            $AllMembers = @($Resolution.Members)

            $DisplayedMembers = @(
                $AllMembers |
                Select-Object -First $MaxGroupMembersToDisplay |
                ForEach-Object {
                    [PSCustomObject]@{
                        name = $_.Name
                        sam  = $_.SamAccountName
                        type = $_.ObjectClass
                        via  = $_.Via
                    }
                }
            )

            [PSCustomObject]@{
                displayName  = $_.DisplayName
                found        = [bool]$Resolution.Found
                error        = $Resolution.Error
                groupName    = $Resolution.GroupName
                sid          = $Resolution.GroupSid
                memberCount  = $AllMembers.Count
                truncated    = ($AllMembers.Count -gt $MaxGroupMembersToDisplay)
                nestedGroups = @(
                    $Resolution.NestedGroups |
                    ForEach-Object {
                        [PSCustomObject]@{
                            name     = $_.Name
                            via      = $_.Via
                            expanded = $_.Expanded
                            error    = $_.Error
                        }
                    }
                )
                members      = $DisplayedMembers
            }
        }
    )

    # Add Protected Users to the privileged group list so it is presented
    # like the other administrative groups. Its members also drive the
    # "Protected Users" column on the privileged-account inventory above.
    $ProtectedUsersAllMembers = @($ProtectedUsersResolution.Members)

    $ProtectedUsersGroupEntry = [PSCustomObject]@{
        displayName  = "Protected Users"
        found        = [bool]$ProtectedUsersResolution.Found
        error        = $ProtectedUsersResolution.Error
        groupName    = $ProtectedUsersResolution.GroupName
        sid          = $ProtectedUsersResolution.GroupSid
        memberCount  = $ProtectedUsersAllMembers.Count
        truncated    = ($ProtectedUsersAllMembers.Count -gt $MaxGroupMembersToDisplay)
        nestedGroups = @(
            $ProtectedUsersResolution.NestedGroups |
            ForEach-Object {
                [PSCustomObject]@{
                    name     = $_.Name
                    via      = $_.Via
                    expanded = $_.Expanded
                    error    = $_.Error
                }
            }
        )
        members      = @(
            $ProtectedUsersAllMembers |
            Select-Object -First $MaxGroupMembersToDisplay |
            ForEach-Object {
                [PSCustomObject]@{
                    name = $_.Name
                    sam  = $_.SamAccountName
                    type = $_.ObjectClass
                    via  = $_.Via
                }
            }
        )
    }

    $DashboardPrivilegedGroups = @($DashboardPrivilegedGroups) + @($ProtectedUsersGroupEntry)

    # Normalize generic lists before JSON serialization. This avoids a
    # Windows PowerShell 5.1 binder issue involving List[object] values.
    $DashboardGposArray = $DashboardGpos.ToArray()
    $DashboardScopeTargetsArray = $DashboardScopeTargets.ToArray()

    $DashboardData = [PSCustomObject]@{
        generatedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
        domain           = $DomainDnsRoot
        domainController = $DomainController
        summary          = [PSCustomObject]@{
            totalGposScanned         = $Gpos.Count
            relevantGpoCount         = $RelevantGpoIds.Count
            findingsSecure           = $SecureFindingCount
            findingsPartial          = $PartialFindingCount
            findingsInsecure         = $InsecureFindingCount
            findingsUnknown          = $UnknownFindingCount
            scopeTargetsTotal        = $ScopeTargets.Count
            scopeTargetsFailed       = $InheritanceErrorResults.Count
            domainControllerCount    = $DomainControllerInventory.Count
            protectedUsersMembers    = $ProtectedUsersMemberCount
            privilegedGroupsResolved = $ResolvedPrivilegedGroupCount
            privilegedGroupsTotal    = $PrivilegedGroupDefinitions.Count
        }
        domainInfo       = $DashboardDomainInfo
        passwordPolicy   = [PSCustomObject]@{
            defaultPolicy      = $DefaultPasswordPolicyDashboard
            defaultPolicyError = $DefaultPasswordPolicyError
            fineGrained        = @($FineGrainedPolicyDashboard.ToArray())
            fineGrainedError   = $FineGrainedPolicyError
        }
        privilegedAccess = [PSCustomObject]@{
            groupColumns    = @($MatrixGroupNames.ToArray())
            groups          = $DashboardPrivilegedGroups
            protectedUsers  = [PSCustomObject]@{
                found       = [bool]$ProtectedUsersResolution.Found
                error       = $ProtectedUsersResolution.Error
                groupName   = $ProtectedUsersResolution.GroupName
                memberCount = $ProtectedUsersMemberCount
            }
            privilegedUsers = [PSCustomObject]@{
                protectedResolved = [bool]$ProtectedUsersResolution.Found
                users             = @($PrivilegedUserMatrix.ToArray())
            }
        }
        gpos             = $DashboardGposArray
        scopeTargets     = $DashboardScopeTargetsArray
        groupMembers     = $GroupMembershipCache
    }

    $DashboardJson = $DashboardData | ConvertTo-Json -Depth 20
    $DashboardJsonPath = Join-Path $Directories.Metadata "Dashboard-Data.json"
    $DashboardJson | Set-Content -LiteralPath $DashboardJsonPath -Encoding UTF8

    $DashboardJsonSafe = $DashboardJson -replace '</script', '<\/script'

    $DashboardHtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Active Directory Security Report - __DOMAIN__</title>
<style>
:root {
  --bg: #f7f8fa;
  --surface: #ffffff;
  --border: #e2e5ea;
  --text: #1a1d23;
  --muted: #6b7280;
  --accent: #2563eb;
  --secure: #16a34a;
  --secure-bg: #dcfce7;
  --partial: #b45309;
  --partial-bg: #fef3c7;
  --insecure: #dc2626;
  --insecure-bg: #fee2e2;
  --unknown: #6b7280;
  --unknown-bg: #e5e7eb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}
header { padding: 24px 32px; background: var(--surface); border-bottom: 1px solid var(--border); }
header h1 { margin: 0 0 4px 0; font-size: 20px; }
header .meta { color: var(--muted); font-size: 13px; }
.summary-cards { display: flex; gap: 12px; padding: 20px 32px 0; flex-wrap: wrap; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; min-width: 160px; }
.card-value { font-size: 26px; font-weight: 700; }
.card-label { font-size: 12px; color: var(--muted); margin-top: 2px; }
.card-insecure .card-value { color: var(--insecure); }
.card-partial .card-value { color: var(--partial); }
.card-secure .card-value { color: var(--secure); }
.tabs { display: flex; gap: 4px; padding: 20px 32px 0; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.tab-btn { border: none; background: none; padding: 10px 16px; cursor: pointer; font-size: 14px; color: var(--muted); border-bottom: 2px solid transparent; }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
.tab-panel { display: none; padding: 20px 32px 40px; }
.tab-panel.active { display: block; }
.controls { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
.controls input[type=text] { padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; min-width: 260px; font-size: 13px; }
.controls select { padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }
.controls label { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.badge-secure { background: var(--secure-bg); color: var(--secure); }
.badge-partial { background: var(--partial-bg); color: var(--partial); }
.badge-insecure { background: var(--insecure-bg); color: var(--insecure); }
.badge-unknown { background: var(--unknown-bg); color: var(--unknown); }
.gpo-block, .scope-block { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; overflow: hidden; }
.gpo-block summary { padding: 14px 18px; cursor: pointer; display: flex; gap: 12px; align-items: center; list-style: none; flex-wrap: wrap; }
.gpo-block summary::-webkit-details-marker { display: none; }
.gpo-name { font-weight: 600; }
.gpo-body { padding: 0 18px 18px; }
.findings-table { width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 13px; }
.findings-table th, .findings-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
.gpo-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.gpo-columns h4 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; color: var(--muted); }
.gpo-columns ul { margin: 0; padding-left: 18px; font-size: 13px; }
.scope-header { padding: 12px 16px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; border-bottom: 1px solid var(--border); }
.scope-body { padding: 12px 16px; }
.scope-body ul { margin: 0; padding-left: 18px; font-size: 13px; }
.scope-body li { margin-bottom: 8px; }
.tag { background: #eef2ff; color: var(--accent); border-radius: 999px; padding: 1px 8px; font-size: 11px; margin-left: 4px; }
.tag-warn { background: var(--insecure-bg); color: var(--insecure); }
.muted { color: var(--muted); font-size: 13px; }
code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
footer { padding: 20px 32px 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 20px; }
.trustee { border-bottom: 1px dotted var(--muted); cursor: help; }
.trustee-chip { display: inline-block; background: #f1f5f9; border-radius: 999px; padding: 1px 8px; font-size: 11px; margin: 2px 4px 0 0; border-bottom: none; cursor: help; }
.member-tooltip {
  position: fixed;
  z-index: 1000;
  background: #111827;
  color: #f9fafb;
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 12px;
  max-width: 320px;
  max-height: 260px;
  overflow-y: auto;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
  display: none;
  pointer-events: none;
}
.member-tooltip .tooltip-title { font-weight: 600; margin-bottom: 6px; }
.member-tooltip .tooltip-muted { color: #9ca3af; }
.member-tooltip ul.tooltip-list { margin: 0; padding-left: 16px; }
.member-tooltip .tooltip-type { color: #9ca3af; }
.section-block { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 14px; }
.section-block h3 { margin: 0 0 12px; font-size: 15px; }
.kv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.kv-table td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.kv-table td:first-child { color: var(--muted); width: 260px; }
.matrix-wrap { overflow-x: auto; }
.matrix-table { border-collapse: collapse; font-size: 13px; width: 100%; }
.matrix-table th, .matrix-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: center; white-space: nowrap; }
.matrix-table th:first-child, .matrix-table td:first-child { text-align: left; position: sticky; left: 0; background: var(--surface); }
.matrix-table th { font-size: 12px; }
.check-direct { color: var(--secure); font-weight: 700; font-size: 15px; }
.check-nested { color: var(--partial); font-weight: 700; font-size: 15px; border-bottom: 1px dotted var(--partial); cursor: help; }
.check-none { color: #cbd5e1; }
.not-protected { color: var(--partial); font-weight: 700; font-size: 15px; border-bottom: 1px dotted var(--partial); cursor: help; }
.legend { margin: 10px 0 0; }
@media (max-width: 720px) { .gpo-columns { grid-template-columns: 1fr; } }
</style>
</head>
<body>

<div id="member-tooltip" class="member-tooltip"></div>

<header>
  <h1>Active Directory Security Report</h1>
  <div class="meta">Domain: <strong>__DOMAIN__</strong> &middot; Domain controller: <strong>__DC__</strong> &middot; Generated: __GENERATED_AT__</div>
</header>

<section class="summary-cards" id="summary-cards"></section>

<nav class="tabs">
  <button class="tab-btn active" data-tab="overview">Domain overview</button>
  <button class="tab-btn" data-tab="privileged">Privileged access</button>
  <button class="tab-btn" data-tab="pwpolicy">Password policy</button>
  <button class="tab-btn" data-tab="policies">Group Policy</button>
  <button class="tab-btn" data-tab="scope">GPO scope by OU</button>
</nav>

<section id="tab-overview" class="tab-panel active">
  <div id="overview-container"></div>
</section>

<section id="tab-policies" class="tab-panel">
  <div class="controls">
    <input type="text" id="policy-search" placeholder="Search GPO name, category, setting..." />
    <select id="severity-filter">
      <option value="all">All statuses</option>
      <option value="insecure">Insecure only</option>
      <option value="partial">Partially mitigated only</option>
      <option value="secure">Secure / enforced only</option>
      <option value="unknown">Unclassified only</option>
    </select>
  </div>
  <div id="policies-container"></div>
</section>

<section id="tab-scope" class="tab-panel">
  <div class="controls">
    <input type="text" id="scope-search" placeholder="Search OU / domain..." />
    <label><input type="checkbox" id="only-gaps" /> Show only OUs without full mitigation</label>
  </div>
  <div id="scope-container"></div>
</section>

<section id="tab-privileged" class="tab-panel">
  <div id="privileged-container"></div>
</section>

<section id="tab-pwpolicy" class="tab-panel">
  <div id="pwpolicy-container"></div>
</section>

<footer>
  This is a point-in-time enumeration of the domain: its controllers and FSMO roles, privileged group
  membership, Protected Users coverage, password policy, and the Group Policy settings that enforce (or fail to
  enforce) key protections such as SMB signing and NTLMv1 prevention. Each area has its own tab above.
  <br /><br />
  Privileged group membership is a snapshot resolved recursively through nested groups; hover over an amber
  checkmark to see the nesting path, and over an underlined group name to see its resolved membership (capped at
  the configured maximum; the full list is in the CSV evidence). Groups shown as "not resolved" could not be
  located (for example because they do not exist at this functional level, or live in another domain of the
  forest) and are evidence gaps rather than confirmed-empty groups.
  <br /><br />
  On the Group Policy tabs, structural scope shows domain/OU containers where a GPO appears in
  InheritedGpoLinks. This is not the same as final effective (resultant) policy: security filtering, WMI
  filtering, loopback processing, disabled GPO sections and client-side processing can still change what
  actually applies on an endpoint. Use <code>gpresult /h</code> or <code>Get-GPResultantSetOfPolicy</code> for
  endpoint-specific proof. Rows marked "Evaluation failed" could not be checked at all (even after retries) and
  are gaps in this evidence set, not confirmed absence of a policy.
</footer>

<script>
const data = __DASHBOARD_JSON__;
const groupMembers = data.groupMembers || {};
const tooltip = document.getElementById('member-tooltip');

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

const severityOrder = { secure: 0, partial: 1, insecure: 2, unknown: 3 };
const severityLabel = {
  secure: 'Secure / enforced',
  partial: 'Partially mitigated',
  insecure: 'Insecure',
  unknown: 'Unclassified'
};

function badge(sev, text) {
  const safeSev = sev && severityLabel[sev] ? sev : 'unknown';
  return '<span class="badge badge-' + esc(safeSev) + '">' + esc(text || severityLabel[safeSev]) + '</span>';
}

function bestSeverity(findings) {
  if (!findings || findings.length === 0) return null;
  return findings.reduce((best, f) => severityOrder[f.severity] < severityOrder[best] ? f.severity : best, findings[0].severity);
}

function trusteeSpan(sid, name, cssClass) {
  return '<span class="' + cssClass + ' trustee" data-sid="' + esc(sid) + '" data-name="' + esc(name) + '">' + esc(name) + '</span>';
}

function tooltipContentForSid(sid, trusteeName) {
  const info = groupMembers[sid];

  if (!info) {
    return '<div class="tooltip-title">' + esc(trusteeName) + '</div><div class="tooltip-muted">Not a resolved AD group (built-in/well-known principal, or resolution was skipped)</div>';
  }
  if (!info.resolved) {
    return '<div class="tooltip-title">' + esc(trusteeName) + '</div><div class="tooltip-muted">Could not resolve membership: ' + esc(info.error) + '</div>';
  }
  if (info.totalCount === 0) {
    return '<div class="tooltip-title">' + esc(trusteeName) + '</div><div class="tooltip-muted">Group has no members</div>';
  }

  const list = info.members.map(m => '<li>' + esc(m.name) + ' <span class="tooltip-type">(' + esc(m.type) + ')</span></li>').join('');
  const more = info.truncated ? '<li class="tooltip-muted">+ ' + (info.totalCount - info.members.length) + ' more (see CSV for full list)</li>' : '';

  return '<div class="tooltip-title">' + esc(trusteeName) + ' &middot; ' + info.totalCount + ' member(s)</div><ul class="tooltip-list">' + list + more + '</ul>';
}

function renderSummary() {
  const s = data.summary;
  const di = data.domainInfo || {};
  document.getElementById('summary-cards').innerHTML =
    '<div class="card"><div class="card-value">' + esc(di.domainMode || '&ndash;') + '</div><div class="card-label">Domain functional level</div></div>' +
    '<div class="card"><div class="card-value">' + s.domainControllerCount + '</div><div class="card-label">Domain controllers</div></div>' +
    '<div class="card"><div class="card-value">' + s.privilegedGroupsResolved + '/' + s.privilegedGroupsTotal + '</div><div class="card-label">Privileged groups enumerated</div></div>' +
    '<div class="card"><div class="card-value">' + s.protectedUsersMembers + '</div><div class="card-label">Protected Users members</div></div>' +
    '<div class="card card-insecure"><div class="card-value">' + s.findingsInsecure + '</div><div class="card-label">Insecure policy findings</div></div>' +
    '<div class="card card-partial"><div class="card-value">' + s.findingsPartial + '</div><div class="card-label">Partially mitigated</div></div>' +
    '<div class="card card-secure"><div class="card-value">' + s.findingsSecure + '</div><div class="card-label">Enforced / secure</div></div>';
}

function renderOverview() {
  const container = document.getElementById('overview-container');
  const d = data.domainInfo || null;

  if (!d) {
    container.innerHTML = '<p class="muted">No domain information collected.</p>';
    return;
  }

  const kvRows = [
    ['Domain (DNS)', esc(d.dnsRoot)],
    ['NetBIOS name', esc(d.netBiosName)],
    ['Distinguished name', '<code>' + esc(d.distinguishedName) + '</code>'],
    ['Domain SID', '<code>' + esc(d.domainSid) + '</code>'],
    ['Domain functional level', esc(d.domainMode)],
    ['Forest', esc(d.forestName)],
    ['Forest functional level', esc(d.forestMode)]
  ].map(r => '<tr><td>' + esc(r[0]) + '</td><td>' + r[1] + '</td></tr>').join('');

  const fsmoRows = [
    ['PDC emulator', esc(d.pdcEmulator)],
    ['RID master', esc(d.ridMaster)],
    ['Infrastructure master', esc(d.infrastructureMaster)],
    ['Schema master', esc(d.schemaMaster)],
    ['Domain naming master', esc(d.domainNamingMaster)]
  ].map(r => '<tr><td>' + esc(r[0]) + '</td><td>' + r[1] + '</td></tr>').join('');

  const dcs = d.domainControllers || [];
  const dcRows = dcs.map(dc =>
    '<tr>' +
    '<td style="text-align:left;">' + esc(dc.hostName || dc.name) + '</td>' +
    '<td>' + esc(dc.ipv4Address) + '</td>' +
    '<td>' + esc(dc.site) + '</td>' +
    '<td style="text-align:left;">' + esc(dc.operatingSystem) + (dc.operatingSystemVersion ? ' <span class="muted">(' + esc(dc.operatingSystemVersion) + ')</span>' : '') + '</td>' +
    '<td>' + (dc.isGlobalCatalog ? 'Yes' : 'No') + '</td>' +
    '<td>' + (dc.isReadOnly ? 'Yes' : 'No') + '</td>' +
    '<td style="text-align:left;">' + esc(dc.operationMasterRoles || '') + '</td>' +
    '</tr>'
  ).join('');

  container.innerHTML =
    '<div class="section-block"><h3>Domain</h3><table class="kv-table">' + kvRows + '</table></div>' +
    '<div class="section-block"><h3>FSMO role holders</h3><table class="kv-table">' + fsmoRows + '</table></div>' +
    '<div class="section-block"><h3>Domain controllers (' + dcs.length + ')</h3>' +
    (dcRows
      ? '<div class="matrix-wrap"><table class="matrix-table"><thead><tr><th>Host</th><th>IPv4</th><th>Site</th><th>Operating system</th><th>GC</th><th>RODC</th><th>FSMO roles</th></tr></thead><tbody>' + dcRows + '</tbody></table></div>'
      : '<p class="muted">No domain controllers were returned.</p>') +
    '</div>';
}

function renderPolicies(filterText, severityFilter) {
  const container = document.getElementById('policies-container');
  const term = filterText.trim().toLowerCase();
  let html = '';

  data.gpos.forEach(gpo => {
    let findings = gpo.findings;
    if (severityFilter !== 'all') findings = findings.filter(f => f.severity === severityFilter);
    if (findings.length === 0) return;

    const matchesText = !term ||
      gpo.gpoName.toLowerCase().includes(term) ||
      findings.some(f => (f.category + ' ' + f.setting).toLowerCase().includes(term));
    if (!matchesText) return;

    const findingsHtml = findings.map(f =>
      '<tr><td>' + esc(f.category) + '</td><td>' + esc(f.setting) + '</td><td><code>' + esc(f.registryData) + '</code></td><td>' + badge(f.severity, f.label) + '</td><td>' + esc(f.interpretation) + '</td></tr>'
    ).join('');

    const scopeHtml = gpo.structuralScope.length
      ? gpo.structuralScope.map(s =>
          '<li><code>' + esc(s.target) + '</code>' +
          (s.linkEnforced === 'True' ? ' <span class="tag">enforced</span>' : '') +
          (s.inheritanceBlocked === 'Yes' ? ' <span class="tag tag-warn">inheritance blocked</span>' : '') +
          '</li>'
        ).join('')
      : '<li class="muted">No structural scope evaluated / no matches found</li>';

    const filteringRows = gpo.securityFiltering.filter(p => p.appliesToGpo);
    const filteringHtml = filteringRows.length
      ? filteringRows.map(p =>
          '<li>' + trusteeSpan(p.sid, p.trustee, 'trustee-inline') + ' <span class="muted">(' + esc(p.type) + ')</span></li>'
        ).join('')
      : '<li class="muted">No Apply permissions recorded</li>';

    const wmiHtml = gpo.wmiFilter
      ? '<div><strong>WMI filter:</strong> ' + esc(gpo.wmiFilter.name) + '</div>'
      : '';

    html +=
      '<details class="gpo-block"><summary><span class="gpo-name">' + esc(gpo.gpoName) + '</span><span class="gpo-status muted">' + esc(gpo.gpoStatus) + '</span></summary>' +
      '<div class="gpo-body">' +
      '<table class="findings-table"><thead><tr><th>Category</th><th>Setting</th><th>Value</th><th>Status</th><th>Interpretation</th></tr></thead><tbody>' + findingsHtml + '</tbody></table>' +
      '<div class="gpo-columns">' +
      '<div><h4>Applies at (structural scope)</h4><ul>' + scopeHtml + '</ul></div>' +
      '<div><h4>Security filtering (Apply permission)</h4><ul>' + filteringHtml + '</ul></div>' +
      '</div>' + wmiHtml +
      '</div></details>';
  });

  container.innerHTML = html || '<p class="muted">No GPOs match the current filters.</p>';
}

function renderScope(filterText, onlyGaps) {
  const container = document.getElementById('scope-container');
  const term = filterText.trim().toLowerCase();
  let html = '';

  data.scopeTargets.forEach(scope => {
    if (term && !scope.target.toLowerCase().includes(term) && !(scope.containerName || '').toLowerCase().includes(term)) return;

    if (scope.evaluationFailed) {
      if (onlyGaps) return;
      html +=
        '<div class="scope-block"><div class="scope-header"><code>' + esc(scope.target) + '</code>' + badge('unknown', 'Evaluation failed') + '</div>' +
        '<div class="scope-body muted">' + esc(scope.evaluationError) + '</div></div>';
      return;
    }

    const smbFindings = scope.linkedGpos.flatMap(g => g.findings.filter(f => f.category === 'SMB signing'));
    const ntlmFindings = scope.linkedGpos.flatMap(g => g.findings.filter(f => f.category === 'NTLMv1'));
    const smbBest = bestSeverity(smbFindings);
    const ntlmBest = bestSeverity(ntlmFindings);
    const hasGap = smbBest !== 'secure' || ntlmBest !== 'secure';

    if (onlyGaps && !hasGap) return;

    const gposHtml = scope.linkedGpos.length
      ? scope.linkedGpos.map(g => {
          const findingBadges = g.findings.map(f => badge(f.severity, f.category + ': ' + f.label)).join(' ');
          const filterChips = (g.filtering || []).map(p => trusteeSpan(p.sid, p.trustee, 'trustee-chip')).join('');

          return '<li><strong>' + esc(g.gpoName) + '</strong>' +
            (g.linkEnforced === 'True' ? ' <span class="tag">enforced</span>' : '') +
            (g.linkEnabled === 'False' ? ' <span class="tag tag-warn">link disabled</span>' : '') +
            '<div>' + findingBadges + '</div>' +
            (filterChips ? '<div class="muted" style="margin-top:4px;">Applies to: ' + filterChips + '</div>' : '') +
            '</li>';
        }).join('')
      : '<li class="muted">No GPOs with relevant settings found in scope</li>';

    html +=
      '<div class="scope-block"><div class="scope-header"><code>' + esc(scope.target) + '</code>' +
      '<span class="tag">' + esc(scope.containerType) + '</span>' +
      (scope.inheritanceBlocked === 'Yes' ? '<span class="tag tag-warn">inheritance blocked</span>' : '') +
      badge(smbBest || 'unknown', 'SMB: ' + (smbBest ? severityLabel[smbBest] : 'no policy scoped')) +
      badge(ntlmBest || 'unknown', 'NTLM: ' + (ntlmBest ? severityLabel[ntlmBest] : 'no policy scoped')) +
      '</div><div class="scope-body"><ul>' + gposHtml + '</ul></div></div>';
  });

  container.innerHTML = html || '<p class="muted">No OUs match the current filters.</p>';
}

function membershipCell(m) {
  if (!m || !m.member) return '<td><span class="check-none">&ndash;</span></td>';
  if (m.via === 'Direct') return '<td><span class="check-direct" title="Direct member">&#10003;</span></td>';
  return '<td><span class="check-nested" title="Nested via: ' + esc(m.via) + '">&#10003;</span></td>';
}

function protectedCell(p) {
  if (!p || p.resolved === false) {
    return '<td><span class="check-none" title="Protected Users group could not be resolved">?</span></td>';
  }
  if (p.member) {
    if (p.via && p.via !== 'Direct') {
      return '<td><span class="check-nested" title="In Protected Users via: ' + esc(p.via) + '">&#10003;</span></td>';
    }
    return '<td><span class="check-direct" title="In Protected Users">&#10003;</span></td>';
  }
  return '<td><span class="not-protected" title="Not a member of Protected Users">&#10007;</span></td>';
}

function renderPrivileged() {
  const container = document.getElementById('privileged-container');
  const pa = data.privilegedAccess || null;

  if (!pa) {
    container.innerHTML = '<p class="muted">No privileged access information collected.</p>';
    return;
  }

  let html = '';

  // Cumulative privileged-account inventory: every account that is a member
  // (directly or through nesting) of any administrative group, with a column
  // per group and a final Protected Users column.
  html += '<div class="section-block"><h3>Privileged &amp; protected accounts</h3>';
  html += '<p class="muted">Every account that is a member &ndash; directly or through a nested group &ndash; of at least one administrative group or of Protected Users, showing the groups it belongs to and whether it is protected.</p>';

  const columns = pa.groupColumns || [];
  const pinv = pa.privilegedUsers || {};
  const users = pinv.users || [];

  if (users.length === 0) {
    html += '<p class="muted">No members were resolved in any administrative group or in Protected Users.</p>';
  } else {
    const protectedResolved = pinv.protectedResolved !== false;
    if (protectedResolved) {
      const protectedCount = users.filter(u => u.protected && u.protected.member).length;
      html += '<p class="muted">' + protectedCount + ' of ' + users.length +
        ' account(s) are in Protected Users.</p>';
    } else {
      html += '<p class="muted">Protected Users could not be resolved, so protection status is unknown for these accounts.</p>';
    }

    const headCols = columns.map(g => '<th>' + esc(g) + '</th>').join('');
    const rows = users.map(u => {
      const cells = columns.map(g => membershipCell((u.memberships || {})[g])).join('');
      return '<tr><td>' + esc(u.name) +
        (u.sam ? ' <span class="muted">(' + esc(u.sam) + ')</span>' : '') +
        '</td><td>' + esc(u.objectClass) + '</td>' + cells +
        protectedCell(u.protected) + '</tr>';
    }).join('');

    html += '<div class="matrix-wrap"><table class="matrix-table"><thead><tr><th>Account</th><th>Type</th>' +
      headCols + '<th>Protected Users</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    html += '<p class="muted legend"><span class="check-direct">&#10003;</span> direct member &nbsp;&nbsp; ' +
      '<span class="check-nested">&#10003;</span> member via a nested group (hover for the path) &nbsp;&nbsp; ' +
      '<span class="check-none">&ndash;</span> not a member &nbsp;&nbsp; ' +
      '<span class="not-protected">&#10007;</span> not in Protected Users</p>';
  }
  html += '</div>';

  // Recursive privileged group membership
  html += '<div class="section-block"><h3>Privileged group membership (recursive)</h3>';

  (pa.groups || []).forEach(g => {
    if (!g.found) {
      html += '<details class="gpo-block"><summary><span class="gpo-name">' + esc(g.displayName) + '</span>' + badge('unknown', 'Not resolved') + '</summary>' +
        '<div class="gpo-body"><p class="muted">' + esc(g.error) + '</p></div></details>';
      return;
    }

    const countBadge = g.memberCount === 0
      ? badge('secure', 'Empty')
      : badge('unknown', g.memberCount + ' member(s)');

    const nestedHtml = (g.nestedGroups && g.nestedGroups.length)
      ? '<ul>' + g.nestedGroups.map(n =>
          '<li>' + esc(n.name) +
          (n.via !== 'Direct' ? ' <span class="muted">(via ' + esc(n.via) + ')</span>' : '') +
          (n.error ? ' <span class="tag tag-warn" title="' + esc(n.error) + '">not expanded</span>' : '') +
          '</li>'
        ).join('') + '</ul>'
      : '<ul><li class="muted">None</li></ul>';

    const memberRows = (g.members || []).map(m =>
      '<tr><td>' + esc(m.name) + '</td><td>' + esc(m.sam) + '</td><td>' + esc(m.type) + '</td><td>' + esc(m.via) + '</td></tr>'
    ).join('');

    const truncNote = g.truncated
      ? '<p class="muted">Showing the first ' + g.members.length + ' of ' + g.memberCount + ' members; see CSV\\Privileged-Group-Members.csv for the full list.</p>'
      : '';

    html += '<details class="gpo-block"><summary><span class="gpo-name">' + esc(g.displayName) + '</span>' + countBadge +
      '<span class="muted"><code>' + esc(g.sid) + '</code></span></summary>' +
      '<div class="gpo-body">' +
      '<div class="gpo-columns" style="margin-bottom:14px;">' +
      '<div><h4>Nested groups</h4>' + nestedHtml + '</div>' +
      '<div><h4>Resolved group object</h4><ul><li>' + esc(g.groupName) + '</li></ul></div>' +
      '</div>' +
      (memberRows
        ? '<table class="findings-table"><thead><tr><th>Member</th><th>Account</th><th>Type</th><th>Via</th></tr></thead><tbody>' + memberRows + '</tbody></table>'
        : '<p class="muted">No members.</p>') +
      truncNote +
      '</div></details>';
  });

  html += '</div>';
  container.innerHTML = html;
}

function policyValueDays(v) {
  if (v === 0 || v >= 10000) return 'Not set / never';
  return v + ' days';
}

function policyTable(p) {
  let rows = '';

  const pwRow = (label, valueHtml, badgeHtml) =>
    '<tr><td>' + esc(label) + '</td><td>' + valueHtml + '</td><td>' + (badgeHtml || '') + '</td></tr>';

  rows += pwRow(
    'Minimum password length',
    esc(p.minPasswordLength) + ' characters',
    p.minPasswordLength >= 14
      ? badge('secure', 'Meets modern guidance')
      : (p.minPasswordLength >= 8 ? badge('partial', 'Below 14 characters') : badge('insecure', 'Weak minimum length'))
  );
  rows += pwRow(
    'Password complexity required',
    p.complexityEnabled ? 'Yes' : 'No',
    p.complexityEnabled ? badge('secure', 'Enabled') : badge('insecure', 'Disabled')
  );
  rows += pwRow(
    'Password history',
    esc(p.passwordHistoryCount) + ' passwords remembered',
    p.passwordHistoryCount >= 24
      ? badge('secure', '24 or more')
      : (p.passwordHistoryCount > 0 ? badge('partial', 'Below 24') : badge('insecure', 'No history'))
  );
  rows += pwRow('Maximum password age', esc(policyValueDays(p.maxPasswordAgeDays)), badge('unknown', 'Informational'));
  rows += pwRow('Minimum password age', esc(p.minPasswordAgeDays) + ' days', badge('unknown', 'Informational'));
  rows += pwRow(
    'Account lockout threshold',
    p.lockoutThreshold === 0 ? 'No lockout' : esc(p.lockoutThreshold) + ' invalid attempts',
    p.lockoutThreshold === 0 ? badge('insecure', 'Lockout disabled') : badge('secure', 'Lockout enabled')
  );
  rows += pwRow('Lockout duration', esc(p.lockoutDurationMinutes) + ' minutes', '');
  rows += pwRow('Lockout observation window', esc(p.lockoutObservationMinutes) + ' minutes', '');
  rows += pwRow(
    'Store passwords using reversible encryption',
    p.reversibleEncryptionEnabled ? 'Yes' : 'No',
    p.reversibleEncryptionEnabled ? badge('insecure', 'Enabled') : badge('secure', 'Disabled')
  );

  return '<table class="findings-table"><thead><tr><th>Setting</th><th>Value</th><th>Assessment</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderPasswordPolicy() {
  const container = document.getElementById('pwpolicy-container');
  const pp = data.passwordPolicy || {};
  let html = '';

  html += '<div class="section-block"><h3>Default domain password policy</h3>';
  if (pp.defaultPolicy) {
    html += policyTable(pp.defaultPolicy);
    html += '<p class="muted">Source: <code>' + esc(pp.defaultPolicy.distinguishedName) + '</code></p>';
  } else {
    html += '<p class="muted">Could not be collected: ' + esc(pp.defaultPolicyError || 'unknown error') + '</p>';
  }
  html += '</div>';

  html += '<div class="section-block"><h3>Fine-grained password policies (PSOs)</h3>';
  if (pp.fineGrainedError) {
    html += '<p class="muted">Could not be enumerated: ' + esc(pp.fineGrainedError) + '</p>';
  } else if (!pp.fineGrained || pp.fineGrained.length === 0) {
    html += '<p class="muted">No fine-grained password policies are defined in this domain. The default domain policy applies to all accounts.</p>';
  } else {
    pp.fineGrained.forEach(f => {
      const appliesTo = (f.appliesTo && f.appliesTo.length)
        ? f.appliesTo.map(a => esc(a)).join(', ')
        : '<span class="muted">nothing (not linked)</span>';

      html += '<details class="gpo-block"><summary><span class="gpo-name">' + esc(f.name) + '</span>' +
        '<span class="muted">Precedence ' + esc(f.precedence) + '</span></summary>' +
        '<div class="gpo-body"><p class="muted">Applies to: ' + appliesTo + '</p>' + policyTable(f) + '</div></details>';
    });
  }
  html += '</div>';

  container.innerHTML = html;
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

const policySearch = document.getElementById('policy-search');
const severityFilter = document.getElementById('severity-filter');
policySearch.addEventListener('input', () => renderPolicies(policySearch.value, severityFilter.value));
severityFilter.addEventListener('change', () => renderPolicies(policySearch.value, severityFilter.value));

const scopeSearch = document.getElementById('scope-search');
const onlyGapsToggle = document.getElementById('only-gaps');
scopeSearch.addEventListener('input', () => renderScope(scopeSearch.value, onlyGapsToggle.checked));
onlyGapsToggle.addEventListener('change', () => renderScope(scopeSearch.value, onlyGapsToggle.checked));

document.body.addEventListener('mouseover', e => {
  const el = e.target.closest('.trustee');
  if (!el) return;
  tooltip.innerHTML = tooltipContentForSid(el.dataset.sid, el.dataset.name);
  tooltip.style.display = 'block';
});

document.body.addEventListener('mousemove', e => {
  if (tooltip.style.display !== 'block') return;
  const offsetX = 16;
  const offsetY = 16;
  let left = e.clientX + offsetX;
  let top = e.clientY + offsetY;
  const maxLeft = window.innerWidth - tooltip.offsetWidth - 10;
  const maxTop = window.innerHeight - tooltip.offsetHeight - 10;
  if (left > maxLeft) left = e.clientX - tooltip.offsetWidth - offsetX;
  if (top > maxTop) top = e.clientY - tooltip.offsetHeight - offsetY;
  tooltip.style.left = Math.max(10, left) + 'px';
  tooltip.style.top = Math.max(10, top) + 'px';
});

document.body.addEventListener('mouseout', e => {
  const el = e.target.closest('.trustee');
  if (!el) return;
  tooltip.style.display = 'none';
});

renderSummary();
renderOverview();
renderPolicies('', 'all');
renderScope('', false);
renderPrivileged();
renderPasswordPolicy();
</script>
</body>
</html>
'@

    $DashboardHtml = $DashboardHtmlTemplate.Replace("__DASHBOARD_JSON__", $DashboardJsonSafe)
    $DashboardHtml = $DashboardHtml.Replace("__GENERATED_AT__", $DashboardData.generatedAt)
    $DashboardHtml = $DashboardHtml.Replace("__DOMAIN__", $DomainDnsRoot)
    $DashboardHtml = $DashboardHtml.Replace("__DC__", $DomainController)

    $DashboardHtmlPath = Join-Path $OutputPath "AUDIT-DASHBOARD.html"
    $DashboardHtml | Set-Content -LiteralPath $DashboardHtmlPath -Encoding UTF8

    Write-AuditLog "Dashboard written to: $DashboardHtmlPath"

    #######################################################################
    # Create human-readable audit summary
    #######################################################################

    $SummaryPath = Join-Path $OutputPath "AUDIT-SUMMARY.txt"

    $SmbServerRequired = @(
        $PolicyResults |
        Where-Object {
            $_.Setting -eq "SMB server signing required" -and
            $_.RegistryData -eq "1"
        }
    )

    $SmbClientRequired = @(
        $PolicyResults |
        Where-Object {
            $_.Setting -eq "SMB client signing required" -and
            $_.RegistryData -eq "1"
        }
    )

    $NtlmClientOnly = @(
        $PolicyResults |
        Where-Object {
            $_.Setting -eq "LAN Manager authentication level" -and
            $_.RegistryData -in @("3", "4")
        }
    )

    $NtlmFullyPrevented = @(
        $PolicyResults |
        Where-Object {
            $_.Setting -eq "LAN Manager authentication level" -and
            $_.RegistryData -eq "5"
        }
    )

    $ProtectedUsersSummaryText = "not resolved ($($ProtectedUsersResolution.Error))"

    if ($ProtectedUsersResolution.Found) {
        $ProtectedUsersSummaryText = "$ProtectedUsersMemberCount member(s)"
    }

    $SummaryLines = New-Object System.Collections.Generic.List[string]

    $SummaryLines.Add("GROUP POLICY SECURITY AUDIT EVIDENCE")
    $SummaryLines.Add("====================================")
    $SummaryLines.Add("")
    $SummaryLines.Add("Collection time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')")
    $SummaryLines.Add("Domain          : $DomainDnsRoot")
    $SummaryLines.Add("Domain controller: $DomainController")
    $SummaryLines.Add("Collector       : $env:COMPUTERNAME")
    $SummaryLines.Add("")
    $SummaryLines.Add("RESULT COUNTS")
    $SummaryLines.Add("-------------")
    $SummaryLines.Add(
        "GPOs requiring inbound/server SMB signing : $($SmbServerRequired.Count)"
    )
    $SummaryLines.Add(
        "GPOs requiring outbound/client SMB signing: $($SmbClientRequired.Count)"
    )
    $SummaryLines.Add(
        "GPOs preventing outbound NTLMv1 only      : $($NtlmClientOnly.Count)"
    )
    $SummaryLines.Add(
        "GPOs refusing inbound and outbound NTLMv1 : $($NtlmFullyPrevented.Count)"
    )
    $SummaryLines.Add(
        "Domain/OU targets that failed inheritance evaluation: $($InheritanceErrorResults.Count) of $($ScopeTargets.Count)"
    )
    $SummaryLines.Add(
        "Security-filtering groups with resolved membership: $($GroupMembershipCache.Keys.Count)"
    )
    $SummaryLines.Add(
        "GPOs where GptTmpl.inf could not be read from SYSVOL: $($GptTmplAccessErrors.Count)"
    )
    $SummaryLines.Add(
        "Domain controllers found                  : $($DomainControllerInventory.Count)"
    )
    $SummaryLines.Add(
        "Protected Users                           : $ProtectedUsersSummaryText"
    )
    $SummaryLines.Add(
        "Privileged groups resolved                : $ResolvedPrivilegedGroupCount of $($PrivilegedGroupDefinitions.Count)"
    )
    $SummaryLines.Add(
        "Fine-grained password policies            : $($FineGrainedPolicyDashboard.Count)"
    )
    $SummaryLines.Add("")
    $SummaryLines.Add("INTERPRETATION")
    $SummaryLines.Add("--------------")
    $SummaryLines.Add(
        "SMB signing is enforced when RequireSecuritySignature is configured as 1."
    )
    $SummaryLines.Add(
        "LmCompatibilityLevel 3 or 4 prevents clients from sending NTLMv1, but does not fully prevent the system from accepting NTLMv1."
    )
    $SummaryLines.Add(
        "LmCompatibilityLevel 5 sends NTLMv2 only and refuses inbound LM and NTLMv1."
    )
    $SummaryLines.Add(
        "The privileged-accounts inventory in the dashboard lists every account that is a member (directly or through a nested group) of any administrative group, with a column per group and whether the account is in Protected Users."
    )
    $SummaryLines.Add("")
    $SummaryLines.Add("IMPORTANT SCOPE LIMITATION")
    $SummaryLines.Add("--------------------------")
    $SummaryLines.Add(
        "The structural scope export shows domain and OU containers where a GPO appears in InheritedGpoLinks."
    )
    $SummaryLines.Add(
        "Final applicability can still be affected by security filtering, WMI filtering, disabled GPO sections, client-side processing and object permissions."
    )
    $SummaryLines.Add(
        "Domain/OU targets listed in Inheritance-Evaluation-Errors.csv could not be checked at all; treat them as evidence gaps, not as confirmed absence of a policy."
    )
    $SummaryLines.Add(
        "Group membership shown in the dashboard is capped at $MaxGroupMembersToDisplay members per group; see the group members CSV for the complete list."
    )
    $SummaryLines.Add(
        "GPOs listed in GptTmpl-Access-Errors.csv could not be read from SYSVOL (e.g. delegated ACLs, replication lag); their configured-setting evidence is incomplete, not confirmed absent."
    )
    $SummaryLines.Add(
        "Privileged groups reported as 'not resolved' could not be located (for example because they do not exist at this functional level, or live in another domain of the forest); treat these as evidence gaps, not as confirmed-empty groups."
    )
    $SummaryLines.Add(
        "Privileged group members with type 'unresolved' are member references that could not be resolved against the selected domain controller (e.g. foreign security principals)."
    )
    $SummaryLines.Add(
        "Use gpresult or Resultant Set of Policy for endpoint-specific implementation evidence."
    )
    $SummaryLines.Add("")
    $SummaryLines.Add("EVIDENCE FILES")
    $SummaryLines.Add("--------------")
    $SummaryLines.Add("AUDIT-DASHBOARD.html (open in a browser)")
    $SummaryLines.Add("CSV\Configured-Security-Policies.csv")
    $SummaryLines.Add("CSV\GptTmpl-Access-Errors.csv")
    $SummaryLines.Add("CSV\Relevant-GPO-Direct-Links.csv")
    $SummaryLines.Add("CSV\Relevant-GPO-Structural-Scope.csv")
    $SummaryLines.Add("CSV\Relevant-GPO-Permissions.csv")
    $SummaryLines.Add("CSV\Relevant-GPO-Security-Filtering-Group-Members.csv")
    $SummaryLines.Add("CSV\Relevant-GPO-WMI-Filters.csv")
    $SummaryLines.Add("CSV\Inheritance-Evaluation-Errors.csv")
    $SummaryLines.Add("CSV\Domain-Information.csv")
    $SummaryLines.Add("CSV\Domain-Controllers.csv")
    $SummaryLines.Add("CSV\Password-Policy.csv")
    $SummaryLines.Add("CSV\Fine-Grained-Password-Policies.csv")
    $SummaryLines.Add("CSV\Privileged-Group-Members.csv")
    $SummaryLines.Add("CSV\Privileged-Group-Nested-Groups.csv")
    $SummaryLines.Add("CSV\Privileged-Account-Membership-Matrix.csv")
    $SummaryLines.Add("GPO-Reports-HTML\")
    $SummaryLines.Add("GPO-Reports-XML\")
    $SummaryLines.Add("Raw-GptTmpl-INF\")
    $SummaryLines.Add("Metadata\Collection-Metadata.csv")
    $SummaryLines.Add("Metadata\Dashboard-Data.json")
    $SummaryLines.Add("Metadata\Evidence-File-Hashes-SHA256.csv")

    $SummaryLines |
        Set-Content `
            -LiteralPath $SummaryPath `
            -Encoding UTF8

    #######################################################################
    # Generate SHA-256 hashes
    #
    # The hash manifest can be used to demonstrate that the exported
    # evidence files have not changed after collection.
    #######################################################################

    $HashManifestPath = Join-Path `
        $Directories.Metadata `
        "Evidence-File-Hashes-SHA256.csv"

    $EvidenceFiles = @(
        Get-ChildItem `
            -LiteralPath $OutputPath `
            -File `
            -Recurse |
        Where-Object {
            $_.FullName -ne $HashManifestPath -and
            $_.FullName -ne $TranscriptPath
        }
    )

    $HashResults = foreach ($EvidenceFile in $EvidenceFiles) {
        $Hash = Get-FileHash `
            -LiteralPath $EvidenceFile.FullName `
            -Algorithm SHA256

        [PSCustomObject]@{
            RelativePath = $EvidenceFile.FullName.Substring(
                $OutputPath.Length
            ).TrimStart("\")
            LengthBytes  = $EvidenceFile.Length
            LastWriteTime = $EvidenceFile.LastWriteTime
            Algorithm    = $Hash.Algorithm
            SHA256       = $Hash.Hash
        }
    }

    $HashResults |
        Sort-Object RelativePath |
        Export-Csv `
            -Path $HashManifestPath `
            -NoTypeInformation `
            -Encoding UTF8

    Write-AuditLog "Evidence collection completed successfully."
    Write-AuditLog "Evidence directory: $OutputPath"
}
catch {
    Write-AuditLog `
        -Level "ERROR" `
        -Message $_.Exception.Message

    throw
}
finally {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # A transcript may not have started if initialization failed.
    }
}