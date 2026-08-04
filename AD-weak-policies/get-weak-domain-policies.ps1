# THIS SCRIPT IS INTENDED TO BE RUN FROM A DOMAIN JOINED COMPUTER WITH DOMAIN ADMIN PRIVILEGES

###########################################################################
# 1. GET SERVER LIST VIA LDAP
###########################################################################

$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.PageSize = 1000
$Searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*Server*))"

$Servers = $Searcher.FindAll() |
    ForEach-Object { $_.Properties.name[0] } |
    Sort-Object

###########################################################################
# 2. TESTS PER SERVER
#
# Checks:
# - Reachability via WinRM
# - Windows product name, version and build
# - IPv4 address
# - SMBv1 enabled
# - SMB Signing forced
# - NTLMv1 allowed, based on LmCompatibilityLevel
# - NetBIOS configuration
# - NetBIOS active, TCP/139 listening
###########################################################################

$Results = foreach ($Server in $Servers) {

    Write-Host "Checking $Server..."

    try {

        Invoke-Command `
            -ComputerName $Server `
            -ErrorAction Stop `
            -ScriptBlock {

                ################################################################
                # Windows operating system information
                ################################################################

                $OperatingSystem = Get-CimInstance `
                    -ClassName Win32_OperatingSystem `
                    -ErrorAction Stop

                $WindowsVersion = $OperatingSystem.Caption
                $OSVersion      = $OperatingSystem.Version
                $OSBuild        = $OperatingSystem.BuildNumber

                ################################################################
                # Gather first usable IPv4 address
                ################################################################

                $IP = Get-NetIPAddress `
                    -AddressFamily IPv4 `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.IPAddress -notlike "169.254*" -and
                        $_.IPAddress -ne "127.0.0.1"
                    } |
                    Select-Object -First 1 -ExpandProperty IPAddress

                ################################################################
                # SMBv1 and SMB Signing
                ################################################################

                $SMBConfiguration = Get-SmbServerConfiguration `
                    -ErrorAction Stop

                $SMBv1      = $SMBConfiguration.EnableSMB1Protocol
                $SMBSigning = $SMBConfiguration.RequireSecuritySignature

                ################################################################
                # NTLM configuration
                ################################################################

                $LMCompat = (
                    Get-ItemProperty `
                        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                        -ErrorAction SilentlyContinue
                ).LmCompatibilityLevel

                if ($null -eq $LMCompat) {
                    $LMCompat       = "NotConfigured"
                    $NTLMv1Allowed  = "Unknown"
                }
                elseif ($LMCompat -lt 3) {
                    $NTLMv1Allowed = "Yes"
                }
                else {
                    $NTLMv1Allowed = "No"
                }

                ################################################################
                # NetBIOS configuration
                ################################################################

                $NetBIOSConfig = Get-CimInstance `
                    -ClassName Win32_NetworkAdapterConfiguration `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.IPEnabled -eq $true
                    } |
                    Select-Object `
                        -First 1 `
                        -ExpandProperty TcpipNetbiosOptions

                switch ($NetBIOSConfig) {
                    0       { $NetBIOSConfig = "DHCP" }
                    1       { $NetBIOSConfig = "Enabled" }
                    2       { $NetBIOSConfig = "Disabled" }
                    default { $NetBIOSConfig = "Unknown" }
                }

                ################################################################
                # Is NetBIOS actually active?
                ################################################################

                try {
                    $null = Get-NetTCPConnection `
                        -LocalPort 139 `
                        -State Listen `
                        -ErrorAction Stop

                    $NetBIOSActive = "Yes"
                }
                catch {
                    $NetBIOSActive = "No"
                }

                ################################################################
                # Return result
                ################################################################

                [PSCustomObject]@{
                    Server          = $env:COMPUTERNAME
                    IPAddress       = $IP
                    WindowsVersion  = $WindowsVersion
                    OSVersion       = $OSVersion
                    OSBuild         = $OSBuild
                    SMBv1           = $SMBv1
                    SMBSigning      = $SMBSigning
                    LMCompatLevel   = $LMCompat
                    NTLMv1Allowed   = $NTLMv1Allowed
                    NetBIOSConfig   = $NetBIOSConfig
                    NetBIOSActive   = $NetBIOSActive
                    CheckedAt       = Get-Date
                    Status          = "Connected"
                }
            }
    }
    catch {

        [PSCustomObject]@{
            Server          = $Server
            IPAddress       = ""
            WindowsVersion  = ""
            OSVersion       = ""
            OSBuild         = ""
            SMBv1           = ""
            SMBSigning      = ""
            LMCompatLevel   = ""
            NTLMv1Allowed   = ""
            NetBIOSConfig   = ""
            NetBIOSActive   = ""
            CheckedAt       = Get-Date
            Status          = "ERROR: $($_.Exception.Message)"
        }
    }
}

###########################################################################
# 3. SHOW RESULTS
###########################################################################

$Results |
    Format-Table `
        Server,
        IPAddress,
        WindowsVersion,
        OSVersion,
        OSBuild,
        SMBv1,
        SMBSigning,
        NTLMv1Allowed,
        NetBIOSConfig,
        NetBIOSActive,
        Status `
        -AutoSize
