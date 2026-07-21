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
# - IPv4-adres
# - SMBv1 enabled
# - SMB Signing forced
# - NTLMv1 allowed (based on LmCompatibilityLevel)
# - NetBIOS configuration
# - NetBIOS active (TCP/139 listening)
###########################################################################

$Results = foreach ($Server in $Servers) {

    Write-Host "Checking $Server..."

    try {

        Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {

            # gather first usable IPv4-address
            $IP = Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object {
                    $_.IPAddress -notlike '169.254*' -and
                    $_.IPAddress -ne '127.0.0.1'
                } |
                Select-Object -First 1 -ExpandProperty IPAddress

            # SMBv1
            $SMBv1 = (Get-SmbServerConfiguration).EnableSMB1Protocol

            # SMB Signing
            $SMBSigning = (Get-SmbServerConfiguration).RequireSecuritySignature

            # NTLM configuration
            $LMCompat = (
                Get-ItemProperty `
                "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ).LmCompatibilityLevel

            if ($null -eq $LMCompat) {
                $LMCompat = "NotConfigured"
                $NTLMv1Allowed = "Unknown"
            }
            elseif ($LMCompat -lt 3) {
                $NTLMv1Allowed = "Yes"
            }
            else {
                $NTLMv1Allowed = "No"
            }

            # NetBIOS configuration
            $NetBIOSConfig = Get-CimInstance Win32_NetworkAdapterConfiguration |
                Where-Object {$_.IPEnabled -eq $true} |
                Select-Object -First 1 -ExpandProperty TcpipNetbiosOptions

            switch ($NetBIOSConfig) {
                0 { $NetBIOSConfig = "DHCP" }
                1 { $NetBIOSConfig = "Enabled" }
                2 { $NetBIOSConfig = "Disabled" }
                default { $NetBIOSConfig = "Unknown" }
            }

            # Is Netbios actually active?
            try {
                $Port139 = Get-NetTCPConnection `
                    -LocalPort 139 `
                    -State Listen `
                    -ErrorAction Stop

                $NetBIOSActive = "Yes"
            }
            catch {
                $NetBIOSActive = "No"
            }

            New-Object PSObject -Property @{
                Server          = $env:COMPUTERNAME
                IPAddress       = $IP
                SMBv1           = $SMBv1
                SMBSigning      = $SMBSigning
                LMCompatLevel   = $LMCompat
                NTLMv1Allowed   = $NTLMv1Allowed
                NetBIOSConfig   = $NetBIOSConfig
                NetBIOSActive   = $NetBIOSActive
                CheckedAt       = (Get-Date)
                Status          = "Connected"
            }

        }

    }
    catch {

        New-Object PSObject -Property @{
            Server          = $Server
            IPAddress       = ""
            SMBv1           = ""
            SMBSigning      = ""
            LMCompatLevel   = ""
            NTLMv1Allowed   = ""
            NetBIOSConfig   = ""
            NetBIOSActive   = ""
            CheckedAt       = ""
            Status          = "ERROR"
        }

    }
}

###########################################################################
# 3. Show results
###########################################################################

$Results | Format-Table `
    Server,
    IPAddress,
    SMBv1,
    SMBSigning,
    NTLMv1Allowed,
    NetBIOSConfig,
    NetBIOSActive,
    Status `
    -AutoSize