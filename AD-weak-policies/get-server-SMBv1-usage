#################################################
# SMBv1 Assessment
#################################################

Write-Host "`n=== OS Information ===" -ForegroundColor Cyan

Get-CimInstance Win32_OperatingSystem |
Select-Object @{
    Name='ComputerName';Expression={$env:COMPUTERNAME}
},Caption,Version |
Format-Table -AutoSize

Write-Host "`n=== SMBv1 Feature Status ===" -ForegroundColor Cyan

Get-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue |
Format-Table Name,InstallState -AutoSize

Write-Host "`n=== SMB Server Configuration ===" -ForegroundColor Cyan

Get-SmbServerConfiguration |
Select-Object EnableSMB1Protocol,EnableSMB2Protocol,AuditSmb1Access |
Format-List

Write-Host "`n=== Shared Folders ===" -ForegroundColor Cyan
net share

Write-Host "`n=== Last 20 SMBv1 Events ===" -ForegroundColor Cyan

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-SMBServer/Audit'
    Id=3000
} -MaxEvents 20 |
Select-Object TimeCreated,Id |
Format-Table -AutoSize

Write-Host "`n=== SMBv1 Event Count (Last 30 Days) ===" -ForegroundColor Cyan

$count = (
    Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-SMBServer/Audit'
        Id=3000
        StartTime=(Get-Date).AddDays(-30)
    } -ErrorAction SilentlyContinue
).Count

Write-Host "Events found: $count"

Write-Host "`n=== Active SMB Sessions ===" -ForegroundColor Cyan

Get-SmbSession -ErrorAction SilentlyContinue |
Select-Object ClientComputerName,ClientUserName |
Format-Table -AutoSize

Write-Host "`n=== SMBv1 Audit Recommendation ===" -ForegroundColor Cyan

if ($count -eq 0) {
    Write-Host "No SMBv1 usage detected in last 30 days." -ForegroundColor Green
}
else {
    Write-Warning "$count SMBv1 events found in last 30 days."
}