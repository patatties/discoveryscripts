# ================================
# CONFIG
# ================================
$DataFolder = ".\KnowBe4Data"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$OutputFile = "KnowBe4_Report_$timestamp.xlsx"

# ================================
# CHECK ImportExcel
# ================================
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Install-Module ImportExcel -Scope CurrentUser -Force
}
Import-Module ImportExcel

# ================================
# DATA INLEZEN
# ================================
$Users       = Get-Content "$DataFolder\users.json" -Raw | ConvertFrom-Json
$Enrollments = Get-Content "$DataFolder\enrollments.json" -Raw | ConvertFrom-Json

$ActiveUsers = $Users | Where-Object { $_.status -eq "active" }

# ================================
# USER LOOKUP
# ================================
$UserLookup = @{}
foreach ($u in $ActiveUsers) {
    $UserLookup["$($u.id)"] = $u
}

# ================================
# DATASET (MET NAME + EMAIL)
# ================================
$Data = @()

foreach ($e in $Enrollments) {

    if (-not $e.user -or -not $e.user.id) { continue }

    $uid = "$($e.user.id)"
    if (-not $UserLookup.ContainsKey($uid)) { continue }

    $user = $UserLookup[$uid]

    $module = $e.module_name
    if (-not $module) { $module = $e.content_title }
    if (-not $module) { $module = $e.training_name }
    if (-not $module) { $module = $e.campaign_name }

    $Data += [PSCustomObject]@{
        UserId     = $user.id
        Name       = "$($user.first_name) $($user.last_name)"
        Email      = $user.email

        Department = $user.department
        Location   = $user.location

        ModuleName = $module
        Status     = $e.status

        # nieuwe kolom
        InsideManCompleted = 0
    }
}

# ================================
# INSIDE MAN COUNT PER USER
# ================================
$InsideManCount = @{}

foreach ($row in $Data) {

    if ($row.ModuleName -like "The Inside Man*" -and $row.Status -eq "Passed") {

        $uid = $row.UserId

        if (-not $InsideManCount.ContainsKey($uid)) {
            $InsideManCount[$uid] = 0
        }

        $InsideManCount[$uid]++
    }
}

# ================================
# INSIDE MAN COUNT TOEVOEGEN
# ================================
foreach ($row in $Data) {

    if ($InsideManCount.ContainsKey($row.UserId)) {
        $row.InsideManCompleted = $InsideManCount[$row.UserId]
    }
    else {
        $row.InsideManCompleted = 0
    }
}

# ================================
# AGGREGATIE
# ================================
$Stats = @{}
function Get-Key($l,$d){ "$l||$d" }

foreach ($row in $Data) {

    $loc = if ($row.Location) { $row.Location } else { "Unknown" }
    $dep = if ($row.Department) { $row.Department } else { "Unknown" }
    $key = Get-Key $loc $dep

    if (-not $Stats.ContainsKey($key)) {
        $Stats[$key] = [ordered]@{
            Location = $loc
            Department = $dep

            "Security Awareness Training Offered"   = 0
            "Security Awareness Training Completed" = 0

            "The Inside Man Offered"   = 0
            "The Inside Man Completed" = 0

            "Phish Alert Offered"   = 0
            "Phish Alert Completed" = 0

            "Executive AI Offered"   = 0
            "Executive AI Completed" = 0
        }
    }

    $module = $row.ModuleName
    $status = $row.Status

    if ($module -like "2025 KnowBe4 Security Awareness Training - 30 Minutes") {
        if ($status) { $Stats[$key]["Security Awareness Training Offered"]++ }
        if ($status -eq "Passed") { $Stats[$key]["Security Awareness Training Completed"]++ }
    }

    if ($module -like "The Inside Man*") {
        if ($status) { $Stats[$key]["The Inside Man Offered"]++ }
        if ($status -eq "Passed") { $Stats[$key]["The Inside Man Completed"]++ }
    }

    if ($module -like "*Phish Alert Button*") {
        if ($status) { $Stats[$key]["Phish Alert Offered"]++ }
        if ($status -eq "Passed") { $Stats[$key]["Phish Alert Completed"]++ }
    }

    if ($module -like "Executive Series: Artificial Intelligence") {
        if ($status) { $Stats[$key]["Executive AI Offered"]++ }
        if ($status -eq "Passed") { $Stats[$key]["Executive AI Completed"]++ }
    }
}

# ================================
# SUMMARY
# ================================
$Summary = @()

foreach ($entry in $Stats.Values) {

    $Summary += [PSCustomObject]@{
        Location = $entry.Location
        Department = $entry.Department

        "Security Awareness Training Offered"   = $entry["Security Awareness Training Offered"]
        "Security Awareness Training Completed" = $entry["Security Awareness Training Completed"]
        "Security Awareness Training Not Completed" = ($entry["Security Awareness Training Offered"] - $entry["Security Awareness Training Completed"])

        "The Inside Man Offered"   = $entry["The Inside Man Offered"]
        "The Inside Man Completed" = $entry["The Inside Man Completed"]
        "The Inside Man Not Completed" = ($entry["The Inside Man Offered"] - $entry["The Inside Man Completed"])

        "Phish Alert Offered"   = $entry["Phish Alert Offered"]
        "Phish Alert Completed" = $entry["Phish Alert Completed"]
        "Phish Alert Not Completed" = ($entry["Phish Alert Offered"] - $entry["Phish Alert Completed"])

        "Executive AI Offered"   = $entry["Executive AI Offered"]
        "Executive AI Completed" = $entry["Executive AI Completed"]
        "Executive AI Not Completed" = ($entry["Executive AI Offered"] - $entry["Executive AI Completed"])
    }
}

# ================================
# SORTERING
# ================================
$Summary = $Summary | Sort-Object Location, Department

# ================================
# TOTALS
# ================================
$Totals = [PSCustomObject]@{
    Location = "TOTAL"
    Department = ""

    "Security Awareness Training Offered"   = ($Summary | Measure-Object "Security Awareness Training Offered" -Sum).Sum
    "Security Awareness Training Completed" = ($Summary | Measure-Object "Security Awareness Training Completed" -Sum).Sum
    "Security Awareness Training Not Completed" = ($Summary | Measure-Object "Security Awareness Training Not Completed" -Sum).Sum

    "The Inside Man Offered"   = ($Summary | Measure-Object "The Inside Man Offered" -Sum).Sum
    "The Inside Man Completed" = ($Summary | Measure-Object "The Inside Man Completed" -Sum).Sum
    "The Inside Man Not Completed" = ($Summary | Measure-Object "The Inside Man Not Completed" -Sum).Sum

    "Phish Alert Offered"   = ($Summary | Measure-Object "Phish Alert Offered" -Sum).Sum
    "Phish Alert Completed" = ($Summary | Measure-Object "Phish Alert Completed" -Sum).Sum
    "Phish Alert Not Completed" = ($Summary | Measure-Object "Phish Alert Not Completed" -Sum).Sum

    "Executive AI Offered"   = ($Summary | Measure-Object "Executive AI Offered" -Sum).Sum
    "Executive AI Completed" = ($Summary | Measure-Object "Executive AI Completed" -Sum).Sum
    "Executive AI Not Completed" = ($Summary | Measure-Object "Executive AI Not Completed" -Sum).Sum
}

$FinalTable = @($Totals) + $Summary

# ================================
# EXPORT
# ================================
if (Test-Path $OutputFile) { Remove-Item $OutputFile }

$Data | Export-Excel -Path $OutputFile -WorksheetName "Data" -TableName "RawData" -AutoSize

$FinalTable | Export-Excel -Path $OutputFile -WorksheetName "Tabel" -TableName "SummaryTable" -BoldTopRow -ClearSheet

# ================================
# STYLING
# ================================
$excel = Open-ExcelPackage -Path $OutputFile
$ws = $excel.Workbook.Worksheets["Tabel"]

$rowCount = $FinalTable.Count + 1

$ws.Cells["A2:N2"].Style.Font.Bold = $true

Add-ConditionalFormatting -Worksheet $ws -Address "E3:E$rowCount" -RuleType Equal -ConditionValue "0" -BackgroundColor Green
Add-ConditionalFormatting -Worksheet $ws -Address "E3:E$rowCount" -RuleType GreaterThan -ConditionValue "0" -BackgroundColor Red

Add-ConditionalFormatting -Worksheet $ws -Address "H3:H$rowCount" -RuleType Equal -ConditionValue "0" -BackgroundColor Green
Add-ConditionalFormatting -Worksheet $ws -Address "H3:H$rowCount" -RuleType GreaterThan -ConditionValue "0" -BackgroundColor Red

Add-ConditionalFormatting -Worksheet $ws -Address "K3:K$rowCount" -RuleType Equal -ConditionValue "0" -BackgroundColor Green
Add-ConditionalFormatting -Worksheet $ws -Address "K3:K$rowCount" -RuleType GreaterThan -ConditionValue "0" -BackgroundColor Red

Add-ConditionalFormatting -Worksheet $ws -Address "N3:N$rowCount" -RuleType Equal -ConditionValue "0" -BackgroundColor Green
Add-ConditionalFormatting -Worksheet $ws -Address "N3:N$rowCount" -RuleType GreaterThan -ConditionValue "0" -BackgroundColor Red

$ws.Cells["A1:N1"].Style.TextRotation = 45

$ws.Column(1).Width = 18
$ws.Column(2).Width = 20
for ($i = 3; $i -le 14; $i++) { $ws.Column($i).Width = 14 }

$ws.View.FreezePanes(3,1)
$ws.Select()

Close-ExcelPackage $excel

Write-Host "✅ Excel rapport gemaakt: $OutputFile"
