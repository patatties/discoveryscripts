# ================================
# CONFIG
# ================================
$ApiKey = "eyJh<...omitted...>DN8g"
$BaseUrl = "https://eu.api.knowbe4.com/v1"
$Headers = @{
    "Authorization" = "Bearer $ApiKey"
    "Accept"        = "application/json"
}
$DataFolder = ".\KnowBe4Data"
# Maak folder als die niet bestaat
if (-not (Test-Path $DataFolder)) {
    New-Item -ItemType Directory -Path $DataFolder | Out-Null
}
# ================================
# PAGING FUNCTIE
# ================================
function Get-AllPages {
    param ($Endpoint)
    $results = @()
    $page = 1
    $perPage = 500
    do {
        $url = "{0}?page={1}&per_page={2}" -f $Endpoint.Trim().TrimEnd('/'), $page, $perPage
        Write-Host "Fetching page $page..."
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
        }
        catch {
            if ($_.Exception.Message -like "*429*") {
                Write-Host "Rate limit - even wachten..."
                Start-Sleep -Seconds 10
                continue
            } else {
                throw
            }
        }
        if ($response -and $response.Count -gt 0) {
            $results += $response
            $page++
            Start-Sleep -Milliseconds 200
        } else {
            break
        }
    } while ($true)
    return $results
}
# ================================
# DATA OPHALEN
# ================================
Write-Host "Users ophalen..."
$Users = Get-AllPages "$BaseUrl/users"
Write-Host "Enrollments ophalen..."
$Enrollments = Get-AllPages "$BaseUrl/training/enrollments"
# ================================
# OPSLAAN NAAR FILES
# ================================
$Users | ConvertTo-Json -Depth 5 | Out-File "$DataFolder\users.json"
$Enrollments | ConvertTo-Json -Depth 5 | Out-File "$DataFolder\enrollments.json"
Write-Host "Data opgeslagen in $DataFolder"