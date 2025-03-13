# PowerShell Script to Check Hashes in VirusTotal API
param (
    [string]$apiKey = "0a70717ae4f34fadc3debabfe7b08161793632b882ff62943b9a9fb4f1d822a6",                  # Your VirusTotal API Key
    [string]$hashFile = "C:\Users\niran\Desktop\hashes.txt"   # File containing list of hashes (one per line)
)

# Ensure API key is provided
if (-not $apiKey) {
    Write-Host "Error: API key is required." -ForegroundColor Red
    exit 1
}

# Ensure hash file exists
if (-not (Test-Path $hashFile)) {
    Write-Host "Error: Hash file not found." -ForegroundColor Red
    exit 1
}

# Load hashes from file
$hashes = Get-Content -Path $hashFile

# Counter for API rate limit handling
$counter = 0

foreach ($hash in $hashes) {
    $url = "https://www.virustotal.com/api/v3/files/$hash"

    # Send API request to VirusTotal
    try {
        $response = Invoke-RestMethod -Uri $url -Headers @{ "x-apikey" = $apiKey } -Method Get

        # Extract relevant information from response
        $fileName = $response.data.attributes.names -join ", "
        $category = $response.data.attributes.type_description
        $detections = $response.data.attributes.last_analysis_stats

        # Display the results
        Write-Output "Hash: $hash"
        Write-Output "File Name: $fileName"
        Write-Output "Category: $category"
        Write-Output "Detections: $detections"
        Write-Output "-------------------------"
    } catch {
        Write-Host "Error checking hash $hash : $_" -ForegroundColor Yellow
    }

    # Rate limit handling: Pause after every 4 requests
    $counter++
    if ($counter -eq 4) {
        Write-Host "Pausing for 1 minute to respect VirusTotal's rate limit..." -ForegroundColor Cyan
        Start-Sleep -Seconds 60
        $counter = 0
    }
}

Write-Host "Script completed successfully." -ForegroundColor Green
