# PowerShell Script to Check Hashes in VirusTotal
# Requirements: VirusTotal API Key

param (
    [string]$ApiKey,             # VirusTotal API Key
    [string]$HashFilePath        # Path to file containing hashes (one per line)
)

# Check if required parameters are provided
if (-not $ApiKey -or -not $HashFilePath) {
    Write-Host "Usage: .\VirusTotalCheck.ps1 -ApiKey <YourApiKey> -HashFilePath <PathToHashFile>"
    exit 1
}

# Load hashes from the provided file
$hashes = Get-Content -Path $HashFilePath

# VirusTotal API URL
$apiUrl = "https://www.virustotal.com/api/v3/files/"

# Counter for rate limiting
$count = 0

foreach ($hash in $hashes) {
    $count++
    $headers = @{ "x-apikey" = $ApiKey }

    try {
        $response = Invoke-RestMethod -Uri "$apiUrl$hash" -Headers $headers -Method GET
        
        # Extract meaningful data from response
        $fileName = $response.data.attributes.meaningful_name
        $detections = $response.data.attributes.last_analysis_stats.malicious

        Write-Output "Hash: $hash"
        Write-Output "File Name: $fileName"
        Write-Output "Detections: $detections"
        Write-Output "----------------------------------------"
    }
    catch {
        Write-Output "Hash: $hash - Error: Failed to retrieve data or hash not found."
        Write-Output "----------------------------------------"
    }

    # Pause for 60 seconds after every 4 requests
    if ($count % 4 -eq 0) {
        Write-Host "Pausing for 1 minute to comply with VirusTotal's rate limit..."
        Start-Sleep -Seconds 60
    }
}
