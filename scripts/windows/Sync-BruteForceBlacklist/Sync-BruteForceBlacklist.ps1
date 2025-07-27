# Define the URL of your blacklist API
$apiUrl = "http://domain.com/blacklist" 
$apiKey = "client-name:client-key"

# Prepare headers
$headers = @{
    "X-Api-Key" = $apiKey
}

# Get currently blocked IPs from Windows Firewall (by your naming pattern)
$localBlockedIps = Get-NetFirewallRule -DisplayName "BlockBruteForce_*" |
    ForEach-Object {
        $ruleName = $_.DisplayName
        $ip = ($ruleName -replace '^BlockBruteForce_', '')
        $ip.Trim()
    }

# Get the remote blacklist from your API
try {
    $remoteBlackIps = Invoke-RestMethod -Uri $apiUrl -Method GET -Headers $headers
} catch {
    Write-Error "Failed to get remote blacklist from $apiUrl"
    exit 1
}

# Extract IPs from response
$remoteIps = $remoteBlackIps | Select-Object -ExpandProperty BlackIp

# Find new IPs that are not yet blocked
$newIps = $remoteIps | Where-Object { $_ -and ($localBlockedIps -notcontains $_) }

# Block new IPs
foreach ($ip in $newIps) {
    $ruleName = "BlockBruteForce_$ip"
    Write-Host "Blocking IP: $ip"

    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $ip `
        -Description "Blocked from centralized blacklist" `
        -Protocol TCP `
        -Profile Any
}
