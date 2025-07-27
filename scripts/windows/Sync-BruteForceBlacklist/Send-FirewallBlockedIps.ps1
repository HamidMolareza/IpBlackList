# === CONFIGURATION ===
$apiUrl = "http://domain.com/blacklist" 
$apiKey = "client-name:client-key"
$headers = @{ "X-Api-Key" = $apiKey }

# === GET BLOCKED IPs FROM WINDOWS FIREWALL ===
$firewallRules = Get-NetFirewallRule -DisplayName "BlockBruteForce_*" -ErrorAction SilentlyContinue
if (-not $firewallRules) {
    Write-Host "No matching firewall rules found (BlockBruteForce_*)."
    return
}

$blockedIps = @()

foreach ($rule in $firewallRules) {
    $ruleName = $rule.DisplayName
    $ip = ($ruleName -replace '^BlockBruteForce_', '').Trim()
    
    if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$') {
        $blockedIps += $ip
    } else {
        Write-Host "Skipping invalid IP: $ip from rule: $ruleName"
    }
}

# === SEND BLOCKED IPs TO API ===
foreach ($ip in $blockedIps) {
    $body = @{ BlackIp = $ip } | ConvertTo-Json -Depth 2

    try {
        Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body -ContentType "application/json"
        Write-Host "✅ Sent IP $ip to blacklist API." -ForegroundColor Cyan
    } catch {
        Write-Warning "⚠️ Failed to send IP $ip to server. Error: $_"
    }
}
