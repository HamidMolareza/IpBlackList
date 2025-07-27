#requires -version 5.1

<#
.SYNOPSIS
    Detects and blocks potential brute-force login attempts with detailed analysis of targeted usernames and attacker intent.
.DESCRIPTION
    Analyzes Security event log for failed login attempts (Event ID 4625), groups by IP and username, infers attacker intent,
    and blocks suspicious IPs using Windows Firewall. Includes a whitelist to avoid blocking trusted IPs with proper CIDR range checking.
.PARAMETER Hours
    Number of hours to look back in the event log. Default is 1 hour.
.PARAMETER Attempts
    Number of failed login attempts to trigger an alert and block. Default is 10 attempts.
.PARAMETER Whitelist
    Array of trusted IP addresses or CIDR ranges to exclude from blocking. Default includes local IPs.
.EXAMPLE
    .\Detect-BruteForceDetailed.ps1 -Hours 3 -Attempts 15 -Whitelist @("192.168.1.100", "10.0.0.0/8")
    Monitors failed logins over 3 hours, blocks IPs with 15+ attempts, and excludes specified trusted IPs.
.OUTPUTS
    Detailed report of IPs, targeted usernames, attempt counts, inferred intent, and blocking status.
.NOTES
    Run with administrative privileges to access the Security event log and modify firewall rules.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [int]$Hours = 1,
    [Parameter(Mandatory=$false)]
    [int]$Attempts = 10,
    [Parameter(Mandatory=$false)]
    [string[]]$Whitelist = @("127.0.0.1", "192.168.0.0/16", "10.0.0.0/8")
)

# API endpoint and key
# Define the URL of your blacklist API
$apiUrl = "http://domain.com/blacklist" 
$apiKey = "client-name:client-key"
$headers = @{ "X-Api-Key" = $apiKey }

Write-Host "Parameters:"
Write-Host " - Hours: $Hours"
Write-Host " - Attempts: $Attempts"
Write-Host " - Whitelist: $($Whitelist -join ', ')"
Write-Host ""

# Ensure the script runs as Administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "This script must be run as Administrator!"
    exit 1
}

# Function to check if an IP is in a CIDR range
function Test-IPInRange {
    param (
        [string]$IP,
        [string]$CIDR
    )
    try {
        $ipAddr = [System.Net.IPAddress]::Parse($IP)
        $ipInt = [BitConverter]::ToUInt32($ipAddr.GetAddressBytes(), 0)

        $cidrParts = $CIDR -split '/'
        $networkAddr = [System.Net.IPAddress]::Parse($cidrParts[0])
        $maskBits = [int]$cidrParts[1]
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $maskBits))
        $networkInt = [BitConverter]::ToUInt32($networkAddr.GetAddressBytes(), 0)
        $networkRange = $networkInt -band $mask

        return ($ipInt -band $mask) -eq $networkRange
    } catch {
        return $false
    }
}

# Define time range for log analysis
$startTime = [DateTime]::Now.AddHours(-$Hours)

# Retrieve failed login events (Event ID 4625) from Security log
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'logon type:\s+(3|10)' } | 
Select-Object @{n='IpAddress';e={$_.Properties[19].Value}}, 
              @{n='UserName';e={$_.Properties[5].Value}}, 
              TimeCreated, 
              @{n='LogonType';e={$_.Properties[10].Value}}, 
              @{n='FailureReason';e={$_.Properties[8].Value}}

# Group by IP and Username, and collect details
$ipUserGroups = $failedLogins | Group-Object -Property IpAddress, UserName | 
Select-Object @{n='IpAddress';e={$_.Name.Split(',')[0].Trim()}}, 
              @{n='UserName';e={$_.Name.Split(',')[1].Trim()}}, 
              @{n='AttemptCount';e={$_.Count}}, 
              @{n='LastAttempt';e={$_.Group | Sort-Object TimeCreated | Select-Object -Last 1 -ExpandProperty TimeCreated}}, 
              @{n='LogonTypes';e={$_.Group.LogonType | Select-Object -Unique}}, 
              @{n='FailureReasons';e={$_.Group.FailureReason | Select-Object -Unique}}

# Filter for potential brute-force attacks
$potentialAttacks = $ipUserGroups | Where-Object { $_.AttemptCount -ge $Attempts }

# Initialize log file
# $logFile = "C:\Logs\BruteForceDetection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
# if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

# Process and block suspicious IPs
if ($potentialAttacks) {
    Write-Host "Potential brute-force attacks detected:" -ForegroundColor Red
    $blockedIPs = @()
    
    $potentialAttacks | ForEach-Object {
        $ip = $_.IpAddress
        $user = $_.UserName
        $count = $_.AttemptCount
        $lastAttempt = $_.LastAttempt
        $logonTypes = $_.LogonTypes -join ", "
        $failureReasons = $_.FailureReasons -join ", "

        # Infer attacker intent
        $intent = switch -Regex ($user) {
            '^(Administrator|admin|root)$' { "Targeting privileged accounts (high-risk)." }
            default { "Attempting to guess credentials for user: $user." }
        }
        if ($count -ge 50) { $intent += " High volume suggests automated brute-force attack." }
        if ($logonTypes -match '10') { $intent += " Targeting RDP (Remote Desktop)." }
        if ($logonTypes -match '3') { $intent += " Targeting network logon (e.g., SMB, RPC)." }

        # Display details
        Write-Host "IP: $ip" -ForegroundColor Yellow
        Write-Host "  Targeted User: $user" -ForegroundColor Cyan
        Write-Host "  Failed Attempts: $count" -ForegroundColor Cyan
        Write-Host "  Last Attempt: $lastAttempt" -ForegroundColor Cyan
        Write-Host "  Logon Types: $logonTypes" -ForegroundColor Cyan
        Write-Host "  Failure Reasons: $failureReasons" -ForegroundColor Cyan
        Write-Host "  Suspected Intent: $intent" -ForegroundColor Magenta

        # Check if IP is in whitelist
        $isWhitelisted = $false
        foreach ($whitelistedIP in $Whitelist) {
            if ($ip -eq $whitelistedIP) {
                $isWhitelisted = $true
                break
            } elseif ($whitelistedIP -match '/') {
                if (Test-IPInRange -IP $ip -CIDR $whitelistedIP) {
                    $isWhitelisted = $true
                    break
                }
            }
        }

        # Block IP if not whitelisted
        if (-not $isWhitelisted -and $ip -ne '' -and $ip -ne '::1') {
            try {
                $ruleName = "BlockBruteForce_$ip"

                # Check if firewall rule already exists
                if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $ip -Action Block -Protocol Any -ErrorAction Stop
                    Write-Host "  Action: Blocked IP $ip via Windows Firewall." -ForegroundColor Green
                    $blockedIPs += $ip

                    # Send POST request to central blacklist API
                    $body = @{ BlackIp = $ip } | ConvertTo-Json -Depth 2
                    try {
                        Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body -ContentType "application/json"
                        Write-Host "  Action: Reported IP $ip to central blacklist." -ForegroundColor Cyan
                    } catch {
                        Write-Warning "  Warning: Failed to report IP $ip to API. Error: $_"
                    }
                } else {
                    Write-Host "  Action: IP $ip already blocked." -ForegroundColor Green
                }
            } catch {
                Write-Host "  Action: Failed to block IP $ip. Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "  Action: IP $ip is whitelisted or invalid; not blocked." -ForegroundColor Green
        }
        Write-Host ""
    }
    Write-Host "Blocked IPs: $blockedIPs"
} else {
    Write-Host "No brute-force attempts detected in the last $Hours hours." -ForegroundColor Green
    "No brute-force attempts detected at $(Get-Date)"
}

# Display recommended actions
# if ($potentialAttacks) {
#     Write-Host "Recommended Actions:" -ForegroundColor Green
#     Write-Host "- Review blocked IPs in Windows Firewall and ensure legitimate users are not affected."
#     Write-Host "- Enable MFA for targeted users, especially privileged accounts."
#     Write-Host "- Investigate blocked IPs using WHOIS or threat intelligence tools."
#     Write-Host "- Check if targeted usernames are valid; disable unused accounts."
#     Write-Host "- Monitor logs at $logFile for ongoing analysis."
# }