[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [int]$Hours = 1,

    [Parameter(Mandatory=$false)]
    [int]$Attempts = 10,

    [Parameter(Mandatory=$false)]
    [string[]]$Whitelist = @("127.0.0.1", "192.168.0.0/16", "10.0.0.0/8")
)

# Ensure the script runs as Administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "This script must be run as Administrator!"
    exit 1
}

$ScriptToRun = "C:\scripts\security\detect-brute-force\Detect-BruteForce.ps1"
$ScriptName = "BruteForceDetection"
$OutputFolder = "C:\Logs\Detect-BruteForce"

# Ensure the output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

# Generate timestamped log file name
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName = "$ScriptName" + "_$timestamp.txt"
$logFile = Join-Path -Path $OutputFolder -ChildPath $logFileName

# Build the script invocation command
& $ScriptToRun -Hours $Hours -Attempts $Attempts -Whitelist $Whitelist *> $logFile
