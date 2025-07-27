[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$ScriptToRun,

    [Parameter(Mandatory=$false)]
    [string]$ScriptName,

    [Parameter(Mandatory=$false)]
    [string]$OutputFolder
)

# Ensure the script runs as Administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "This script must be run as Administrator!"
    exit 1
}

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
