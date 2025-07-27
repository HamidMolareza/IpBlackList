# Script to create a Scheduled Task for running Detect-BruteForceDetailed.ps1
$taskName = "BruteForceDetectionDetailed"
$scriptPath = "C:\scripts\security\detect-brute-force\Detect-BruteForce-Log.ps1"
$taskDescription = "Runs brute-force detection script every 5 minutes to monitor and block suspicious IPs."

# Define the trigger (run every 5 minutes, starting now)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 999)

# Define the action (run the PowerShell script with parameters)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Hours 3 -Attempts 5"

# Define task settings (run with highest privileges, allow start if on battery)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

# Register the task
try {
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Description $taskDescription -Settings $settings -Force -ErrorAction Stop
    Write-Host "Scheduled Task '$taskName' created successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to create Scheduled Task. Error: $_" -ForegroundColor Red
}

# Verify the task was created
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "Task Details:" -ForegroundColor Green
    $task | Select-Object TaskName, State, Actions, Triggers | Format-List
} else {
    Write-Host "Task '$taskName' not found. Creation may have failed." -ForegroundColor Red
}