$startTime = (Get-Date).AddDays(-7)

$uniqueIPs = Get-WinEvent -FilterHashtable @{
    LogName = 'Security';
    Id = 4624;
    StartTime = $startTime
} | ForEach-Object {
    $message = $_.Message
    if ($message -match 'Source Network Address:\s+([\d\.]+)') {
        $ip = $matches[1]
        if ($ip -and $ip -ne '::1' -and $ip -ne '127.0.0.1' -and $ip -ne '-') {
            $ip
        }
    }
} | Sort-Object | Get-Unique

# Format like: ('ip1', 'ip2', ...)
$formatted = "('" + ($uniqueIPs -join "', '") + "')"
Write-Output $formatted
