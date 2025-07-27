param (
    [string]$ipAddress
)

# Define the XML filter to query Security log for events matching the IP address
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625)]]
      and
      *[EventData[Data[@Name='IpAddress'] and (Data='$ipAddress')]]
    </Select>
  </Query>
</QueryList>
"@

# Retrieve events from the Security log
$events = Get-WinEvent -FilterXml $filter -ErrorAction SilentlyContinue

# Check if any events were found
if ($events.Count -eq 0) {
    Write-Host "No login attempts found for IP: $ipAddress"
} else {
    # Separate events into failed and successful logins
    $failedEvents = $events | Where-Object { $_.Id -eq 4625 }
    $successEvents = $events | Where-Object { $_.Id -eq 4624 }

    # Determine the first login attempt (successful or failed)
    $firstEvent = $events | Sort-Object TimeCreated | Select-Object -First 1
    $firstAttemptTime = $firstEvent.TimeCreated
    $firstAttemptType = if ($firstEvent.Id -eq 4624) { "successful" } else { "failed" }

    # Process failed login attempts
    $failedByUser = $failedEvents | Group-Object -Property { $_.Properties[5].Value } | 
                    Select-Object Name, Count | Sort-Object Count -Descending

    # Process successful logins
    if ($successEvents.Count -gt 0) {
        $sortedSuccess = $successEvents | Sort-Object TimeCreated
        $firstSuccessEvent = $sortedSuccess[0]
        $lastSuccessEvent = $sortedSuccess[-1]
        $firstSuccessTime = $firstSuccessEvent.TimeCreated
        $firstSuccessUser = $firstSuccessEvent.Properties[5].Value
        $lastSuccessTime = $lastSuccessEvent.TimeCreated
        $lastSuccessUser = $lastSuccessEvent.Properties[5].Value
    }

    # Generate the summary report
    Write-Host "Summary for IP: $ipAddress"
    Write-Host "First attempt: $($firstAttemptTime.ToString('yyyy-MM-dd HH:mm:ss')) ($firstAttemptType)"
    Write-Host "Failed login attempts: $($failedEvents.Count)"
    if ($failedEvents.Count -gt 0) {
        Write-Host "Usernames attempted:"
        foreach ($user in $failedByUser) {
            Write-Host "- $($user.Name): $($user.Count) attempts"
        }
    }
    Write-Host "Successful logins: $($successEvents.Count)"
    if ($successEvents.Count -gt 0) {
        Write-Host "First successful login: $($firstSuccessTime.ToString('yyyy-MM-dd HH:mm:ss')) by $firstSuccessUser"
        Write-Host "Last successful login: $($lastSuccessTime.ToString('yyyy-MM-dd HH:mm:ss')) by $lastSuccessUser"
    }
}