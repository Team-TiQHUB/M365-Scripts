# Admin Login Monitor using Webhook Notification
# Author: Nithin Kumar
# Organization: TiQHUB

$ScriptName = "AdminLoginMonitor"
$ScriptPath = "C:\Scripts\AdminLoginMonitor.ps1"
$TaskName = "Admin Login Monitor"
# Replace with your actual webhook URL
$TeamsWebhookUrl = ""

try {
    Write-Output "Installing Admin Login Monitor..."

    if (!(Test-Path "C:\Scripts")) {
        New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null
        Write-Output "Created directory: C:\Scripts"
    }

    # Create the main monitoring script
    $MonitoringScript = @'
# Admin Login Monitor Script
$TeamsWebhookUrl = ""
$ComputerName = $env:COMPUTERNAME

function Get-PublicIPAddress {
    try {
        $publicIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        return $publicIP
    } catch {
        try {
            $publicIP = (Invoke-RestMethod -Uri "https://ipinfo.io/ip" -TimeoutSec 10).Trim()
            return $publicIP
        } catch {
            return "Unable to determine"
        }
    }
}

function Send-TeamsNotification {
    param(
        [string]$Username,
        [string]$Domain,
        [string]$LogonType,
        [string]$SourceIP,
        [string]$TimeCreated,
        [string]$ComputerName
    )
    
    try {
        # Get MAC address of the Wi-Fi adapter
        $macAddress = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.Name -like '*Wi-Fi*' -or $_.InterfaceDescription -like '*Wireless*') } | Select-Object -First 1).MacAddress
        if (-not $macAddress) {
            $macAddress = "Wi-Fi adapter not found or inactive"
        }

        $message = @{
            text = "ADMIN LOGIN ALERT`n`n" +
                   "Administrator login detected`n`n" +
                   "User: $Username`n" +
                   "Domain: $Domain`n" +
                   "Logon Type: $LogonType`n" +
                   "Source IP: $SourceIP`n" +
                   "Time: $TimeCreated`n" +
                   "Device: $ComputerName`n" +
                   "Wi-Fi MAC Address: $macAddress"
        }

        $jsonPayload = $message | ConvertTo-Json -Depth 2
        Invoke-RestMethod -Method Post -Uri $TeamsWebhookUrl -Body $jsonPayload -ContentType 'application/json' -TimeoutSec 30
        return $true
        
    } catch {
        Write-Host "Teams notification failed: $($_.Exception.Message)"
        return $false
    }
}


try {
    # System accounts to ignore
    $SystemAccounts = @("DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3", 
                        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DefaultAccount")

    # Get login events from the last hour
    $LoginEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; ID = 4624; StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction Stop

    # Get public IP address once
    $PublicIP = Get-PublicIPAddress

    # Filter for interactive, network, and remote desktop logins
    $RecentLogins = $LoginEvents | Where-Object {
        $LogonType = $_.Properties[8].Value
        $LogonType -eq 2 -or $LogonType -eq 10 -or $LogonType -eq 3
    } | ForEach-Object {
        [PSCustomObject]@{
            Username = $_.Properties[5].Value
            Domain = $_.Properties[6].Value
            LogonType = switch ($_.Properties[8].Value) {
                2 { "Interactive" }
                3 { "Network" }
                10 { "Remote Desktop" }
                default { $_.Properties[8].Value }
            }
            SourceIP = $PublicIP
            TimeCreated = $_.TimeCreated
        }
    } | Where-Object { 
        $_.Username -notin $SystemAccounts -and 
        -not $_.Username.EndsWith('$') -and 
        $_.Username -ne '-' -and 
        $_.Username -ne ''
    }

    if ($RecentLogins.Count -eq 0) {
        Write-Host "No user logins detected in the past hour"
        return
    }

    Write-Host "Found $($RecentLogins.Count) user login(s), checking for admin privileges..."

    # Track admin users already notified
    $NotifiedAdmins = @()

    # Check each login for admin privileges
    foreach ($login in $RecentLogins) {
        try {
            # Build full username for domain accounts
            $fullUsername = if ($login.Domain -and $login.Domain -ne '-' -and $login.Domain -ne $env:COMPUTERNAME) {
                "$($login.Domain)\$($login.Username)"
            } else { 
                $login.Username 
            }

            # Skip if we already notified for this user
            if ($NotifiedAdmins -contains $login.Username) {
                Write-Host "Already notified for admin user: $($login.Username) - Skipping"
                continue
            }

            # Check if user is in Administrators group
            $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            $isAdmin = $adminMembers | Where-Object { 
                $_.Name -eq $fullUsername -or 
                $_.Name -eq $login.Username -or 
                $_.Name.EndsWith("\$($login.Username)")
            }

            if ($isAdmin) {
                Write-Host "ADMIN LOGIN DETECTED: $($login.Username) - Sending Teams notification"
                
                # Send Teams notification
                $notificationSent = Send-TeamsNotification -Username $login.Username -Domain $login.Domain -LogonType $login.LogonType -SourceIP $login.SourceIP -TimeCreated $login.TimeCreated -ComputerName $ComputerName
                
                if ($notificationSent) {
                    Write-Host "Teams notification sent successfully for: $($login.Username)"
                    # Add to notified list to prevent duplicates
                    $NotifiedAdmins += $login.Username
                } else {
                    Write-Host "Failed to send Teams notification for: $($login.Username)"
                }
            } else {
                Write-Host "Standard user login: $($login.Username)"
            }
        } catch {
            Write-Host "Error checking user $($login.Username): $($_.Exception.Message)"
        }
    }

} catch {
    if ($_.Exception.Message -notmatch "No events were found") {
        Write-Host "Error: $($_.Exception.Message)"
    } else {
        Write-Host "No security events found in the specified time range"
    }
}
'@

    Set-Content -Path $ScriptPath -Value $MonitoringScript -Encoding UTF8
    Write-Output "Created monitoring script: $ScriptPath"

    # Create simple webhook test script
    $WebhookTestScript = @'
# Simple Webhook Test
$TeamsWebhookUrl = ""

try {
    $testMessage = @{
        text = "Test Message`n`nWebhook test from $env:COMPUTERNAME at $(Get-Date)"
    }
    $payload = $testMessage | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri $TeamsWebhookUrl -Body $payload -ContentType 'application/json' -TimeoutSec 30
    Write-Host "Test message sent successfully" -ForegroundColor Green
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}
'@

    $WebhookTestPath = "C:\Scripts\TestWebhook.ps1"
    Set-Content -Path $WebhookTestPath -Value $WebhookTestScript -Encoding UTF8
    Write-Output "Created test script: $WebhookTestPath"

    # Set up scheduled task
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($ExistingTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "Removed existing scheduled task"
    }

    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File `"$ScriptPath`""
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 365)
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Simple admin login monitor with Teams webhook notification" | Out-Null

    Write-Output "Created scheduled task: $TaskName"

    # Test webhook
    Write-Output "Testing webhook..."
    & $WebhookTestPath

    # Run initial check
    Write-Output "Running initial admin login check..."
    & $ScriptPath

    Write-Output ""
    Write-Output "Installation completed successfully!"
    Write-Output "Files created:"
    Write-Output "  • Main script: $ScriptPath"
    Write-Output "  • Test script: $WebhookTestPath"
    Write-Output ""
    Write-Output "The script will run every hour and send Teams notifications for admin logins only."
    Write-Output "No log files will be created - notifications only."

} catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
}