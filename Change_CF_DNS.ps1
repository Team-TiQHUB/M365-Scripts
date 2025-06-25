# Author: Nithin (Optimized for Intune by ChatGPT)
# Purpose: Set Cloudflare Family DNS on all active network adapters (Wi-Fi and Ethernet)

try {
    # Get all active network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    foreach ($adapter in $adapters) {
        try {
            # Set Cloudflare Family DNS
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @(
                "1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"
            )
            Write-Output "DNS successfully set on adapter $($adapter.Name)"
        } catch {
            Write-Output "Failed to set DNS on adapter $($adapter.Name): $_"
        }
    }
} catch {
    Write-Output "Script failed to run: $_"
}
