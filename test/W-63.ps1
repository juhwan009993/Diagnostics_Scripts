# Script Parameter Definition
# -a: Specifies the execution mode of the script (Detect, Remediate, Restore). Default is Detect.
param(
    [ValidateSet("Detect", "Remediate", "Restore")]
    [string]$a = "Detect"
)

# Set output encoding to UTF-8 to prevent character corruption.
$OutputEncoding = [System.Text.Encoding]::UTF8

# --- Path and File Setup ---
$dir = $PSScriptRoot
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_file = Join-Path $dir "W-63.backup.json"
# Create the result directory if it doesn't exist.
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

# Set log and JSON result file paths.
$log_file = Join-Path $result_dir "W-63.log"
$json_file = Join-Path $result_dir "W-63.json"

# --- Status Variable Initialization ---
$detect_status = "PASS" # Detection status (PASS, FAIL, MANUAL_CHECK_NEEDED, ERROR)
$remediate_status = "FAIL" # Remediation status (PASS, FAIL, N/A)
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK" # Current timestamp

# --- Function Definitions ---

# [Internal Function] Gets DNS Zone status using dnscmd.exe (Fallback method).
function Get-DnsZoneStatusFromDnscmd {
    Write-Host "[INFO] Fallback: Attempting to get DNS zones using dnscmd.exe..."
    $zones = @()
    try {
        $zone_list_output = dnscmd.exe /EnumZones

        # Skip header lines and process each zone line
        $zone_lines = $zone_list_output | Select-Object -Skip 4
        
        foreach ($line in $zone_lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match "Command completed successfully") { continue }

            # Split the line into columns based on multiple spaces
            $columns = $line.Trim() -split '\s+' | Where-Object { $_ }
            
            if ($columns.Count -ge 2) {
                $zone_name = $columns[0]
                $zone_type = $columns[1]

                # Process only Primary zones
                if ($zone_type -eq 'Primary') {
                    $zone_info = dnscmd.exe /ZoneInfo $zone_name
                    
                    # Safely extract 'update' value.
                    # The key is simply 'update', not 'dynamic update'.
                    $update_line = $zone_info | Where-Object { $_ -match '^\s*update\s*=' } | Select-Object -First 1
                    $update_value = "0" # Default to 'None'
                    if ($update_line) {
                        $parts = $update_line -split '=', 2
                        if ($parts.Count -ge 2) { $update_value = $parts[1].Trim() }
                    }
                    
                    $is_vulnerable = $update_value -ne "0"
                    $update_string = switch ($update_value) {
                        "0" { "None" }
                        "1" { "NonsecureAndSecure" }
                        "2" { "Secure" }
                        default { "Unknown" }
                    }
                    $zones += [PSCustomObject]@{
                        ZoneName      = $zone_name
                        DynamicUpdate = $update_string
                        IsVulnerable  = $is_vulnerable
                    }
                }
            }
        }
        
        if (-not $zones) {
            Write-Host "[INFO] Fallback: dnscmd.exe did not find any primary zones."
        }
        return $zones
    } catch {
        Write-Host "[ERROR] Fallback: Failed to get DNS status using dnscmd.exe. Error: $_" -ForegroundColor Red
        return $null
    }
}


# Main function to get DNS Zone status. Tries PowerShell Cmdlet first, falls back to dnscmd.exe on failure.
function Get-DnsZoneStatus {
    try {
        Write-Host "[INFO] Querying for all primary DNS zones using PowerShell Cmdlet..."
        Import-Module DnsServer -ErrorAction Stop -Force
        # Get status using Get-DnsServerPrimaryZone Cmdlet.
        return Get-DnsServerPrimaryZone -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                ZoneName      = $_.ZoneName
                DynamicUpdate = $_.DynamicUpdate.ToString()
                IsVulnerable  = $_.DynamicUpdate -ne "None"
            }
        }
    } catch {
        # If the cmdlet fails (e.g., 'not recognized'), call the dnscmd.exe fallback.
        Write-Host "[WARN] PowerShell Cmdlet failed. This can happen in some environments. Attempting fallback..." -ForegroundColor Yellow
        Write-Host "Error details: $($_.Exception.Message)"
        return Get-DnsZoneStatusFromDnscmd
    }
}

# Function to restore settings from a backup file.
function Restore-FromBackup {
    if (-not (Test-Path $backup_file)) {
        Write-Host "[INFO] Backup file not found: $backup_file. Nothing to restore." -ForegroundColor Cyan
        exit
    }
    Write-Host "[INFO] Restoring settings from backup file: $backup_file" -ForegroundColor Cyan
    $zones_to_restore = Get-Content -Path $backup_file | ConvertFrom-Json
    
    foreach ($zone_to_restore in $zones_to_restore) {
        $original_setting = $zone_to_restore.DynamicUpdate
        Write-Host "[ACTION] Restoring dynamic update setting for zone '$($zone_to_restore.ZoneName)' to original value: $original_setting"
        try {
            # Attempt to restore using PowerShell Cmdlet first.
            Set-DnsServerPrimaryZone -Name $zone_to_restore.ZoneName -DynamicUpdate $original_setting -ErrorAction Stop
            Write-Host "[SUCCESS] Successfully restored setting for zone '$($zone_to_restore.ZoneName)' via Cmdlet." -ForegroundColor Green
        } catch {
            # Fallback to dnscmd.exe if cmdlet fails.
            Write-Host "[WARN] Set-DnsServerPrimaryZone failed. Attempting fallback with dnscmd.exe..."
            $update_value = switch ($original_setting) {
                "None" { 0 }
                "NonsecureAndSecure" { 1 }
                "Secure" { 2 }
            }
            try {
                dnscmd.exe /ZoneResetProperty $zone_to_restore.ZoneName /DynamicUpdate $update_value
                Write-Host "[SUCCESS] Successfully restored setting for zone '$($zone_to_restore.ZoneName)' via dnscmd.exe." -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] Failed to restore setting for zone '$($zone_to_restore.ZoneName)' with both methods. Details: $_" -ForegroundColor Red
            }
        }
    }
    Remove-Item -Path $backup_file
    Write-Host "[SUCCESS] Restoration complete. Backup file deleted." -ForegroundColor Green
}


# --- Main Script Execution Block ---
try {
    # Start logging all script execution.
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-63] DNS Dynamic Update Security Assessment (Action: $a) ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # Administrator privilege check.
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        throw "This script must be run with Administrator privileges."
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    # Handle the Restore action.
    if ($a -eq 'Restore') {
        Restore-FromBackup
        exit
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"

    # Check if the DNS service exists.
    $dns_service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if (-not $dns_service) {
        # If DNS service is not present, it's not applicable.
        $detect_status = "PASS"
        $remediate_status = "PASS"
        $discussion = "Good: DNS service is not installed, so this check is not applicable."
        $initial_status = @([PSCustomObject]@{ Status = "DNS Service Not Found" })
        Write-Host "[PASS] DNS Service is not installed. This check is not applicable." -ForegroundColor Green
    } else {
        # Get DNS Zone status (with fallback logic).
        $initial_status = Get-DnsZoneStatus
        
        if ($null -eq $initial_status) {
            # If Get-DnsZoneStatus encountered a serious, unrecoverable error.
            throw "Could not retrieve DNS zone status from any available method."
        }

        $vulnerable_zones = $initial_status | Where-Object { $_.IsVulnerable }

        if ($vulnerable_zones) {
            $detect_status = "FAIL"
            Write-Host "[FAIL] Vulnerable DNS zones found:" -ForegroundColor Yellow
            $vulnerable_zones | ForEach-Object { Write-Host " - $($_.ZoneName) (Dynamic updates: $($_.DynamicUpdate))" -ForegroundColor Yellow }
        } else {
            $detect_status = "PASS"
            Write-Host "[PASS] All primary DNS zones are configured securely (Dynamic Updates are 'None') or no primary zones found." -ForegroundColor Green
        }
    }

    $final_status = $null
    # Handle the Remediate action.
    if ($a -eq 'Remediate') {
        Write-Host ""
        Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
        Write-Host "--------------------"
        if ($detect_status -eq "FAIL") {
            # Back up original settings.
            Write-Host "[INFO] Backing up original settings for vulnerable zones to $backup_file..."
            $vulnerable_zones | ConvertTo-Json | Set-Content -Path $backup_file -Encoding UTF8
            Write-Host "[SUCCESS] Backup complete." -ForegroundColor Green

            # Apply remediation.
            foreach ($zone in $vulnerable_zones) {
                Write-Host "[ACTION] Disabling dynamic updates for zone: $($zone.ZoneName)"
                try {
                    # Attempt 1: Use PowerShell Cmdlet.
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate None -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully disabled dynamic updates for: $($zone.ZoneName) via Cmdlet" -ForegroundColor Green
                } catch {
                    # Attempt 2: Fallback to dnscmd.exe.
                    Write-Host "[WARN] Set-DnsServerPrimaryZone failed. Attempting fallback with dnscmd.exe..." -ForegroundColor Yellow
                    try {
                        dnscmd.exe /ZoneResetProperty $zone.ZoneName /DynamicUpdate 0
                        Write-Host "[SUCCESS] Successfully disabled dynamic updates for: $($zone.ZoneName) via dnscmd.exe" -ForegroundColor Green
                    } catch {
                        Write-Host "[ERROR] Failed to disable dynamic updates for zone: $($zone.ZoneName) with both methods. Details: $_" -ForegroundColor Red
                    }
                }
            }

            # Verify remediation.
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-DnsZoneStatus
            if ($null -eq $final_status) { throw "Could not re-check DNS zones after remediation." }
            $remaining_vulnerable = $final_status | Where-Object { $_.IsVulnerable }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL"
                Write-Host "[FAIL] Remediation failed for one or more zones." -ForegroundColor Red
            } else {
                $remediate_status = "PASS"
                Write-Host "[PASS] Remediation successful for all vulnerable zones." -ForegroundColor Green
            }
        } else {
            $remediate_status = "PASS"
            Write-Host "[INFO] No remediation required."
        }
    }

    # Set default report content if not set by specific conditions.
    if (!$discussion) {
        $discussion = @'
- Good: Dynamic updates are disabled ('None').
- Vulnerable: Dynamic updates are enabled ('Secure' or 'NonsecureAndSecure').
'@
        $check_content = "In DNS Manager (dnsmgmt.msc), check the 'Dynamic updates' setting for each primary zone."
        $fix_text = "Set 'Dynamic updates' to 'None' for all primary zones."
    }

    Write-Host ""
    Write-Host "PHASE 3: GENERATING REPORT" -ForegroundColor Magenta
    Write-Host "--------------------------"
    Write-Host "[INFO] Generating final report object..."
    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "SC-8"
        check_target   = "W-63: DNS Dynamic Updates Enabled"
        discussion     = $discussion
        check_content  = $check_content
        fix_text       = "Set 'Dynamic updates' to 'None' for all primary zones."
        payload        = [PSCustomObject]@{
            severity     = "medium"
            port         = "53"
            service      = "DNS"
            protocol     = "UDP/TCP"
            threat       = @("DNS Zone Poisoning", "Unauthorized Record Modification")
            TTP          = @("T1565.002")
            file_checked = "DNS Zone Configuration"
        }
        results        = @(
            [PSCustomObject]@{
                phase   = "detect"
                status  = $detect_status
                details = ($initial_status | ConvertTo-Json -Compress)
            },
            [PSCustomObject]@{
                phase   = "remediate"
                status  = $remediate_status
                details = ($(if ($final_status) { $final_status } else { $initial_status }) | ConvertTo-Json -Compress)
            }
        )
    }
}
catch {
    Write-Host "[FATAL] A critical error occurred: $_" -ForegroundColor Red
    $result = [PSCustomObject]@{
        date         = $ts
        check_target = "W-63: DNS Dynamic Updates Enabled"
        status       = "ERROR"
        discussion   = $_.ToString()
    }
}
finally {
    # Save the result to a JSON file if it exists.
    if ($result) {
        Write-Host "[INFO] Saving report to: $json_file"
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    # Stop logging.
    Write-Host "[INFO] Stopping script execution log."
    Stop-Transcript | Out-Null
}