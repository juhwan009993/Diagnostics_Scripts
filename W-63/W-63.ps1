$OutputEncoding = [System.Text.Encoding]::UTF8

$result_dir = "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

$log_file = Join-Path $result_dir "W-63.log"
$json_file = Join-Path $result_dir "W-63.json"

$detect_status = "PASS"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

try {
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-63] DNS Dynamic Update Security Assessment ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # Administrator privilege check
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        throw "This script must be run with Administrator privileges."
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"

    Write-Host "[INFO] Checking for DNS Service (dns.exe)..."
    $dns_service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if (-not $dns_service) {
        $detect_status = "PASS"
        $remediate_status = "PASS"
        $discussion = "Good: DNS service is not installed, so this check is not applicable."
        $check_content = "DNS service is not installed on this server."
        $fix_text = "N/A"
        $initial_status = @([PSCustomObject]@{ Status = "DNS Service Not Found" })
        Write-Host "[PASS] DNS Service is not installed. This check is not applicable." -ForegroundColor Green
    } else {
        Write-Host "[INFO] DNS Service is running. Checking for DnsServer PowerShell module..."
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            $detect_status = "MANUAL_CHECK_NEEDED"
            $remediate_status = "N/A"
            $discussion = "MANUAL CHECK NEEDED: The 'DnsServer' PowerShell module is missing (common on Windows Server 2008 R2 and older). Please check manually using 'dnscmd.exe'."
            $check_content = "1. Check server info: dnscmd.exe /info`n2. Check each zone: dnscmd.exe /zoneinfo <ZoneName>"
            $fix_text = "To disable dynamic updates for a zone: dnscmd.exe /zoneresetproperty <ZoneName> /DynamicUpdate 0"
            $initial_status = @([PSCustomObject]@{ Status = "DnsServer Module Not Found" })
            Write-Host "[WARN] DnsServer module not found. Automatic check is not possible. Please check manually using 'dnscmd.exe'." -ForegroundColor Yellow
        } else {
            Write-Host "[INFO] DnsServer module found. Importing module..."
            try {
                Import-Module DnsServer -ErrorAction Stop

                function Get-DnsZoneStatus {
                    Write-Host "[INFO] Querying for all primary DNS zones..."
                    Get-DnsServerPrimaryZone -ErrorAction Stop | ForEach-Object {
                        [PSCustomObject]@{
                            ZoneName      = $_.ZoneName
                            DynamicUpdate = $_.DynamicUpdate.ToString()
                            IsVulnerable  = $_.DynamicUpdate -ne "None"
                        }
                    }
                }

                $initial_status = Get-DnsZoneStatus
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
            catch {
                $detect_status = "PASS"
                $remediate_status = "PASS"
                $discussion = "Good: No configurable primary DNS zones were found on this server."
                $check_content = "The script could not find any primary DNS zones to check. This is typical for a caching-only DNS server. Error details: $($_.ToString())"
                $fix_text = "N/A"
                $initial_status = @([PSCustomObject]@{ Status = "Not a configurable DNS Server" })
                Write-Host "[PASS] No primary DNS zones found to check. This is considered a PASS state." -ForegroundColor Green
            }
        }
    }

    Write-Host ""
    Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
    Write-Host "--------------------"
    $final_status = $null
    if ($detect_status -eq "FAIL") {
        $choice = Read-Host "취약점이 발견되었습니다. 자동으로 조치하시겠습니까? (y/n)"
        if ($choice -match '^[Yy]$') {
            Write-Host "[INFO] User approved automatic remediation."
            foreach ($zone in $vulnerable_zones) {
                Write-Host "[ACTION] Disabling dynamic updates for zone: $($zone.ZoneName)"
                try {
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate None -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully sent command to disable dynamic updates for: $($zone.ZoneName)" -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] Failed to disable dynamic updates for zone: $($zone.ZoneName). Details: $_" -ForegroundColor Red
                }
            }

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
            $remediate_status = "MANUAL"
            Write-Host "[INFO] User declined automatic remediation. Providing manual instructions." -ForegroundColor Yellow
            $manual_guide = "In DNS Manager (dnsmgmt.msc), right-click each vulnerable zone, go to Properties, and on the General tab, set 'Dynamic updates' to 'None'."
            Write-Host "--------- 수동 조치 가이드 ---------" -ForegroundColor Cyan
            Write-Host $manual_guide
            Write-Host "---------------------------------"
        }
    } elseif ($detect_status -match "PASS|MANUAL_CHECK_NEEDED") {
        $remediate_status = "PASS"
        Write-Host "[INFO] No remediation required."
    }

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
        fix_text       = $fix_text
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
                details = (if ($final_status) { $final_status } else { $initial_status } | ConvertTo-Json -Compress)
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
    if ($choice -match '^[Yy]' -and $detect_status -eq 'FAIL') {
        Write-Host ""
        Write-Host "PHASE 4: RESTORING ORIGINAL SETTINGS" -ForegroundColor Magenta
        Write-Host "------------------------------------"
        
        foreach ($zone_to_restore in $vulnerable_zones) {
            $original_setting = $zone_to_restore.DynamicUpdate
            Write-Host "[ACTION] Restoring dynamic update setting for zone '$($zone_to_restore.ZoneName)' to original value: $original_setting"
            try {
                Set-DnsServerPrimaryZone -Name $zone_to_restore.ZoneName -DynamicUpdate $original_setting -ErrorAction Stop
                Write-Host "[SUCCESS] Successfully restored setting for zone '$($zone_to_restore.ZoneName)'." -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] Failed to restore setting for zone '$($zone_to_restore.ZoneName)'. Details: $_" -ForegroundColor Red
            }
        }
    }

    if ($result) {
        Write-Host "[INFO] Saving report to: $json_file"
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    Write-Host "[INFO] Stopping script execution log."
    Stop-Transcript | Out-Null
}
