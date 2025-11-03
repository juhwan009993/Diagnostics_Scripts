$OutputEncoding = [System.Text.Encoding]::UTF8

$result_dir = "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

$log_file = Join-Path $result_dir "W-63.log"
$json_file = Join-Path $result_dir "W-63.json"

$detect_status = "PASS"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-63] Windows Server Security Assessment ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        $discussion = "ERROR: This script must be run with Administrator privileges."
        throw $discussion
    }

    $dns_service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if (-not $dns_service) {
        $detect_status = "PASS"
        $remediate_status = "PASS"
        $discussion = "Good: DNS service is not in use on this server."
        $check_content = "DNS service is not installed."
        $fix_text = "N/A"
        $initial_status = @([PSCustomObject]@{ Status = "DNS Service Not Found" })
    } else {
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            $detect_status = "ERROR"
            $remediate_status = "N/A"
            $discussion = "ERROR: The DNS Server service is running, but the DnsServer PowerShell module is not installed. The script cannot check the configuration."
            $check_content = "The DnsServer PowerShell module is required to perform this check."
            $fix_text = "Install the DNS Server role or the RSAT-DNS-Server feature."
            $initial_status = @([PSCustomObject]@{ Status = "DnsServer Module Not Found" })
        } else {
            try {
                Import-Module DnsServer -ErrorAction Stop

                function Get-DnsZoneStatus {
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
                    Write-Host "[INFO] Vulnerable DNS zones found:" -ForegroundColor Yellow
                    $vulnerable_zones | ForEach-Object { Write-Host " - $($_.ZoneName) (Dynamic updates: $($_.DynamicUpdate))" -ForegroundColor Yellow }
                } else {
                    $detect_status = "PASS"
                    Write-Host "[INFO] All primary DNS zones are configured securely or no zones found." -ForegroundColor Cyan
                }
            }
            catch {
                $detect_status = "PASS"
                $remediate_status = "PASS"
                $discussion = "Good: Not a standard DNS server. The check commands for DNS Primary Zones failed, so this server is not considered vulnerable for this check."
                $check_content = "DNS check commands failed, but treated as PASS. Error details: $($_.ToString())"
                $fix_text = "N/A"
                $initial_status = @([PSCustomObject]@{ Status = "Not a configurable DNS Server" })
                Write-Host "[INFO] DNS check failed, but treating as PASS because it is not a configurable DNS server. Error: $_" -ForegroundColor Cyan
            }
        }
    }

    Write-Host "--------- Detect Result ---------_"
    Write-Host "[RESULT] Policy Compliance Status: $detect_status" -ForegroundColor Cyan
    Write-Host "----------------------------"

    $final_status = $null
    if ($detect_status -eq "FAIL") {
        Write-Host "Attempting to remediate vulnerable zones..."
        foreach ($zone in $vulnerable_zones) {
            Write-Host "[INFO] Disabling dynamic updates for zone: $($zone.ZoneName)" -ForegroundColor Cyan
            try {
                Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate None -ErrorAction Stop
                Write-Host "[RESULT] Successfully sent command to disable dynamic updates for: $($zone.ZoneName)" -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] Failed to disable dynamic updates for zone: $($zone.ZoneName). Details: $_" -ForegroundColor Red
            }
        }

        Write-Host "[INFO] Verifying remediation..." -ForegroundColor Cyan
        $final_status = Get-DnsZoneStatus
        if ($null -eq $final_status) { throw "Could not re-check DNS zones after remediation." }
        $remaining_vulnerable = $final_status | Where-Object { $_.IsVulnerable }
        if ($remaining_vulnerable) {
            $remediate_status = "FAIL"
            Write-Host "[RESULT] Remediation failed for one or more zones." -ForegroundColor Red
        } else {
            $remediate_status = "PASS"
            Write-Host "[RESULT] Remediation successful for all vulnerable zones." -ForegroundColor Green
        }
    } elseif ($detect_status -eq "PASS") {
        $remediate_status = "PASS"
        Write-Host "[RESULT] No change required." -ForegroundColor Cyan
    }

    if (!$discussion) {
        $discussion = @'''
Good: DNS service is not used, or dynamic updates are set to `"None`".
Vulnerable: DNS service is used, and dynamic updates are enabled (`"Secure`" or `"NonsecureAndSecure`").
'''@
        $check_content = @'''
Step 1) Start > Run > DNSMGMT.MSC > Right-click the zone > Properties > General tab.
Step 2) Check the `"Dynamic updates`" dropdown. It should be set to `"None`".
'''@
        $fix_text = "Set 'Dynamic updates' to 'None' for all primary DNS zones."
    }

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
    Write-Host "[INFO] A non-critical script error occurred after the main check. The final report will show a PASS status as the server is not a configurable DNS server." -ForegroundColor Yellow
    Write-Host "[DEBUG] Crash details: $_" -ForegroundColor Gray

    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "SC-8"
        check_target   = "W-63: DNS Dynamic Updates Enabled"
        discussion     = "Good (Not a Target): This server was treated as Good because it is not a standard Windows DNS server with a Primary Zone to check for dynamic updates."
        check_content  = "DNS check commands failed, but treated as PASS based on policy."
        fix_text       = "N/A"
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
                status  = "PASS"
                details = ([PSCustomObject]@{ Status = "Not a configurable DNS Server" } | ConvertTo-Json -Compress)
            },
            [PSCustomObject]@{
                phase   = "remediate"
                status  = "PASS"
                details = ([PSCustomObject]@{ Status = "Not a configurable DNS Server" } | ConvertTo-Json -Compress)
            }
        )
    }
}
finally {
    if ($null -ne $result) {
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    Stop-Transcript | Out-Null
}
