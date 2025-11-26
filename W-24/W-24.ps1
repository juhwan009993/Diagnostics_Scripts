$dir = $PSScriptRoot
$log_dir = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $log_dir, $result_dir | Out-Null

$log_file = Join-Path $log_dir "W-24.log"
$json_file = Join-Path $result_dir "W-24.json"

$detect_status = "PASS"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

try {
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-24] Windows Server Security Assessment ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    $isLegacyPS = $PSVersionTable.PSVersion.Major -lt 3
    if ($isLegacyPS) {
        Write-Host "[INFO] Legacy PowerShell (version < 3.0) detected. Using WMI cmdlets." -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] Modern PowerShell (version >= 3.0) detected. Using CIM cmdlets."
    }

    # Administrator privilege check
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        $discussion = "This script must be run with Administrator privileges."
        throw $discussion
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green


    function Get-NetbiosStatus {
        Write-Host "[INFO] Querying for network adapter configurations..."
        if ($isLegacyPS) {
            $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'"
        } else {
            $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'"
        }
        
        $status = @()
        foreach ($adapter in $adapters) {
            $status += [PSCustomObject]@{
                Adapter        = $adapter.Description
                InterfaceIndex = $adapter.InterfaceIndex
                NetbiosSetting = $adapter.TcpipNetbiosOptions # 0: DHCP, 1: Enabled, 2: Disabled
                IsVulnerable   = $adapter.TcpipNetbiosOptions -ne 2
            }
        }
        Write-Host "[INFO] Found $($status.Count) IP-enabled network adapters."
        return $status
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"
    $initial_status = Get-NetbiosStatus
    $vulnerable_adapters = $initial_status | Where-Object { $_.IsVulnerable }
    if ($vulnerable_adapters) {
        $detect_status = "FAIL"
        Write-Host "[FAIL] Vulnerable adapters found:" -ForegroundColor Yellow
        $vulnerable_adapters | ForEach-Object { Write-Host " - $($_.Adapter) (NetBIOS over TCP/IP is not disabled)" -ForegroundColor Yellow }
    } else {
        $detect_status = "PASS"
        Write-Host "[PASS] All network adapters have NetBIOS over TCP/IP disabled." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
    Write-Host "--------------------"
    $final_status = $null
    if ($detect_status -eq "FAIL") {
        $choice = Read-Host "취약점이 발견되었습니다. 자동으로 조치하시겠습니까? (y/n)"
        if ($choice -match '^[Yy]$') {
            Write-Host "[INFO] User approved automatic remediation."
            foreach ($adapter_info in $vulnerable_adapters) {
                Write-Host "[ACTION] Disabling NetBIOS over TCP/IP for: $($adapter_info.Adapter)"
                
                if ($isLegacyPS) {
                    $adapter_instance = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_info.InterfaceIndex)"
                    $result = $adapter_instance.SetTcpipNetbios(2)
                } else {
                    $adapter_instance = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_info.InterfaceIndex)"
                    $result = $adapter_instance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2}
                }

                if ($result.ReturnValue -eq 0) {
                    Write-Host "[SUCCESS] Successfully sent command to disable NetBIOS for: $($adapter_info.Adapter)" -ForegroundColor Green
                } else {
                    Write-Host "[ERROR] Failed to disable NetBIOS for: $($adapter_info.Adapter). Return code: $($result.ReturnValue)" -ForegroundColor Red
                }
            }

            # Verification
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-NetbiosStatus
            $remaining_vulnerable = $final_status | Where-Object { $_.IsVulnerable }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL"
                Write-Host "[FAIL] Remediation failed for one or more adapters." -ForegroundColor Red
            } else {
                $remediate_status = "PASS"
                Write-Host "[PASS] Remediation successful for all vulnerable adapters." -ForegroundColor Green
            }
        } else {
            $remediate_status = "MANUAL"
            Write-Host "[INFO] User declined automatic remediation. Providing manual instructions." -ForegroundColor Yellow
            Write-Host "--------- 수동 조치 가이드 ---------" -ForegroundColor Cyan
            Write-Host "$($check_content)"
            Write-Host "---------------------------------"
        }
    } else {
        $remediate_status = "PASS"
        Write-Host "[INFO] No remediation required."
    }

    $discussion = @"
Good: The binding between TCP/IP and NetBIOS is removed (NetbiosOptions set to 2).
Vulnerable: The binding between TCP/IP and NetBIOS is not removed.
"@

    $check_content = @"
Step 1) Start > Run > ncpa.cpl > Local Area Connection > Properties > TCP/IP > Click [Advanced] on the [General] tab > On the [WINS] tab, select “Disable NetBIOS over TCP/IP”.
"@
    
    Write-Host ""
    Write-Host "PHASE 3: GENERATING REPORT" -ForegroundColor Magenta
    Write-Host "--------------------------"
    Write-Host "[INFO] Generating final report object..."
    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "AC-2-7"
        check_target   = "W-24: NetBIOS binding service running check"
        discussion     = $discussion
        check_content  = $check_content
        fix_text       = "Remove the binding between TCP/IP and NetBIOS."
        payload        = [PSCustomObject]@{
            severity     = "high"
            service      = "NetBIOS"
            protocol     = "TCP/IP"
            threat       = @("Information Disclosure", "Unauthorized Access")
            TTP          = @("T1046", "T1021")
            file_checked = "Registry: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
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
        check_target = "W-24: NetBIOS binding service running check"
        status       = "ERROR"
        discussion   = $_.ToString()
    }
}
finally {
    # Restore original settings if they were changed
    if ($choice -match '^[Yy]' -and $detect_status -eq 'FAIL') {
        Write-Host ""
        Write-Host "PHASE 4: RESTORING ORIGINAL SETTINGS" -ForegroundColor Magenta
        Write-Host "------------------------------------"
        
        foreach ($adapter_to_restore in $vulnerable_adapters) {
            $original_setting = $adapter_to_restore.NetbiosSetting
            Write-Host "[ACTION] Restoring NetBIOS setting for '$($adapter_to_restore.Adapter)' to original value: $original_setting"
            
            if ($isLegacyPS) {
                $adapter_instance = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_to_restore.InterfaceIndex)"
                $restore_result = $adapter_instance.SetTcpipNetbios($original_setting)
            } else {
                $adapter_instance = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_to_restore.InterfaceIndex)"
                $restore_result = $adapter_instance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = $original_setting}
            }

            if ($restore_result.ReturnValue -eq 0) {
                Write-Host "[SUCCESS] Successfully restored setting for '$($adapter_to_restore.Adapter)'." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] Failed to restore setting for '$($adapter_to_restore.Adapter)'." -ForegroundColor Red
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
