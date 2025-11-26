$dir = $PSScriptRoot
$log_dir = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $log_dir, $result_dir | Out-Null

$log_file = Join-Path $log_dir "W-78.log"
$json_file = Join-Path $result_dir "W-78.json"

$detect_status = "PASS"
$remediate_status = "FAIL"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

try {
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-78] Secure Channel Policy Security Assessment ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # Administrator privilege check
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        throw "This script must be run with Administrator privileges."
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    $reg_path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $policy_names = @("RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel")

    function Get-SecureChannelPolicyStatus {
        param($path, $policies)
        Write-Host "[INFO] Querying registry for secure channel policies at: $path"
        $status = @{}
        foreach ($policy in $policies) {
            $status[$policy] = (Get-ItemProperty -Path $path -Name $policy -ErrorAction SilentlyContinue).$policy
        }
        return $status
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"
    $initial_status = Get-SecureChannelPolicyStatus -path $reg_path -policies $policy_names
    $vulnerable_policies = $policy_names | Where-Object { $initial_status[$_] -ne 1 }

    if ($vulnerable_policies) {
        $detect_status = "FAIL"
        Write-Host "[FAIL] Vulnerable secure channel policies found:" -ForegroundColor Yellow
        $vulnerable_policies | ForEach-Object { 
            $current_val = if ($null -eq $initial_status[$_]) { "Not Found" } else { $initial_status[$_] }
            Write-Host " - $_ is set to '$($current_val)' (Should be 1)" -ForegroundColor Yellow
        }
    } else {
        $detect_status = "PASS"
        Write-Host "[PASS] All secure channel policies are configured correctly." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
    Write-Host "--------------------"
    $final_status = $null
    if ($detect_status -eq "FAIL") {
        $choice = Read-Host "취약점이 발견되었습니다. 자동으로 조치하시겠습니까? (y/n)"
        if ($choice -match '^[Yy]$') {
            Write-Host "[INFO] User approved automatic remediation."
            foreach ($policy in $vulnerable_policies) {
                Write-Host "[ACTION] Setting policy '$policy' to 1 (Enabled)"
                try {
                    Set-ItemProperty -Path $reg_path -Name $policy -Value 1 -Type DWORD -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully set policy '$policy'." -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] Failed to set policy '$policy'. Details: $_" -ForegroundColor Red
                }
            }

            # Verification
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-SecureChannelPolicyStatus -path $reg_path -policies $policy_names
            $remaining_vulnerable = $policy_names | Where-Object { $final_status[$_] -ne 1 }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL"
                Write-Host "[FAIL] Remediation failed for one or more policies." -ForegroundColor Red
            } else {
                $remediate_status = "PASS"
                Write-Host "[PASS] Remediation successful for all vulnerable policies." -ForegroundColor Green
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
Good: All three secure channel policies are set to "Enabled" (1).
Vulnerable: One or more of the three secure channel policies are set to "Disabled" (0 or not present).
"@

    $check_content = @"
Check the following registry values under HKLM:\System\CurrentControlSet\Control\Lsa:
1. RequireSignOrSeal: Should be 1 (Enabled)
2. SealSecureChannel: Should be 1 (Enabled)
3. SignSecureChannel: Should be 1 (Enabled)
"@

    $fix_text = "Enable all three secure channel policies via Group Policy or by setting the corresponding registry keys to 1."

    Write-Host ""
    Write-Host "PHASE 3: GENERATING REPORT" -ForegroundColor Magenta
    Write-Host "--------------------------"
    Write-Host "[INFO] Generating final report object..."
    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "SC-8"
        check_target   = "W-78: Secure Channel Data Digital Encryption or Signing"
        discussion     = $discussion
        check_content  = $check_content
        fix_text       = $fix_text
        payload        = [PSCustomObject]@{
            severity     = "medium"
            service      = "NetLogon"
            protocol     = "RPC"
            threat       = @("Man-in-the-Middle (MitM) Attack", "Session Hijacking", "Replay Attack")
            TTP          = @("T1071", "T1557")
            file_checked = "Registry: HKLM\System\CurrentControlSet\Control\Lsa"
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
        check_target = "W-78: Secure Channel Data Digital Encryption or Signing"
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
        
        foreach ($policy_to_restore in $vulnerable_policies) {
            $original_value = $initial_status[$policy_to_restore]
            
            try {
                if ($null -eq $original_value) {
                    Write-Host "[ACTION] Restoring policy '$policy_to_restore' by removing it (it did not exist originally)."
                    Remove-ItemProperty -Path $reg_path -Name $policy_to_restore -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully removed policy '$policy_to_restore'." -ForegroundColor Green
                } else {
                    Write-Host "[ACTION] Restoring policy '$policy_to_restore' to original value: $original_value"
                    Set-ItemProperty -Path $reg_path -Name $policy_to_restore -Value $original_value -Type DWORD -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully restored policy '$policy_to_restore'." -ForegroundColor Green
                }
            } catch {
                Write-Host "[ERROR] Failed to restore policy '$policy_to_restore'. Details: $_" -ForegroundColor Red
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
