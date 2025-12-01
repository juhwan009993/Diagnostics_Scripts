# 스크립트 매개변수 정의
# -a: 스크립트의 실행 모드를 지정합니다 (Detect, Remediate, Restore). 기본값은 Detect입니다.
param(
    [ValidateSet("Detect", "Remediate", "Restore")]
    [string]$a = "Detect"
)

# --- 경로 및 파일 설정 ---
$dir = $PSScriptRoot
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_file = Join-Path $dir "W-78.backup.json"
# 결과 디렉터리가 없으면 생성합니다.
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

# 로그 및 JSON 결과 파일 경로를 설정합니다.
$log_file = Join-Path $result_dir "W-78.log"
$json_file = Join-Path $result_dir "W-78.json"

# --- 상태 변수 초기화 ---
$detect_status = "PASS" # 탐지 상태 (PASS, Vulnerable, ERROR)
$remediate_status = "FAIL" # 조치 상태 (PASS, SUCCESS, FAIL, N/A)
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK" # 현재 타임스탬프

# --- 함수 정의 ---

# 함수: 레지스트리에서 보안 채널 관련 정책들의 현재 값을 가져옵니다.
function Get-SecureChannelPolicyStatus {
    param($path, $policies)
    Write-Host "[INFO] Querying registry for secure channel policies at: $path"
    $status = @{}
    foreach ($policy in $policies) {
        # Get-ItemProperty를 사용하여 각 정책 값을 조회하고 상태 해시테이블에 저장합니다.
        $value = (Get-ItemProperty -Path $path -Name $policy -ErrorAction SilentlyContinue).$policy
        Write-Host "[DEBUG] Policy: '$policy', Value read from registry: '$value'"
        $status[$policy] = $value
    }
    return $status
}

# 함수: 백업 파일로부터 보안 채널 정책 설정을 복원합니다.
function Restore-FromBackup {
    if (-not (Test-Path $backup_file)) {
        Write-Host "[INFO] Backup file not found: $backup_file. Nothing to restore." -ForegroundColor Cyan
        exit
    }
    Write-Host "[INFO] Restoring settings from backup file: $backup_file" -ForegroundColor Cyan
    $backup_data = Get-Content -Path $backup_file | ConvertFrom-Json
    
    # 백업된 각 정책에 대한 설정을 복원합니다.
    foreach ($item in $backup_data) {
        $policy_to_restore = $item.PSObject.Properties.Name
        $original_value = $item.$policy_to_restore
        
        try {
            # 원래 값이 null이면 레지스트리 값을 제거합니다 (원래 존재하지 않았으므로).
            if ($null -eq $original_value) {
                Write-Host "[ACTION] Restoring policy '$policy_to_restore' by removing it (it did not exist originally)."
                if (Get-ItemProperty -Path $reg_path -Name $policy_to_restore -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $reg_path -Name $policy_to_restore -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully removed policy '$policy_to_restore'." -ForegroundColor Green
                } else {
                    Write-Host "[INFO] Policy '$policy_to_restore' does not exist. No action needed." -ForegroundColor White
                }
            } else {
                # 원래 값이 있었다면, 레지스트리를 해당 값으로 설정합니다.
                Write-Host "[ACTION] Restoring policy '$policy_to_restore' to original value: $original_value"
                Set-ItemProperty -Path $reg_path -Name $policy_to_restore -Value $original_value -Type DWORD -Force -ErrorAction Stop
                Write-Host "[SUCCESS] Successfully restored policy '$policy_to_restore'." -ForegroundColor Green
            }
        } catch {
            Write-Host "[ERROR] Failed to restore policy '$policy_to_restore'. Details: $_" -ForegroundColor Red
        }
    }
    # 복원 성공 후 백업 파일을 삭제합니다.
    Remove-Item -Path $backup_file
    Write-Host "[SUCCESS] Restoration complete. Backup file deleted." -ForegroundColor Green
}

# --- 메인 스크립트 실행 블록 ---
try {
    # 모든 스크립트 실행을 로깅 시작.
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-78] Secure Channel Policy Security Assessment (Action: $a) ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # 관리자 권한 확인.
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        $discussion = "This script must be run with Administrator privileges."
        throw $discussion # 관리자 권한이 없으면 오류 발생.
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    # 점검 대상 레지스트리 경로 및 정책 이름 설정.
    $reg_path = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $policy_names = @("RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel")

    # Restore 액션 처리.
    if ($a -eq 'Restore') {
        Restore-FromBackup
        exit
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"
    # 레지스트리에서 현재 보안 채널 정책 값을 가져옵니다.
    $initial_status = Get-SecureChannelPolicyStatus -path $reg_path -policies $policy_names
    # 값이 1이 아닌 (취약한) 정책들을 필터링합니다.
    $vulnerable_policies = $policy_names | Where-Object { $initial_status[$_] -ne 1 }

    if ($vulnerable_policies) {
        $detect_status = "Vulnerable"
        Write-Host "[Vulnerable] Vulnerable secure channel policies found:" -ForegroundColor Yellow
        # 취약한 정책과 현재 값을 출력합니다.
        $vulnerable_policies | ForEach-Object { 
            $current_val = if ($null -eq $initial_status[$_]) { "Not Found" } else { $initial_status[$_] }
            Write-Host " - $_ is set to '$($current_val)' (Should be 1)" -ForegroundColor Yellow
        }
    } else {
        $detect_status = "PASS"
        Write-Host "[PASS] All secure channel policies are configured correctly." -ForegroundColor Green
    }

    $final_status = $null
    # Remediate 액션 처리.
    if ($a -eq 'Remediate') {
        Write-Host ""
        Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
        Write-Host "--------------------"
        if ($detect_status -eq "Vulnerable") { # 취약한 경우에만 조치를 진행합니다.
            # 원래 설정 백업.
            Write-Host "[INFO] Backing up original settings to $backup_file..."
            $backup_data = $vulnerable_policies | ForEach-Object { 
                $policyName = $_
                $policyValue = $initial_status[$policyName]
                [PSCustomObject]@{
                    $policyName = $policyValue
                }
            }
            $backup_data | ConvertTo-Json | Set-Content -Path $backup_file -Encoding UTF8
            Write-Host "[SUCCESS] Backup complete." -ForegroundColor Green

            # 조치 적용 (정책 값을 1로 설정).
            foreach ($policy in $vulnerable_policies) {
                Write-Host "[ACTION] Setting policy '$policy' to 1 (Enabled)"
                try {
                    Set-ItemProperty -Path $reg_path -Name $policy -Value 1 -Type DWORD -Force -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully set policy '$policy'." -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] Failed to set policy '$policy'. Details: $_" -ForegroundColor Red
                }
            }

            # 조치 검증.
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-SecureChannelPolicyStatus -path $reg_path -policies $policy_names
            $remaining_vulnerable = $policy_names | Where-Object { $final_status[$_] -ne 1 }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL" # 조치 실패.
                Write-Host "[FAIL] Remediation failed for one or more policies." -ForegroundColor Red
            } else {
                $remediate_status = "SUCCESS" # 조치 성공.
                Write-Host "[SUCCESS] Remediation successful for all vulnerable policies." -ForegroundColor Green
            }
        } else {
            $remediate_status = "PASS" # 조치 필요 없음.
            Write-Host "[INFO] No remediation required."
        }
    }

    # 기본 보고서 내용 설정.
    if (!$discussion) {
        $discussion = @'
Good: All three secure channel policies are set to "Enabled" (1).
Vulnerable: One or more of the three secure channel policies are set to "Disabled" (0 or not present).
'@
        $check_content = @'
Check the following registry values under HKLM:\System\CurrentControlSet\Control\Lsa:
1. RequireSignOrSeal: Should be 1 (Enabled)
2. SealSecureChannel: Should be 1 (Enabled)
3. SignSecureChannel: Should be 1 (Enabled)
'@
        $fix_text = "Enable all three secure channel policies via Group Policy or by setting the corresponding registry keys to 1."
    }

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
            port         = "53"
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
                details = ($(if ($final_status) { $final_status } else { $initial_status }) | ConvertTo-Json -Compress)
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
    # 결과가 있는 경우 JSON 파일로 저장.
    if ($result) {
        Write-Host "[INFO] Saving report to: $json_file"
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    # 로깅 중지.
    Write-Host "[INFO] Stopping script execution log."
    Stop-Transcript | Out-Null
}
