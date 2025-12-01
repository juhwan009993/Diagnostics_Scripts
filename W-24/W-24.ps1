# 스크립트 매개변수 정의
# -Action: 스크립트의 실행 모드를 지정합니다 (Detect: 점검, Remediate: 조치, Restore: 복원)
# 기본값은 Detect입니다.
param(
    [ValidateSet("Detect", "Remediate", "Restore")]
    [string]$Action = "Detect"
)

# 스크립트 실행 경로 및 결과 저장 경로 설정
$dir = $PSScriptRoot
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_file = Join-Path $dir "W-24.backup.json"
# 결과 디렉터리가 없으면 생성
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

# 로그 파일 및 JSON 결과 파일 경로 설정
$log_file = Join-Path $result_dir "W-24.log"
$json_file = Join-Path $result_dir "W-24.json"

# 초기 상태 및 결과 변수 설정
$detect_status = "PASS" # 탐지 상태 (PASS, Vulnerable, ERROR)
$remediate_status = "FAIL" # 조치 상태 (PASS, FAIL, N/A)
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK" # 현재 타임스탬프
# PowerShell 버전 확인 (레거시/최신 CIM cmdlet 사용 분기)
$isLegacyPS = $PSVersionTable.PSVersion.Major -lt 3

# 함수: 네트워크 어댑터의 NetBIOS 설정 상태를 가져옵니다.
function Get-NetbiosStatus {
    Write-Host "[INFO] Querying for network adapter configurations..."
    # PowerShell 버전에 따라 WMI 또는 CIM cmdlet 사용
    if ($isLegacyPS) {
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'"
    } else {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'"
    }
    
    $status = @()
    # 각 어댑터의 NetBIOS 설정 정보 추출
    foreach ($adapter in $adapters) {
        # 디버깅을 위해 각 어댑터의 실제 TcpipNetbiosOptions 값을 출력합니다.
        Write-Host "[DEBUG] Adapter: $($adapter.Description), Raw TcpipNetbiosOptions value: $($adapter.TcpipNetbiosOptions)"
        $status += [PSCustomObject]@{
            Adapter        = $adapter.Description
            InterfaceIndex = $adapter.InterfaceIndex
            NetbiosSetting = $adapter.TcpipNetbiosOptions # 0: DHCP, 1: Enabled, 2: Disabled
            IsVulnerable   = $adapter.TcpipNetbiosOptions -ne 2 # NetBIOS가 비활성화(2)가 아니면 취약
        }
    }
    Write-Host "[INFO] Found $($status.Count) IP-enabled network adapters."
    return $status
}

# 함수: 백업 파일로부터 NetBIOS 설정을 복원합니다.
function Restore-FromBackup {
    # 백업 파일 존재 여부 확인
    if (-not (Test-Path $backup_file)) {
        Write-Host "[INFO] Backup file not found: $backup_file. Nothing to restore." -ForegroundColor Cyan
        exit
    }
    Write-Host "[INFO] Restoring settings from backup file: $backup_file" -ForegroundColor Cyan
    # 백업 파일 내용 읽고 JSON 역직렬화
    $adapters_to_restore = Get-Content -Path $backup_file | ConvertFrom-Json
    
    # 각 어댑터에 대해 설정 복원
    foreach ($adapter_to_restore in $adapters_to_restore) {
        $original_setting = $adapter_to_restore.NetbiosSetting
        Write-Host "[ACTION] Restoring NetBIOS setting for '$($adapter_to_restore.Adapter)' to original value: $original_setting"
        
        try {
            # PowerShell 버전에 따라 WMI 또는 CIM cmdlet 사용
            if ($isLegacyPS) {
                $adapter_instance = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_to_restore.InterfaceIndex)"
                $restore_result = $adapter_instance.SetTcpipNetbios($original_setting)
            } else {
                $adapter_instance = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_to_restore.InterfaceIndex)"
                $restore_result = $adapter_instance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = $original_setting}
            }

            # 복원 결과 확인
            if ($restore_result.ReturnValue -eq 0) {
                Write-Host "[SUCCESS] Successfully restored setting for '$($adapter_to_restore.Adapter)'." -ForegroundColor Green
            } else {
                Write-Host "[ERROR] Failed to restore setting for '$($adapter_to_restore.Adapter)'. Return code: $($restore_result.ReturnValue)" -ForegroundColor Red
            }
        } catch {
            Write-Host "[ERROR] Failed to restore setting for '$($adapter_to_restore.Adapter)'. Details: $_" -ForegroundColor Red
        }
    }
    # 복원 완료 후 백업 파일 삭제
    Remove-Item -Path $backup_file
    Write-Host "[SUCCESS] Restoration complete. Backup file deleted." -ForegroundColor Green
}

# 메인 스크립트 실행 블록
try {
    # 스크립트 실행 시작 및 로그 기록 시작
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-24] Windows Server Security Assessment (Action: $Action) ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # PowerShell 버전 정보 출력
    if ($isLegacyPS) {
        Write-Host "[INFO] Legacy PowerShell (version < 3.0) detected. Using WMI cmdlets." -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] Modern PowerShell (version >= 3.0) detected. Using CIM cmdlets."
    }

    # 관리자 권한 확인
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        $discussion = "This script must be run with Administrator privileges."
        throw $discussion # 관리자 권한 없으면 오류 발생
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    # Restore 액션이 지정된 경우 복원 함수 실행 후 종료
    if ($Action -eq 'Restore') {
        Restore-FromBackup
        exit
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"
    # NetBIOS 설정 상태 가져오기
    $initial_status = Get-NetbiosStatus
    # 취약한 어댑터 필터링
    $vulnerable_adapters = $initial_status | Where-Object { $_.IsVulnerable }
    if ($vulnerable_adapters) {
        $detect_status = "Vulnerable" # 취약점 발견 시 상태 변경
        Write-Host "[Vulnerable] Vulnerable adapters found:" -ForegroundColor Yellow
        $vulnerable_adapters | ForEach-Object { Write-Host " - $($_.Adapter) (NetBIOS over TCP/IP is not disabled)" -ForegroundColor Yellow }
    } else {
        $detect_status = "PASS" # 취약점 없음
        Write-Host "[PASS] All network adapters have NetBIOS over TCP/IP disabled." -ForegroundColor Green
    }

    $final_status = $null
    # Remediate 액션이 지정된 경우 조치 단계 실행
    if ($Action -eq 'Remediate') {
        Write-Host ""
        Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
        Write-Host "--------------------"
        if ($detect_status -eq "Vulnerable") { # 취약한 상태인 경우에만 조치 진행
            # 원래 설정 백업
            Write-Host "[INFO] Backing up original settings for vulnerable adapters to $backup_file..."
            $vulnerable_adapters | ConvertTo-Json | Set-Content -Path $backup_file -Encoding UTF8
            Write-Host "[SUCCESS] Backup complete." -ForegroundColor Green

            # 취약점 조치 적용 (NetBIOS 비활성화)
            foreach ($adapter_info in $vulnerable_adapters) {
                Write-Host "[ACTION] Disabling NetBIOS over TCP/IP for: $($adapter_info.Adapter)"
                
                # PowerShell 버전에 따라 WMI 또는 CIM cmdlet 사용
                if ($isLegacyPS) {
                    $adapter_instance = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_info.InterfaceIndex)"
                    $result = $adapter_instance.SetTcpipNetbios(2) # 2: 비활성화
                } else {
                    $adapter_instance = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($adapter_info.InterfaceIndex)"
                    $result = $adapter_instance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} # 2: 비활성화
                }

                # 조치 결과 확인
                if ($result.ReturnValue -eq 0) {
                    Write-Host "[SUCCESS] Successfully sent command to disable NetBIOS for: $($adapter_info.Adapter)" -ForegroundColor Green
                } else {
                    Write-Host "[ERROR] Failed to disable NetBIOS for: $($adapter_info.Adapter). Return code: $($result.ReturnValue)" -ForegroundColor Red
                }
            }

            # 조치 후 재검증
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-NetbiosStatus
            $remaining_vulnerable = $final_status | Where-Object { $_.IsVulnerable }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL" # 조치 실패
                Write-Host "[FAIL] Remediation failed for one or more adapters." -ForegroundColor Red
            } else {
                $remediate_status = "PASS" # 조치 성공
                Write-Host "[PASS] Remediation successful for all vulnerable adapters." -ForegroundColor Green
            }
        } else {
            $remediate_status = "PASS" # 조치할 취약점 없음
            Write-Host "[INFO] No remediation required."
        }
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
                details = ConvertTo-Json -InputObject $(if ($final_status) { $final_status } else { $initial_status }) -Compress
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
    if ($result) {
        Write-Host "[INFO] Saving report to: $json_file"
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    Write-Host "[INFO] Stopping script execution log."
    Stop-Transcript | Out-Null
}