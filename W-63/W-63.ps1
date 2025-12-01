# 스크립트 매개변수 정의
# -a: 스크립트의 실행 모드를 지정합니다 (Detect, Remediate, Restore). 기본값은 Detect
param(
    [ValidateSet("Detect", "Remediate", "Restore")]
    [string]$a = "Detect"
)

# 출력 인코딩을 UTF-8로 설정하여 문자 깨짐을 방지
$OutputEncoding = [System.Text.Encoding]::UTF8

# --- 경로 및 파일 설정 ---
$dir = $PSScriptRoot
$result_dir = Join-Path $dir "KISA_RESULT"
$backup_file = Join-Path $dir "W-63.backup.json"
# 디렉터리가 없으면 생성합니다.
New-Item -ItemType Directory -Force -Path $result_dir | Out-Null

# 로그 및 JSON 결과 파일 경로를 설정
$log_file = Join-Path $result_dir "W-63.log"
$json_file = Join-Path $result_dir "W-63.json"

# --- 상태 변수 초기화 ---
$detect_status = "PASS" # 탐지 상태 (PASS, FAIL, Vulnerable, ERROR)
$remediate_status = "FAIL" # 조치 상태 (SUCCESS, FAIL, N/A)
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK" # 현재 타임스탬프

# --- 함수 정의 ---

# [내부 함수] dnscmd.exe를 사용하여 DNS Zone 상태를 가져옴 (PowerShell Cmdlet 실패 시 대체 수단).
function Get-DnsZoneStatusFromDnscmd {
    Write-Host "[INFO] Fallback: Attempting to get DNS zones using dnscmd.exe..."
    $zones = @()
    try {
        $zone_list_output = dnscmd.exe /EnumZones

        # 헤더 라인을 건너뛰고 각 존 라인을 처리
        $zone_lines = $zone_list_output | Select-Object -Skip 4
        
        foreach ($line in $zone_lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -match "Command completed successfully") { continue }

            # 여러 공백을 기준으로 라인을 컬럼으로 분할
            $columns = $line.Trim() -split '\s+' | Where-Object { $_ }
            
            if ($columns.Count -ge 2) {
                $zone_name = $columns[0]
                $zone_type = $columns[1]

                # 주 영역만 처리
                if ($zone_type -eq 'Primary') {
                    $zone_info = dnscmd.exe /ZoneInfo $zone_name
                    
                    # 'update' 값을 안전하게 추출
                    $update_line = $zone_info | Where-Object { $_ -match '^\s*update\s*=' } | Select-Object -First 1
                    $update_value = "0" # 기본값 'None'
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


# DNS Zone 상태를 가져오는 메인 함수. PowerShell Cmdlet을 먼저 시도하고, 실패 시 dnscmd.exe로 대체
function Get-DnsZoneStatus {
    try {
        Write-Host "[INFO] Querying for all primary DNS zones using PowerShell Cmdlet..."
        Import-Module DnsServer -ErrorAction Stop -Force
        # Get-DnsServerPrimaryZone Cmdlet을 사용하여 상태를 가져옵니다.
        return Get-DnsServerPrimaryZone -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                ZoneName      = $_.ZoneName
                DynamicUpdate = $_.DynamicUpdate.ToString()
                IsVulnerable  = $_.DynamicUpdate -ne "None"
            }
        }
    } catch {
        # Cmdlet이 실패하면 dnscmd.exe 대체 수단을 호출합니다.
        Write-Host "[WARN] PowerShell Cmdlet failed. This can happen in some environments. Attempting fallback..." -ForegroundColor Yellow
        Write-Host "Error details: $($_.Exception.Message)"
        return Get-DnsZoneStatusFromDnscmd
    }
}

# 백업 파일로부터 설정을 복원하는 함수.
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
            # 복원 시도: 먼저 PowerShell Cmdlet 사용.
            Set-DnsServerPrimaryZone -Name $zone_to_restore.ZoneName -DynamicUpdate $original_setting -ErrorAction Stop
            Write-Host "[SUCCESS] Successfully restored setting for zone '$($zone_to_restore.ZoneName)' via Cmdlet." -ForegroundColor Green
        } catch {
            # Cmdlet 실패 시 dnscmd.exe로 대체.
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
    # 복원 완료 후 백업 파일 삭제.
    Remove-Item -Path $backup_file
    Write-Host "[SUCCESS] Restoration complete. Backup file deleted." -ForegroundColor Green
}


# --- 메인 스크립트 실행 블록 ---
try {
    # 모든 스크립트 실행 과정을 로깅 시작.
    Write-Host "[INFO] Starting script execution and logging to: $log_file"
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-63] DNS Dynamic Update Security Assessment (Action: $a) ==========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    # 관리자 권한 확인.
    Write-Host "[INFO] Checking for Administrator privileges..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $detect_status = "ERROR"
        $remediate_status = "N/A"
        throw "This script must be run with Administrator privileges."
    }
    Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

    # Restore 액션 처리.
    if ($a -eq 'Restore') {
        Restore-FromBackup
        exit
    }

    Write-Host ""
    Write-Host "PHASE 1: VULNERABILITY DETECTION" -ForegroundColor Magenta
    Write-Host "---------------------------------"

    # DNS 서비스 존재 여부 확인.
    $dns_service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if (-not $dns_service) {
        # DNS 서비스가 없으면 점검 대상이 아님.
        $detect_status = "PASS"
        $remediate_status = "PASS"
        $discussion = "Good: DNS service is not installed, so this check is not applicable."
        $initial_status = @([PSCustomObject]@{ Status = "DNS Service Not Found" })
        Write-Host "[PASS] DNS Service is not installed. This check is not applicable." -ForegroundColor Green
    } else {
        # DNS Zone 상태 가져오기 (대체 로직 포함).
        $initial_status = Get-DnsZoneStatus
        
        if ($null -eq $initial_status) {
            # Get-DnsZoneStatus가 심각하고 복구 불가능한 오류를 만난 경우.
            throw "Could not retrieve DNS zone status from any available method."
        }

        $vulnerable_zones = $initial_status | Where-Object { $_.IsVulnerable }

        if ($vulnerable_zones) {
            $detect_status = "Vulnerable"
            Write-Host "[Vulnerable] Vulnerable DNS zones found:" -ForegroundColor Yellow
            $vulnerable_zones | ForEach-Object { Write-Host " - $($_.ZoneName) (Dynamic updates: $($_.DynamicUpdate))" -ForegroundColor Yellow }
        } else {
            $detect_status = "PASS"
            Write-Host "[PASS] All primary DNS zones are configured securely (Dynamic Updates are 'None') or no primary zones found." -ForegroundColor Green
        }
    }

    $final_status = $null
    # Remediate 액션 처리.
    if ($a -eq 'Remediate') {
        Write-Host ""
        Write-Host "PHASE 2: REMEDIATION" -ForegroundColor Magenta
        Write-Host "--------------------"
        if ($detect_status -eq "Vulnerable") {
            # 원래 설정 백업.
            Write-Host "[INFO] Backing up original settings for vulnerable zones to $backup_file..."
            $vulnerable_zones | ConvertTo-Json | Set-Content -Path $backup_file -Encoding UTF8
            Write-Host "[SUCCESS] Backup complete." -ForegroundColor Green

            # 조치 적용.
            foreach ($zone in $vulnerable_zones) {
                Write-Host "[ACTION] Disabling dynamic updates for zone: $($zone.ZoneName)"
                try {
                    # 시도 1: PowerShell Cmdlet 사용.
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate None -ErrorAction Stop
                    Write-Host "[SUCCESS] Successfully disabled dynamic updates for: $($zone.ZoneName) via Cmdlet" -ForegroundColor Green
                } catch {
                    # 시도 2: dnscmd.exe로 대체.
                    Write-Host "[WARN] Set-DnsServerPrimaryZone failed. Attempting fallback with dnscmd.exe..." -ForegroundColor Yellow
                    try {
                        dnscmd.exe /ZoneResetProperty $zone.ZoneName /DynamicUpdate 0
                        Write-Host "[SUCCESS] Successfully disabled dynamic updates for: $($zone.ZoneName) via dnscmd.exe" -ForegroundColor Green
                    } catch {
                        Write-Host "[ERROR] Failed to disable dynamic updates for zone: $($zone.ZoneName) with both methods. Details: $_" -ForegroundColor Red
                    }
                }
            }

            # 조치 검증.
            Write-Host "[INFO] Verifying remediation..."
            $final_status = Get-DnsZoneStatus
            if ($null -eq $final_status) { throw "Could not re-check DNS zones after remediation." }
            $remaining_vulnerable = $final_status | Where-Object { $_.IsVulnerable }
            if ($remaining_vulnerable) {
                $remediate_status = "FAIL"
                Write-Host "[FAIL] Remediation failed for one or more zones." -ForegroundColor Red
            } else {
                $remediate_status = "SUCCESS"
                Write-Host "[SUCCESS] Remediation successful for all vulnerable zones." -ForegroundColor Green
            }
        } else {
            $remediate_status = "PASS"
            Write-Host "[INFO] No remediation required."
        }
    }

    # 특정 조건에 의해 설정되지 않은 경우 기본 보고서 내용 설정.
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
    # 결과가 있는 경우 JSON 파일로 저장.
    if ($result) {
        Write-Host "[INFO] Saving report to: $json_file"
        $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
    }
    # 로깅 중지.
    Write-Host "[INFO] Stopping script execution log."
    Stop-Transcript | Out-Null
}