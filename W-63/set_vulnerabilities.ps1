# W-63 취약점 재현 스크립트
# 목적: 테스트를 위해 시스템을 의도적으로 W-63 취약점 상태로 설정합니다.
# 이 스크립트는 첫 번째 주 DNS 영역(Primary Zone)의 동적 업데이트를 '안전하지 않음(NonsecureAndSecure)'으로 설정합니다.

Write-Host "========= [W-63] Set Vulnerable State Script ==========" -ForegroundColor Yellow

# 관리자 권한 확인
Write-Host "[INFO] Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run with Administrator privileges." -ForegroundColor Red
    exit
}
Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

# DnsServer 모듈 확인
Write-Host "[INFO] Checking for DnsServer PowerShell module..."
if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "[ERROR] DnsServer module not found. This script requires a modern Windows Server with the DNS role." -ForegroundColor Red
    exit
}
Write-Host "[INFO] DnsServer module found."

# 첫 번째 주 DNS 영역 찾기
Write-Host "[INFO] Finding the first primary DNS zone..."
try {
    Import-Module DnsServer
    $zone = Get-DnsServerPrimaryZone -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($zone) {
        Write-Host "[ACTION] Setting Dynamic Updates to 'NonsecureAndSecure' for zone: $($zone.ZoneName)" -ForegroundColor Cyan
        
        # 취약점 설정
        Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate "NonsecureAndSecure" -ErrorAction Stop
        
        Write-Host "[SUCCESS] Successfully set the DNS zone to a vulnerable state." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] No primary DNS zone found to make vulnerable." -ForegroundColor Red
    }
} catch {
    Write-Host "[FATAL] An unexpected error occurred: $_" -ForegroundColor Red
}
