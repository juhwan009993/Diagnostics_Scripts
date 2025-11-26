# W-78 취약점 재현 스크립트
# 목적: 테스트를 위해 시스템을 의도적으로 W-78 취약점 상태로 설정합니다.
# 이 스크립트는 보안 채널 관련 레지스트리 키 중 하나인 'RequireSignOrSeal'을 '0' (사용 안 함)으로 설정합니다.

Write-Host "========= [W-78] Set Vulnerable State Script ==========" -ForegroundColor Yellow

# 관리자 권한 확인
Write-Host "[INFO] Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run with Administrator privileges." -ForegroundColor Red
    exit
}
Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

$reg_path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$policy_to_weaken = "RequireSignOrSeal"

# 레지스트리 키 설정
Write-Host "[ACTION] Setting registry policy '$policy_to_weaken' to 0 (Disabled)..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path $reg_path -Name $policy_to_weaken -Value 0 -Type DWORD -Force -ErrorAction Stop
    Write-Host "[SUCCESS] Successfully set the registry policy to a vulnerable state." -ForegroundColor Green
} catch {
    Write-Host "[FATAL] An unexpected error occurred: $_" -ForegroundColor Red
}
