# W-24 취약점 재현 스크립트
# 목적: 테스트를 위해 시스템을 의도적으로 W-24 취약점 상태로 설정합니다.
# 이 스크립트는 첫 번째 활성 네트워크 어댑터의 NetBIOS over TCP/IP를 '사용'으로 설정합니다.

Write-Host "========= [W-24] Set Vulnerable State Script ==========" -ForegroundColor Yellow

# 관리자 권한 확인
Write-Host "[INFO] Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run with Administrator privileges." -ForegroundColor Red
    exit
}
Write-Host "[SUCCESS] Administrator privileges confirmed." -ForegroundColor Green

# PowerShell 버전에 따라 WMI/CIM 사용
$isLegacyPS = $PSVersionTable.PSVersion.Major -lt 3
if ($isLegacyPS) {
    Write-Host "[INFO] Legacy PowerShell detected. Using WMI." -ForegroundColor Yellow
} else {
    Write-Host "[INFO] Modern PowerShell detected. Using CIM."
}

# 첫 번째 활성 네트워크 어댑터 찾기
Write-Host "[INFO] Finding the first active network adapter..."
try {
    if ($isLegacyPS) {
        $adapter_instance = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'" | Select-Object -First 1
    } else {
        $adapter_instance = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'" | Select-Object -First 1
    }

    if ($adapter_instance) {
        Write-Host "[ACTION] Setting NetBIOS over TCP/IP to 'Enabled' (1) for adapter: $($adapter_instance.Description)" -ForegroundColor Cyan
        
        # 취약점 설정
        if ($isLegacyPS) {
            $result = $adapter_instance.SetTcpipNetbios(1)
        } else {
            $result = $adapter_instance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 1 }
        }

        if ($result.ReturnValue -eq 0) {
            Write-Host "[SUCCESS] Successfully set the adapter to a vulnerable state." -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Failed to set the adapter to a vulnerable state. Return code: $($result.ReturnValue)" -ForegroundColor Red
        }
    } else {
        Write-Host "[ERROR] No active network adapter found." -ForegroundColor Red
    }
} catch {
    Write-Host "[FATAL] An unexpected error occurred: $_" -ForegroundColor Red
}
