$OutputEncoding = [System.Text.Encoding]::UTF8

<#
.SYNOPSIS
Windows 서버 보안 점검 스크립트를 실행하는 명령줄 도구

.DESCRIPTION
이 스크립트는 KISA 가이드에 기반한 특정 `W-XX.ps1` 보안 스크립트를 찾아 실행하는 디스패처 역할을 합니다.
사용 가능한 스크립트 목록을 확인하고, 도움말을 얻으며, 선택한 동작(Detect, Remediate, Restore)으로 특정 스크립트를 실행할 수 있습니다.

.PARAMETER Command
첫 번째 위치 매개변수입니다. 스크립트 이름(예: 'W-24') 또는 'help' 명령어가 될 수 있습니다.
생략하면 도움말 메시지가 표시됩니다.

.PARAMETER Action
수행할 동작입니다. 기본값은 'Detect'입니다.
별칭은 '-a'입니다.

.EXAMPLE
# 도움말 메시지 표시
.\Wcheck.ps1 help

.EXAMPLE
# W-24 취약점 점검 실행 (기본 동작은 'Detect')
.\Wcheck.ps1 W-24

.EXAMPLE
# W-63 조치 실행
.\Wcheck.ps1 W-63 -a Remediate

.EXAMPLE
# W-78 백업에서 복원
.\Wcheck.ps1 W-78 --Action Restore
#>
param(
    [Parameter(Position=0)]
    [string]$Command,

    [ValidateSet("Detect", "Remediate", "Restore")]
    [Alias('a')]
    [string]$Action = "Detect"
)

# Get the directory where this script is located
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# --- Helper Function for printing Help ---
function Show-Help {
    Write-Host "Windows 서버 보안 점검 도구" -ForegroundColor Green
    Write-Host "KISA 보안 가이드라인 스크립트를 실행하는 도구입니다."
    Write-Host
    
    Write-Host "사용법:" -ForegroundColor Yellow
    Write-Host "  .\Wcheck.ps1 [스크립트_이름] [-Action <동작>]"
    Write-Host "  .\Wcheck.ps1 help"
    Write-Host

    Write-Host "명령어:" -ForegroundColor Yellow
    Write-Host "  help              이 도움말 메시지를 표시합니다."
    Write-Host

    Write-Host "사용 가능한 스크립트:" -ForegroundColor Yellow
    $scriptFiles = Get-ChildItem -Path $PSScriptRoot -Filter "W-*.ps1" -Recurse | Where-Object { $_.Name -match "^W-\d{2}\.ps1$" -and $_.Name -ne 'Wcheck.ps1' }
    if ($null -eq $scriptFiles) {
        Write-Host "  'W-XX.ps1' 스크립트를 찾을 수 없습니다." -ForegroundColor Red
    } else {
        foreach ($file in $scriptFiles) {
            $readmePath = Join-Path $file.DirectoryName "README.md"
            $description = ""
            if (Test-Path $readmePath) {
                $description = Get-Content $readmePath | ForEach-Object { if ($_ -match '^\s*-\s*`W-\d{2}`\s*:\s*(.+)$') { $Matches[1].Trim() } } | Select-Object -First 1
            }
            Write-Host ("  {0,-10} - {1}" -f $file.BaseName, $description)
        }
    }
    Write-Host

    Write-Host "옵션:" -ForegroundColor Yellow
    Write-Host "  -Action, -a <동작>"
    Write-Host "    수행할 동작을 지정합니다. 다음 중 하나를 선택할 수 있습니다:"
    Write-Host "      Detect    (기본값) - 변경 없이 취약점을 점검합니다."
    Write-Host "      Remediate           - 취약점을 점검하고 자동으로 조치합니다."
    Write-Host "      Restore             - 조치에 의해 변경된 사항을 되돌립니다 (복원)."
    Write-Host
}

# --- Main Logic ---
if ([string]::IsNullOrEmpty($Command) -or $Command -eq 'help') {
    Show-Help
    exit 0
}

# Discover the target script from the script's own root
$targetScriptName = if ($Command -match "^W-\d{2}$") { "$Command.ps1" } else { "$Command" }
$selectedScript = Get-ChildItem -Path $PSScriptRoot -Filter $targetScriptName -Recurse | Where-Object { $_.Name -ne 'Wcheck.ps1' } | Select-Object -First 1

if ($null -eq $selectedScript) {
    Write-Host "[오류] 스크립트 '$Command'를 찾을 수 없습니다." -ForegroundColor Red
    Write-Host "사용 가능한 스크립트 목록을 보려면 '.\Wcheck.ps1 help'를 실행하세요."
    exit 1
}

# Execute the script
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "스크립트 실행 중: $($selectedScript.FullName)"
Write-Host "동작: $Action"
Write-Host "==================================================" -ForegroundColor Cyan

try {
    # Execute in the context of the script's directory
    Push-Location -Path $selectedScript.DirectoryName
    
    # Execute the script with the -Action parameter
    & $selectedScript.FullName -Action $Action
    
    $exitCode = $LASTEXITCODE
    Pop-Location
    
    # --- Copy results after execution ---
    $sourceResultDir = Join-Path -Path $selectedScript.DirectoryName -ChildPath "KISA_RESULT"
    
    if (Test-Path -Path $sourceResultDir) {
        Write-Host "결과를 복사하는 중..." -ForegroundColor Green
        $destResultDir = Join-Path -Path $PSScriptRoot -ChildPath "KISA_RESULT"
        
        # Ensure the root result directory exists
        if (-not (Test-Path -Path $destResultDir)) {
            New-Item -ItemType Directory -Path $destResultDir | Out-Null
        }
        
        # Copy the contents of the script's result folder to the root result folder
        Copy-Item -Path "$sourceResultDir\*" -Destination $destResultDir -Recurse -Force
        
        Write-Host "결과가 '$destResultDir'에 복사되었습니다." -ForegroundColor Green
    }
    
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "스크립트 실행 완료."
    Write-Host "==================================================" -ForegroundColor Cyan
    exit $exitCode
}
catch {
    Write-Error "스크립트 실행 중 오류가 발생했습니다: $($selectedScript.FullName)"
    Write-Error $_
    exit 1
}