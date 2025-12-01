# Windows Server 보안 취약점 점검 스크립트 실행 결과 보고서 (예시)

이 문서는 `W-24`, `W-63`, `W-78` 스크립트의 각 테스트 단계별 실행 결과를 예시 형식으로 보여줍니다.

---

### W-24: NetBIOS 바인딩 서비스 구동 점검

< W-24 테스트 1: 초기 진단 (Vulnerable State) >
`[Vulnerable]` NetBIOS over TCP/IP 활성화됨. (현재 값: 1) `FAIL`.
- 설명: `set_vulnerabilities.ps1` 실행 후, 하나 이상의 네트워크 어댑터에서 NetBIOS가 '사용'으로 설정된 취약한 상태임을 정확히 진단했습니다.

< W-24 테스트 2: 백업 >
`[BACKUP]` Settings backed up to: C:\Test-Scripts\W-24.backup.json `PASS`.
- 설명: `Remediate` 모드 실행 시, 조치 전 원본 설정을 복원을 위해 JSON 파일로 성공적으로 백업했습니다.

< W-24 테스트 3: 조치 실행 >
`[SUCCESS]` NetBIOS over TCP/IP 비활성화 완료. `PASS`.
- 설명: `Invoke-CimMethod` 또는 `SetTcpipNetbios` 명령을 통해 취약한 어댑터의 NetBIOS 설정을 '사용 안 함'(2)으로 성공적으로 변경했습니다.

< W-24 테스트 4: 최종 검증 >
`[PASS]` 모든 네트워크 어댑터의 NetBIOS가 비활성화됨. `PASS`.
- 설명: 조치 후 재진단을 통해 모든 관련 설정이 정상적으로 반영되어 최종적으로 양호 상태가 되었음을 확인했습니다.

---

### W-63: DNS 서비스 동적 업데이트 설정 점검

< W-63 테스트 1: 초기 진단 (Vulnerable State) >
`[Vulnerable]` DNS 동적 업데이트가 안전하지 않게 설정됨. (현재 값: NonsecureAndSecure) `FAIL`.
- 설명: `set_vulnerabilities.ps1` 실행 후, `test.com` 주 DNS 영역의 동적 업데이트 설정이 취약한 상태임을 `dnscmd.exe` 대체 로직을 통해 정확히 진단했습니다.

< W-63 테스트 2: 백업 >
`[BACKUP]` Settings backed up to: C:\Test-Scripts\W-63.backup.json `PASS`.
- 설명: `Remediate` 모드 실행 시, 조치 전 `test.com` 영역의 원본 설정을 JSON 파일로 성공적으로 백업했습니다.

< W-63 테스트 3: 조치 실행 >
`[SUCCESS]` DNS 동적 업데이트 설정을 'None'으로 변경 완료. `PASS`.
- 설명: `dnscmd.exe /ZoneResetProperty` 대체 명령을 통해 취약한 DNS 영역의 동적 업데이트 설정을 'None'(0)으로 성공적으로 변경했습니다.

< W-63 테스트 4: 최종 검증 >
`[PASS]` 모든 주 DNS 영역이 안전하게 설정됨. `PASS`.
- 설명: 조치 후 재진단을 통해 모든 DNS 주 영역의 동적 업데이트가 'None'으로 설정되어 최종적으로 양호 상태가 되었음을 확인했습니다.

---

### W-78: 보안 채널 데이터 디지털 암호화/서명 점검

< W-78 테스트 1: 초기 진단 (Vulnerable State) >
`[Vulnerable]` 보안 채널 정책 미설정. (`RequireSignOrSeal` 값: 0) `FAIL`.
- 설명: `set_vulnerabilities.ps1` 실행 후, `RequireSignOrSeal` 레지스트리 값이 `0`으로 설정된 취약한 상태임을 정확히 진단했습니다.

< W-78 테스트 2: 백업 >
`[BACKUP]` Settings backed up to: C:\Test-Scripts\W-78.backup.json `PASS`.
- 설명: `Remediate` 모드 실행 시, 조치 전 `RequireSignOrSeal`의 원본 값(`0`)을 복원을 위해 JSON 파일로 성공적으로 백업했습니다.

< W-78 테스트 3: 조치 실행 >
`[SUCCESS]` 보안 채널 정책 '사용'(1) 적용 완료. `PASS`.
- 설명: `Set-ItemProperty` 명령을 통해 `RequireSignOrSeal` 정책 값을 KISA 권고 기준인 `1`로 성공적으로 설정했습니다.

< W-78 테스트 4: 최종 검증 >
`[PASS]` 모든 보안 채널 정책이 올바르게 설정됨. `PASS`.
- 설명: 조치 후 재진단을 통해 모든 관련 정책 값이 `1`로 설정되어 최종적으로 양호 상태가 되었음을 확인했습니다.