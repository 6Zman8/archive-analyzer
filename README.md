# 압축파일 검사기 (Archive Analyzer)

ZIP·CBZ·RAR·7z 안의 이미지로 중복 후보를 찾고 비교·검토하는 Windows 프로그램입니다.

**[최신 실행파일 다운로드](https://github.com/6Zman8/archive-analyzer/releases/latest)**

## 실행하기

1. 최신 릴리스의 `ArchiveAnalyzer.exe`를 내려받아 전용 폴더에 넣습니다.
2. 더블클릭합니다. Python 설치나 GitHub 로그인은 필요하지 않습니다.
3. 이전 결과는 **저장된 결과 열기**, 새 검사는 **폴더 선택 → 검사 시작**을 사용합니다.

Windows 10/11 64비트를 지원합니다. RAR·7z를 읽으려면 7-Zip이 필요합니다.
검사 DB와 설정은 Windows 사용자 데이터 폴더에 저장됩니다. 검사는 원본을 바꾸지 않으며,
격리·휴지통 이동은 사용자가 직접 선택한 동작으로만 수행합니다.

## 자동 업데이트

시작 시 및 6시간마다 GitHub 최신 정식 버전을 확인합니다. 새 EXE를 백그라운드에서 받고
크기·SHA-256을 검증합니다. 작업을 마친 뒤 프로그램을 종료하면 자동 적용되고 다음 실행에 새 버전을 사용합니다.
실패하면 기존 파일을 유지하거나 복구합니다. **기능 추가 전 구버전은 한 번 직접 교체해야 합니다.**

- [사용 방법](docs/USER_GUIDE.md)
- [정리된 화면과 기능 위치](docs/UI_GUIDE.md)
- [자동 업데이트 설정과 새 버전 배포 방법](docs/UPDATES.md)
- [새 버전 배포 화면](https://github.com/6Zman8/archive-analyzer/actions/workflows/release.yml)

## 개발과 배포

Python 3.13으로 `.venv`를 만들고 `pip install -e ".[dev]"`로 설치합니다.
`python tools/run_regression.py`는 일반 테스트와 Tk 테스트를 별도 프로세스에서 실행합니다.
Windows EXE는 `tools/build_windows_exe.ps1`로 만듭니다.

코드 변경을 `main`에 올린 후 Actions의 **Windows 새 버전 배포 → Run workflow**에서
새 버전 번호와 변경 내용을 입력하면 검사·빌드·릴리스 공개까지 처리합니다.
공개할 릴리스 자산 이름은 `ArchiveAnalyzer.exe`입니다.

사용자 DB, 개인 경로 기록, 인증 정보는 이 저장소에 포함하지 않습니다.
