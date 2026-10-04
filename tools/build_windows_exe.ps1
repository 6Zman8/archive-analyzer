param(
    [string]$Python,
    [string]$DistPath,
    [string]$WorkPath,
    [string]$SpecPath,
    [string]$Name = "압축파일 검사기"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

function Get-ProjectPath([string]$Value, [string]$DefaultRelativePath) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [IO.Path]::GetFullPath((Join-Path $projectRoot $DefaultRelativePath))
    }
    if ([IO.Path]::IsPathRooted($Value)) {
        return [IO.Path]::GetFullPath($Value)
    }
    return [IO.Path]::GetFullPath((Join-Path $projectRoot $Value))
}

if ([string]::IsNullOrWhiteSpace($Name) -or [IO.Path]::GetFileName($Name) -ne $Name) {
    throw "Name은 경로가 아닌 실행파일 이름이어야 합니다."
}

$DistPath = Get-ProjectPath $DistPath "dist\final"
$WorkPath = Get-ProjectPath $WorkPath "build\final\work"
$SpecPath = Get-ProjectPath $SpecPath "build\final\spec"
$sourceRoot = Join-Path $projectRoot "src"
$migrations = Join-Path $sourceRoot "archive_analyzer\storage\migrations"
$ocrAssets = Join-Path $projectRoot "build\ocr-assets"
$launcher = Join-Path $PSScriptRoot "windows_launcher.py"
$target = Join-Path $DistPath "$Name.exe"

foreach ($version in "001", "002", "003", "004", "005", "006", "007", "008", "009") {
    $migration = Join-Path $migrations "$version.sql"
    if (-not (Test-Path -LiteralPath $migration -PathType Leaf)) {
        throw "필수 DB migration을 찾을 수 없습니다: $migration"
    }
}
if (Test-Path -LiteralPath $target) {
    throw "기존 실행파일을 덮어쓰지 않습니다: $target`n다른 DistPath 또는 Name을 지정해 주세요."
}

function Test-PathWithin([string]$Parent, [string]$Child) {
    $relative = [IO.Path]::GetRelativePath($Parent, $Child)
    return (-not [IO.Path]::IsPathRooted($relative)) -and
        ($relative -ne "..") -and
        (-not $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::Ordinal)) -and
        (-not $relative.StartsWith("..$([IO.Path]::AltDirectorySeparatorChar)", [StringComparison]::Ordinal))
}

function Test-PathStrictlyWithin([string]$Parent, [string]$Child) {
    $parentCanonical = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    $childCanonical = [IO.Path]::GetFullPath($Child).TrimEnd('\', '/')
    return (-not [StringComparer]::OrdinalIgnoreCase.Equals($parentCanonical, $childCanonical)) -and
        (Test-PathWithin $parentCanonical $childCanonical)
}

function Assert-SafeWorkPath([string]$Path) {
    $root = [IO.Path]::GetPathRoot($Path)
    $normalizedPath = $Path.TrimEnd('\', '/')
    if ([StringComparer]::OrdinalIgnoreCase.Equals($normalizedPath, $root.TrimEnd('\', '/'))) {
        throw "WorkPath에 파일 시스템 루트를 사용할 수 없습니다: $Path"
    }
    $protected = @(
        $env:WINDIR,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:PUBLIC
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') }
    foreach ($systemPath in $protected) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($normalizedPath, $systemPath) -or
            (Test-PathWithin $systemPath $normalizedPath)) {
            throw "WorkPath에 시스템 또는 광범위한 폴더를 사용할 수 없습니다: $Path"
        }
    }
    $cursor = $Path
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "WorkPath 경로에 링크/재분석 지점이 있어 사용할 수 없습니다: $cursor"
            }
            $parent = $item.Parent
            if ($null -eq $parent) { break }
            $cursor = $parent.FullName
        } else {
            $cursor = Split-Path -Parent $cursor
        }
    }
}

$workRoot = [IO.Path]::GetFullPath($WorkPath)
Assert-SafeWorkPath $workRoot
$projectBuildRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "build"))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$workRootNormalized = $workRoot.TrimEnd('\', '/')
if (-not ((Test-PathStrictlyWithin $projectBuildRoot $workRootNormalized) -or
        (Test-PathStrictlyWithin $tempRoot $workRootNormalized))) {
    throw "WorkPath는 프로젝트 build 또는 Windows 임시 폴더의 하위 경로여야 합니다: $workRoot"
}
$dedicatedWorkPath = [IO.Path]::GetFullPath((Join-Path $workRoot $Name))
if (-not (Test-PathWithin $workRoot $dedicatedWorkPath)) {
    throw "실행파일 전용 work 경로가 WorkPath 밖에 있습니다: $dedicatedWorkPath"
}
$ownershipMarker = Join-Path $dedicatedWorkPath ".archive-analyzer-build-owned"
if (Test-Path -LiteralPath $dedicatedWorkPath) {
    if (-not (Test-Path -LiteralPath $dedicatedWorkPath -PathType Container)) {
        throw "실행파일 전용 work 경로가 폴더가 아닙니다: $dedicatedWorkPath"
    }
    if (-not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf)) {
        throw "기존 실행파일 work 폴더의 소유권을 확인할 수 없어 삭제하지 않습니다: $dedicatedWorkPath"
    }
}

if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = Join-Path $projectRoot ".venv\Scripts\python.exe"
}
$Python = [IO.Path]::GetFullPath($Python)
$projectPython = [IO.Path]::GetFullPath((Join-Path $projectRoot ".venv\Scripts\python.exe"))
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($Python, $projectPython)) {
    throw "프로젝트 .venv Python만 빌드에 사용할 수 있습니다: $projectPython"
}
if (-not (Test-Path -LiteralPath $projectPython -PathType Leaf)) {
    throw "프로젝트 Python을 찾을 수 없습니다: $Python`n먼저 .venv에 개발 의존성을 설치해 주세요."
}

$preflight = @'
import sys

if sys.version_info[:2] != (3, 13):
    raise SystemExit("Python 3.13 is required for the Windows build.")
try:
    import PIL
    import PyInstaller
    import cv2
    import numpy
    import onnxruntime
    import rapidocr
except ImportError as error:
    raise SystemExit(
        "Pillow, PyInstaller, RapidOCR, ONNX Runtime, NumPy and OpenCV must all be installed in the selected project Python."
    ) from error
print(f"BUILD_PYTHON={sys.executable}")
print(f"PYTHON_VERSION={sys.version.split()[0]}")
print(f"PILLOW_VERSION={PIL.__version__}")
print(f"PYINSTALLER_VERSION={PyInstaller.__version__}")
print(f"ONNXRUNTIME_VERSION={onnxruntime.__version__}")
print(f"NUMPY_VERSION={numpy.__version__}")
print(f"OPENCV_VERSION={cv2.__version__}")
'@
& $Python -c $preflight
if ($LASTEXITCODE -ne 0) {
    throw "빌드 환경 확인에 실패했습니다. .venv에 OCR·패키징 의존성을 설치해 주세요."
}

New-Item -ItemType Directory -Force -Path $DistPath, $WorkPath, $SpecPath | Out-Null
if (Test-Path -LiteralPath $dedicatedWorkPath) {
    throw "기존 빌드 자료를 보존합니다. 다른 WorkPath를 지정해 주세요: $dedicatedWorkPath"
}
New-Item -ItemType Directory -Force -Path $dedicatedWorkPath | Out-Null
Set-Content -LiteralPath $ownershipMarker -Value "Archive Analyzer final build work directory" -Encoding ASCII -NoNewline
$migrationData = "$migrations;archive_analyzer/storage/migrations"
$ocrData = "$ocrAssets;archive_analyzer/ocr"
& $Python (Join-Path $PSScriptRoot "prepare_ocr_assets.py") --output $ocrAssets
if ($LASTEXITCODE -ne 0) {
    throw "오프라인 OCR 자원 준비에 실패했습니다."
}
& $Python -m PyInstaller `
    --onefile `
    --windowed `
    --name $Name `
    --paths $sourceRoot `
    --add-data $migrationData `
    --add-data $ocrData `
    --collect-all PIL `
    --collect-all rapidocr `
    --collect-all onnxruntime `
    --collect-all numpy `
    --collect-all cv2 `
    --distpath $DistPath `
    --workpath $dedicatedWorkPath `
    --specpath $SpecPath `
    $launcher

if ($LASTEXITCODE -ne 0) {
    throw "실행파일 빌드에 실패했습니다."
}
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "빌드가 끝났지만 실행파일을 찾을 수 없습니다: $target"
}

Get-Item -LiteralPath $target
