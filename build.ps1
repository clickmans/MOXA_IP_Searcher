# 一键构建 MOXA_IP_Searcher（Windows x64 单文件、无依赖）
#
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
#   powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 2.0
#
# 产物（v1.8 起按版本号命名，旧文件一律保留）：
#   dist\MOXA_IP_Searcher_v<版本>.exe   主交付（带版本号，归档用）
#   dist\MOXA_IP_Searcher.exe           同内容副本（方便双击）
#
# 本脚本只写这两个文件；dist\versions\ 下的历史版本永不删除、不覆盖。
# 依赖：仅需要 Go 1.24（不需要 CGO、不需要任何第三方包、可离线编译）

param(
    [string]$Version = '1.9.1'
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'

# 优先使用固定安装路径，找不到再退回 PATH 里的 go
$go = "$env:ProgramFiles\Go\bin\go.exe"
if (-not (Test-Path $go)) { $go = 'go' }

Write-Host "==> 编译器: $go" -ForegroundColor Cyan
& $go version
if ($LASTEXITCODE -ne 0) { throw 'go 不可用，请先安装 Go 1.24' }

Write-Host "==> 目标版本: v$Version" -ForegroundColor Cyan

if (-not (Test-Path 'dist')) { New-Item -ItemType Directory -Path 'dist' | Out-Null }
if (-not (Test-Path 'dist\versions')) { New-Item -ItemType Directory -Path 'dist\versions' | Out-Null }

Write-Host '==> 格式检查（gofmt -l 必须无输出）' -ForegroundColor Cyan
$unformatted = & $go fmt ./src/... 2>&1 | Where-Object { $_ -and $_ -notmatch '^$' }
if ($unformatted) { Write-Warning "go fmt 改动了以下文件: $unformatted" }

Write-Host '==> 运行单元测试' -ForegroundColor Cyan
& $go test ./src/... -count=1
if ($LASTEXITCODE -ne 0) { throw "单元测试失败 (exit $LASTEXITCODE)" }

$versioned = "dist\MOXA_IP_Searcher_v$Version.exe"
$current = 'dist\MOXA_IP_Searcher.exe'

Write-Host "==> 构建 $versioned" -ForegroundColor Cyan
& $go build -trimpath -ldflags "-H=windowsgui -s -w" -o $versioned .\src
if ($LASTEXITCODE -ne 0) { throw "构建失败 (exit $LASTEXITCODE)" }

Write-Host "==> 同步副本 $current（同内容）" -ForegroundColor Cyan
Copy-Item -LiteralPath $versioned -Destination $current -Force

$exe = Get-Item -LiteralPath $versioned
$copy = Get-Item -LiteralPath $current
Write-Host ('==> 完成: {0}  ({1:N0} 字节)' -f $exe.FullName, $exe.Length) -ForegroundColor Green
Write-Host ('==> 副本: {0}  ({1:N0} 字节)' -f $copy.FullName, $copy.Length) -ForegroundColor Green
Write-Host ('    SHA256 {0}' -f (Get-FileHash -LiteralPath $versioned -Algorithm SHA256).Hash)
Write-Host ('    SHA256 {0}  (副本)' -f (Get-FileHash -LiteralPath $current -Algorithm SHA256).Hash)

Write-Host '==> 历史版本（只读核对，不删不改）' -ForegroundColor Cyan
Get-ChildItem -LiteralPath 'dist\versions' -Filter '*.exe' -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host ('    {0}  {1:N0} 字节  {2}' -f $_.Name, $_.Length,
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)
}

Write-Host '==> 无界面自检（本机无设备时应输出 devices: [] 且退出码 0）' -ForegroundColor Cyan
& $exe.FullName --scan --out dist\_scan_test.json
Write-Host "自检退出码: $LASTEXITCODE"
if ($LASTEXITCODE -ne 0) { throw '无界面自检失败' }

if ((Test-Path '_analysis\pe_res_check.py') -and (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host '==> 图标资源自检（应输出 HAS ICON）' -ForegroundColor Cyan
    python -X utf8 _analysis\pe_res_check.py $exe.FullName
}
else {
    Write-Host '==> 跳过图标自检（未找到 python，可稍后手动执行 pe_res_check.py）' -ForegroundColor Yellow
}
