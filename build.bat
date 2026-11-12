@echo off
rem 一键构建 MOXA_IP_Searcher（Windows x64 单文件、无依赖）
rem 产物（v1.8 起按版本号命名，旧文件一律保留）:
rem   dist\MOXA_IP_Searcher_v1.8.exe  主交付
rem   dist\MOXA_IP_Searcher.exe       同内容副本
setlocal
cd /d "%~dp0"

set VERSION=1.8
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

set GOEXE=C:\Program Files\Go\bin\go.exe
if not exist "%GOEXE%" set GOEXE=go

echo ==^> 运行单元测试
"%GOEXE%" test ./src/... -count=1
if errorlevel 1 goto :fail

if not exist dist mkdir dist

echo ==^> 构建 dist\MOXA_IP_Searcher_v%VERSION%.exe
"%GOEXE%" build -trimpath -ldflags "-H=windowsgui -s -w" -o dist\MOXA_IP_Searcher_v%VERSION%.exe .\src
if errorlevel 1 goto :fail

echo ==^> 同步 dist\MOXA_IP_Searcher.exe
copy /y dist\MOXA_IP_Searcher_v%VERSION%.exe dist\MOXA_IP_Searcher.exe >nul
if errorlevel 1 goto :fail

echo ==^> 完成
dir dist\MOXA_IP_Searcher_v%VERSION%.exe dist\MOXA_IP_Searcher.exe
goto :eof

:fail
echo 构建失败
exit /b 1
