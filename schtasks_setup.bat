@echo off
SET NAME="PSC Syslog Connector"
SET CMD="%~dp0PSC_Syslog_Connector.exe"

if "%1" == "/Install" Goto Install
if "%1" == "/Update" Goto Update
if "%1" == "/Delete" Goto Delete
if "%1" == "/Enable" Goto Enable
if "%1" == "/Disable" Goto Disable
if "%1" == "/?" (
    echo Usage: %0 ^[/Update ^| /Delete ^| /Enable ^| /Disable ^]
    echo %NAME% 実行用タスクスケジュールを作成します。
    echo オプション：
    echo 　/Update　既存タスクスケジュールの設定更新
    echo 　/Delete　既存タスクスケジュールの削除
    echo 　/Enable　既存タスクスケジュールの有効化
    echo 　/Disable 既存タスクスケジュールの無効化
    echo
    pause
    exit /b 0
)

:Install
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 0 (
    REM Update Task Scheduler setting with new command
    REM chtasks /Change /TN %NAME% /TR %CMD% 
    exit /b 0
)
:Create
REM Create new Task Scheduler settings
schtasks /Create /TN %NAME% /TR %CMD% /SC daily /ST 00:00 /DU 23:55 /RI 10 /RU ""
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの作成に失敗しました。
    pause
    exit /b 1
)
REM Check created Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの作成に失敗しました。
    pause
    exit /b 1
)
exit /b 0

:Update
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    REM No entry found
    Goto Create
    exit /b 0
)
REM Update new Task Scheduler settings
schtasks /Change /TN %NAME% /TR %CMD% /ST 00:00 /DU 23:55 /RI 10 /RU ""
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの更新に失敗しました。
    pause
    exit /b 1
)
exit /b 0

:Enable
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    rem No entry found
    echo %NAME%タスクが存在しません。
    pause
    exit /b 0
)
REM Enable Task Scheduler settings
schtasks /Change /TN %NAME% /Enable
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの有効化に失敗しました。
    pause
    exit /b 1
)
exit /b 0

:Disable
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクが存在しません。
    exit /b 0
)
REM Diable Task Scheduler settings
schtasks /Change /TN %NAME% /Disable
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの無効化に失敗しました。
    exit /b 1
)
exit /b 0

:Delete
REM Delete Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクが存在しません。
    exit /b 0
)
schtasks /Delete /TN %NAME%
if %ERRORLEVEL% equ 1 (
    echo %NAME%タスクの削除に失敗しました。
    pause
    exit /b 1
)
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo %NAME%タスクの削除に失敗しました。
    pause
    exit /b 1
)
exit /b 0
