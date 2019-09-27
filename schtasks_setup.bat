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
    echo %NAME% ���s�p�^�X�N�X�P�W���[�����쐬���܂��B
    echo �I�v�V�����F
    echo �@/Update�@�����^�X�N�X�P�W���[���̐ݒ�X�V
    echo �@/Delete�@�����^�X�N�X�P�W���[���̍폜
    echo �@/Enable�@�����^�X�N�X�P�W���[���̗L����
    echo �@/Disable �����^�X�N�X�P�W���[���̖�����
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
    echo %NAME%�^�X�N�̍쐬�Ɏ��s���܂����B
    pause
    exit /b 1
)
REM Check created Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�̍쐬�Ɏ��s���܂����B
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
    echo %NAME%�^�X�N�̍X�V�Ɏ��s���܂����B
    pause
    exit /b 1
)
exit /b 0

:Enable
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    rem No entry found
    echo %NAME%�^�X�N�����݂��܂���B
    pause
    exit /b 0
)
REM Enable Task Scheduler settings
schtasks /Change /TN %NAME% /Enable
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�̗L�����Ɏ��s���܂����B
    pause
    exit /b 1
)
exit /b 0

:Disable
REM Check for existing Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�����݂��܂���B
    exit /b 0
)
REM Diable Task Scheduler settings
schtasks /Change /TN %NAME% /Disable
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�̖������Ɏ��s���܂����B
    exit /b 1
)
exit /b 0

:Delete
REM Delete Task Scheduler settings
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�����݂��܂���B
    exit /b 0
)
schtasks /Delete /TN %NAME%
if %ERRORLEVEL% equ 1 (
    echo %NAME%�^�X�N�̍폜�Ɏ��s���܂����B
    pause
    exit /b 1
)
schtasks /Query /TN %NAME% >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo %NAME%�^�X�N�̍폜�Ɏ��s���܂����B
    pause
    exit /b 1
)
exit /b 0
