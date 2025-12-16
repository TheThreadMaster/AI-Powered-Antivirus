@echo off
REM AI Shield - Windows Batch Script for File Deletion
REM This script deletes files with admin privileges if needed

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo [Error] No file path provided
    exit /b 1
)

set "FILE_PATH=%~1"
set "SUCCESS=0"

REM Check if file exists
if not exist "%FILE_PATH%" (
    echo [Info] File does not exist: %FILE_PATH%
    exit /b 0
)

echo [Delete] Attempting to delete: %FILE_PATH%

REM Method 1: Normal deletion
del /f /q "%FILE_PATH%" 2>nul
if not exist "%FILE_PATH%" (
    echo [Delete] Success: File deleted using DEL command
    exit /b 0
)

REM Method 2: Remove read-only attribute and delete
attrib -R "%FILE_PATH%" >nul 2>&1
del /f /q "%FILE_PATH%" 2>nul
if not exist "%FILE_PATH%" (
    echo [Delete] Success: File deleted after removing read-only attribute
    exit /b 0
)

REM Method 3: Take ownership and delete (requires admin)
takeown /f "%FILE_PATH%" >nul 2>&1
icacls "%FILE_PATH%" /grant Everyone:F >nul 2>&1
del /f /q "%FILE_PATH%" 2>nul
if not exist "%FILE_PATH%" (
    echo [Delete] Success: File deleted after taking ownership
    exit /b 0
)

REM Method 4: Use PowerShell for force deletion
powershell -Command "Remove-Item -Path '%FILE_PATH%' -Force -ErrorAction SilentlyContinue" >nul 2>&1
if not exist "%FILE_PATH%" (
    echo [Delete] Success: File deleted using PowerShell
    exit /b 0
)

echo [Delete] Failed: All deletion methods failed
exit /b 1

