# AI Shield - PowerShell Script for File Deletion
# This script deletes files with admin privileges if needed

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$ErrorActionPreference = "SilentlyContinue"

# Normalize the file path (handle spaces and special characters)
$FilePath = $FilePath.Trim('"').Trim("'")

if (-not (Test-Path -LiteralPath $FilePath)) {
    Write-Host "[Info] File does not exist: $FilePath"
    exit 0
}

Write-Host "[Delete] Attempting to delete: $FilePath"

# Method 1: Normal deletion (use -LiteralPath to handle spaces and special chars)
try {
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Host "[Delete] Success: File deleted using Remove-Item"
        exit 0
    }
} catch {
    Write-Host "[Delete] Method 1 failed: $_"
}

# Method 2: Remove read-only and delete
try {
    $file = Get-Item -LiteralPath $FilePath -Force
    $file.IsReadOnly = $false
    $file.Attributes = $file.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Host "[Delete] Success: File deleted after removing read-only"
        exit 0
    }
} catch {
    Write-Host "[Delete] Method 2 failed: $_"
}

# Method 3: Take ownership and delete (requires admin)
try {
    # Take ownership (quote path for spaces)
    $quotedPath = "`"$FilePath`""
    takeown /f $quotedPath 2>&1 | Out-Null
    
    # Grant full control
    icacls $quotedPath /grant Everyone:F 2>&1 | Out-Null
    
    # Delete
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Host "[Delete] Success: File deleted after taking ownership"
        exit 0
    }
} catch {
    Write-Host "[Delete] Method 3 failed: $_"
}

# Method 4: Use .NET File.Delete with force
try {
    [System.IO.File]::Delete($FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Host "[Delete] Success: File deleted using .NET File.Delete"
        exit 0
    }
} catch {
    Write-Host "[Delete] Method 4 failed: $_"
}

# Method 5: Use WMI to delete
try {
    # Escape single quotes in path for WMI filter
    $escapedPath = $FilePath -replace "'", "''"
    $file = Get-WmiObject -Class Win32_FileSpecification -Filter "Name='$escapedPath'" -ErrorAction SilentlyContinue
    if ($file) {
        $file.Delete()
    }
    Remove-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Host "[Delete] Success: File deleted using WMI"
        exit 0
    }
} catch {
    Write-Host "[Delete] Method 5 failed: $_"
}

Write-Host "[Delete] Failed: All deletion methods failed"
exit 1

