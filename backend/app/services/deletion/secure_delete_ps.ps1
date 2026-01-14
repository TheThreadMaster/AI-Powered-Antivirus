# secure_delete_ps.ps1
# AI Shield - Secure File Deletion using sdelete.exe (Sysinternals)
# This script securely overwrites files before deletion using multiple passes
# Requires: sdelete.exe from Sysinternals Suite (https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete)

param(
  [Parameter(Mandatory=$true)][string]$Path,
  [int]$Passes = 3,        # number of overwrite passes (sensible default)
  [switch]$Recurse,
  [switch]$NoConfirm       # Skip confirmation for programmatic use
)

# Confirm user intent (legal guard) - skip if NoConfirm is set
if (-not $NoConfirm) {
    $yn = Read-Host "Permanently overwrite and delete '$Path' ? Type YES to confirm"
    if ($yn -ne "YES") { 
        Write-Host "Cancelled"
        exit 1 
    }
}

# Check if sdelete.exe is available
$sdelete = "sdelete.exe"
$sdeletePath = Get-Command $sdelete -ErrorAction SilentlyContinue

if (-not $sdeletePath) {
    # Try common locations
    $commonPaths = @(
        "$env:ProgramFiles\Sysinternals\sdelete.exe",
        "$env:ProgramFiles(x86)\Sysinternals\sdelete.exe",
        "$env:SystemRoot\System32\sdelete.exe",
        ".\sdelete.exe"
    )
    
    $found = $false
    foreach ($commonPath in $commonPaths) {
        if (Test-Path $commonPath) {
            $sdelete = $commonPath
            $found = $true
            break
        }
    }
    
    if (-not $found) {
        Write-Host "Error: sdelete.exe not found. Please install Sysinternals Suite or place sdelete.exe in PATH."
        exit 1
    }
}

# Build sdelete args
if ($Recurse) { 
    $args = "-p $Passes -s -q -- `"$Path`"" 
} else { 
    $args = "-p $Passes -q -- `"$Path`"" 
}

# Run sdelete (requires admin for some targets)
Write-Host "Running secure deletion: $sdelete $args"
try {
    $process = Start-Process -FilePath $sdelete -ArgumentList $args -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Host "Secure deletion completed successfully."
        exit 0
    } else {
        Write-Host "Secure deletion failed with exit code: $($process.ExitCode)"
        exit $process.ExitCode
    }
} catch {
    Write-Host "Error running sdelete: $_"
    exit 1
}

