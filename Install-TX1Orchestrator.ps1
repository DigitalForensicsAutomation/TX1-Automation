<#
.SYNOPSIS
    Automated installer for the TX1 Orchestrator PowerShell module +
    Windows service (or scheduled task fallback).

.NOTES
    Run as Administrator.
#>

param(
    [string]$SourcePath = ".\TX1-Orchestrator",
    [string]$InstallRoot = "C:\ProgramData\TX1-Orchestrator",
    [string]$ServiceName = "TX1Orchestrator",
    [string]$TaskName = "TX1OrchestratorTask",
    [string]$NSSMPath = "C:\Tools\nssm.exe"   # auto-detect later
)

Write-Host "=== TX1 Orchestrator Installer ===" -ForegroundColor Cyan

# ---------------------------
# 1. Pre-flight checks
# ---------------------------

if (-not (Test-Path $SourcePath)) {
    Write-Host "Source folder not found: $SourcePath" -ForegroundColor Red
    exit 1
}

# Auto-detect NSSM if not specified
if (-not (Test-Path $NSSMPath)) {
    $nssm = (Get-Command nssm.exe -ErrorAction SilentlyContinue)
    if ($nssm) { $NSSMPath = $nssm.Source }
}

$UseNSSM = Test-Path $NSSMPath

Write-Host "NSSM detected: $UseNSSM ($NSSMPath)"

# ---------------------------
# 2. Create install directory
# ---------------------------
Write-Host "Creating install directory: $InstallRoot"
New-Item -Path $InstallRoot -ItemType Directory -Force | Out-Null

# ---------------------------
# 3. Copy files
# ---------------------------
Write-Host "Copying module + launcher files..."
Copy-Item "$SourcePath\*" $InstallRoot -Recurse -Force

# ---------------------------
# 4. Create log directory
# ---------------------------
$LogDir = Join-Path $InstallRoot "Logs"
New-Item $LogDir -ItemType Directory -Force | Out-Null

# ---------------------------
# 5. Secure permissions
# ---------------------------
Write-Host "Hardening permissions..."
$acl = Get-Acl $InstallRoot
$acl.SetAccessRuleProtection($true, $false)

# Remove inherited rules
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

# Add only SYSTEM + Administrators
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")

$acl.AddAccessRule($rule1)
$acl.AddAccessRule($rule2)

Set-Acl -Path $InstallRoot -AclObject $acl

# ---------------------------
# 6. Install Service (NSSM)
# ---------------------------
if ($UseNSSM) {
    Write-Host "Installing Windows service via NSSM..." -ForegroundColor Green

    $Exe = "powershell.exe"
    $Args = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallRoot\TX1Orchestrator.Launcher.ps1`""

    & $NSSMPath install $ServiceName $Exe $Args
    & $NSSMPath set $ServiceName Start SERVICE_AUTO_START
    & $NSSMPath set $ServiceName AppStdout "$LogDir\TX1-Service.out.log"
    & $NSSMPath set $ServiceName AppStderr "$LogDir\TX1-Service.err.log"

    Write-Host "Starting service..."
    Start-Service $ServiceName
}
else {
    # ---------------------------
    # Fallback: Scheduled Task
    # ---------------------------
    Write-Host "NSSM not found — using Scheduled Task fallback." -ForegroundColor Yellow

    $Action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallRoot\TX1Orchestrator.Launcher.ps1`""

    $Trigger = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -RunLevel Highest `
        -User "SYSTEM" `
        -Force

    Write-Host "Starting scheduled task..."
    Start-ScheduledTask -TaskName $TaskName
}

# ---------------------------
# 7. Final summary
# ---------------------------
Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Write-Host "Install directory: $InstallRoot"
Write-Host "Logs:             $LogDir"

if ($UseNSSM) {
    Write-Host "Service:          $ServiceName (running)"
} else {
    Write-Host "Scheduled Task:   $TaskName (running)"
}

Write-Host "======================================="
