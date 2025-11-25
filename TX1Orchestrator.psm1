# FILE: TX1Orchestrator.psm1
<#
.SYNOPSIS
  TX1 Orchestrator PowerShell Module
.DESCRIPTION
  Packaged functions for orchestrating Tableau TX1 devices, logging, and installing as a Windows service.
  - Config-driven
  - Robust logging with log rotation
  - Session handling (cookies + optional CSRF)
  - Monitor loop to detect attached drives and start imaging jobs
  - Helpers to install/uninstall a Windows service wrapper (supports NSSM or native Task Scheduler fallback)

  IMPORTANT: You must adapt API endpoint paths to your TX1 firmware. This module deliberately accepts self-signed certs by default
  — replace that behaviour by pinning certificates in production.
#>

#region Module-level configuration
# Default configuration — can be overridden by calling Import-Module with -Configuration or by setting $Global:Tx1OrchConfig
if (-not (Test-Path -LiteralPath "$env:ProgramData\TX1Orchestrator")) { New-Item -Path "$env:ProgramData\TX1Orchestrator" -ItemType Directory -Force | Out-Null }
$Global:Tx1OrchConfig = [ordered]@{
    Tx1List = @(
        @{ Name='TX1-01'; Host='192.168.10.21' }
    )
    CredentialTarget = 'TX1-Orch-Creds'
    LocalStaging = 'C:\Forensic\Staging'
    EvidenceShare = '\\evidence.local\cases'
    LogFolder = "$env:ProgramData\TX1Orchestrator\logs"
    PollingIntervalSeconds = 10
    JobPollIntervalSeconds = 15
    MaxConcurrentJobs = 4
    AcceptSelfSignedCert = $true
    UseNssmIfAvailable = $true
}

if (-not (Test-Path -LiteralPath $Global:Tx1OrchConfig.LogFolder)) { New-Item -Path $Global:Tx1OrchConfig.LogFolder -ItemType Directory -Force | Out-Null }

#endregion

#region Logging
function Get-LogFilePath {
    param([string]$BaseName = 'tx1_orchestrator')
    $date = (Get-Date).ToString('yyyy-MM-dd')
    return Join-Path $Global:Tx1OrchConfig.LogFolder "$BaseName-$date.log"
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    $path = Get-LogFilePath
    $line | Out-File -FilePath $path -Append -Encoding UTF8
    if ($Level -eq 'ERROR') { Write-Error $Message } else { Write-Verbose $Message }
}

function Get-RecentLogs {
    param([int]$Days = 7)
    Get-ChildItem -Path $Global:Tx1OrchConfig.LogFolder -Filter "*.log" | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$Days) } | Sort-Object LastWriteTime -Descending
}

#endregion

#region Credential helpers
function Get-OrchCredential {
    <#
    Attempts to get credential from Windows Credential Manager (CredentialManager module). If not found, prompts.
    #>
    try {
        if (Get-Module -ListAvailable -Name CredentialManager) { Import-Module CredentialManager -ErrorAction Stop }
        $credObj = Get-StoredCredential -Target $Global:Tx1OrchConfig.CredentialTarget -ErrorAction SilentlyContinue
        if ($credObj) {
            return New-Object System.Management.Automation.PSCredential($credObj.UserName, (ConvertTo-SecureString $credObj.Password -AsPlainText -Force))
        }
    } catch {
        Write-Log "CredentialManager module not available or retrieval failed: $_" 'WARN'
    }
    Write-Log "Prompting for orchestration credential" 'WARN'
    return Get-Credential -Message 'Enter orchestration account for TX1 devices'
}

#endregion

#region HTTP / Session helpers
function New-Tx1Session {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Host,
        [Parameter(Mandatory=$true)][pscredential]$Credential
    )
    $base = "https://$Host"
    # Configure handler
    $handler = New-Object System.Net.Http.HttpClientHandler
    if ($Global:Tx1OrchConfig.AcceptSelfSignedCert) { $handler.ServerCertificateCustomValidationCallback = { $true } }
    $handler.AllowAutoRedirect = $true
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    $session = [ordered]@{
        Host = $Host
        Base = $base
        Http = $client
        CsrfToken = $null
    }

    try {
        $loginUrl = "$base/api/login"
        $payload = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
        $content = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, 'application/json')
        $resp = $client.PostAsync($loginUrl, $content).Result
        if (-not $resp.IsSuccessStatusCode) {
            Write-Log "Login to $Host failed: $($resp.StatusCode)" 'ERROR'
            return $null
        }
        $body = $resp.Content.ReadAsStringAsync().Result
        try { $json = $body | ConvertFrom-Json } catch { $json = $null }
        if ($json -and $json.csrfToken) { $session.CsrfToken = $json.csrfToken }
        Write-Log "Authenticated to $Host" 'INFO'
        return $session
    } catch {
        Write-Log "Exception during login to $Host: $_" 'ERROR'
        return $null
    }
}

function Invoke-Tx1Get {
    param(
        $Session,
        [Parameter(Mandatory=$true)][string]$Path
    )
    $url = "$($Session.Base)$Path"
    $resp = $Session.Http.GetAsync($url).Result
    $body = $resp.Content.ReadAsStringAsync().Result
    if ($resp.IsSuccessStatusCode) {
        try { return $body | ConvertFrom-Json } catch { return $body }
    } else {
        throw "GET $url failed: $($resp.StatusCode) - $body"
    }
}

function Invoke-Tx1Post {
    param(
        $Session,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][object]$Payload
    )
    $url = "$($Session.Base)$Path"
    $json = $Payload | ConvertTo-Json -Depth 10
    $content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
    if ($Session.CsrfToken) { $content.Headers.Add('X-CSRF-Token', $Session.CsrfToken) }
    $resp = $Session.Http.PostAsync($url, $content).Result
    $body = $resp.Content.ReadAsStringAsync().Result
    if ($resp.IsSuccessStatusCode) {
        try { return $body | ConvertFrom-Json } catch { return $body }
    } else {
        throw "POST $url failed: $($resp.StatusCode) - $body"
    }
}

#endregion

#region Imaging helpers
function Get-Tx1ConnectedDrives {
    [CmdletBinding()]
    param(
        $Session
    )
    try {
        $json = Invoke-Tx1Get -Session $Session -Path '/api/devices'
        return $json.devices
    } catch {
        Write-Log "Failed Get-Tx1ConnectedDrives for $($Session.Host): $_" 'ERROR'
        return @()
    }
}

function Start-Tx1ImagingJob {
    [CmdletBinding()]
    param(
        $Session,
        [Parameter(Mandatory=$true)][string]$DriveId,
        [Parameter(Mandatory=$true)][hashtable]$JobTemplate
    )
    try {
        $payload = @{ driveId = $DriveId; job = $JobTemplate }
        $resp = Invoke-Tx1Post -Session $Session -Path '/api/jobs/start' -Payload $payload
        Write-Log "Started imaging job for drive $DriveId on $($Session.Host) - job: $($resp.jobId)" 'INFO'
        return $resp
    } catch {
        Write-Log "Failed to start imaging job on $($Session.Host): $_" 'ERROR'
        return $null
    }
}

function Wait-Tx1JobCompletion {
    [CmdletBinding()]
    param(
        $Session,
        [Parameter(Mandatory=$true)][string]$JobId
    )
    while ($true) {
        Start-Sleep -Seconds $Global:Tx1OrchConfig.JobPollIntervalSeconds
        try {
            $status = Invoke-Tx1Get -Session $Session -Path "/api/jobs/$JobId"
            $state = $status.state
            Write-Log "Job $JobId on $($Session.Host) state: $state" 'INFO'
            if ($state -in @('COMPLETED','FAILED','CANCELED')) { return $status }
        } catch {
            Write-Log "Error polling job $JobId: $_" 'ERROR'
        }
    }
}

function Fetch-JobArtifacts {
    [CmdletBinding()]
    param(
        $Session,
        $JobStatus
    )
    $jobId = $JobStatus.jobId
    $dest = Join-Path $Global:Tx1OrchConfig.LocalStaging $jobId
    New-Item -Path $dest -ItemType Directory -Force | Out-Null
    if ($JobStatus.reportUrl) {
        $bin = $Session.Http.GetByteArrayAsync($JobStatus.reportUrl).Result
        [IO.File]::WriteAllBytes((Join-Path $dest 'job_report.json'), $bin)
        Write-Log "Downloaded report for $jobId" 'INFO'
    }
    if ($JobStatus.fileList) {
        foreach ($f in $JobStatus.fileList) {
            $url = $f.url
            $name = $f.name
            $local = Join-Path $dest $name
            $bin = $Session.Http.GetByteArrayAsync($url).Result
            [IO.File]::WriteAllBytes($local, $bin)
            Write-Log "Downloaded $name for job $jobId" 'INFO'
        }
    }
    return $dest
}

#endregion

#region Transfer & verification
function Transfer-ToSMB {
    param(
        [Parameter(Mandatory=$true)][string]$LocalFolder,
        [Parameter(Mandatory=$true)][string]$CaseId
    )
    $dest = Join-Path $Global:Tx1OrchConfig.EvidenceShare $CaseId
    New-Item -Path $dest -ItemType Directory -Force | Out-Null
    $robocopyArgs = @($LocalFolder, $dest, '/E', '/COPYALL', '/R:3', '/W:5')
    $rc = & robocopy @robocopyArgs
    $code = $LASTEXITCODE
    if ($code -ge 8) { Write-Log "Robocopy failed with code $code" 'ERROR'; throw "robocopy failed $code" }
    Write-Log "Transferred $LocalFolder -> $dest" 'INFO'
    return $dest
}

function Verify-Hashes {
    param(
        [Parameter(Mandatory=$true)][string]$LocalFolder,
        [Parameter(Mandatory=$true)][hashtable]$ReportedHashes
    )
    $mismatches = @()
    foreach ($file in Get-ChildItem -Path $LocalFolder -File -Recurse) {
        $fname = $file.Name
        if ($ReportedHashes.ContainsKey($fname)) {
            $rep = $ReportedHashes[$fname]
            $md5 = (Get-FileHash -Path $file.FullName -Algorithm MD5).Hash.ToLower()
            $sha = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
            if ($rep.md5 -and ($md5 -ne $rep.md5.ToLower())) { $mismatches += "MD5 mismatch: $fname" }
            if ($rep.sha256 -and ($sha -ne $rep.sha256.ToLower())) { $mismatches += "SHA256 mismatch: $fname" }
        } else {
            $mismatches += "No reported hash for $fname"
        }
    }
    return $mismatches
}

#endregion

#region Orchestrator main
function Start-Tx1Orchestrator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][hashtable]$Config
    )
    if ($Config) { foreach ($k in $Config.Keys) { $Global:Tx1OrchConfig[$k] = $Config[$k] } }

    $credential = Get-OrchCredential
    $semaphore = [System.Threading.Semaphore]::new($Global:Tx1OrchConfig.MaxConcurrentJobs, $Global:Tx1OrchConfig.MaxConcurrentJobs)

    Write-Log "Starting TX1 orchestrator main loop" 'INFO'

    while ($true) {
        foreach ($t in $Global:Tx1OrchConfig.Tx1List) {
            try {
                $session = New-Tx1Session -Host $t.Host -Credential $credential
                if (-not $session) { continue }
                $drives = Get-Tx1ConnectedDrives -Session $session
                foreach ($d in $drives) {
                    if ($d.state -eq 'ATTACHED' -and -not $d.imaged) {
                        Write-Log "Detected drive $($d.id) on $($t.Name)" 'INFO'
                        # Wait for semaphore
                        $semaphore.WaitOne() | Out-Null
                        Start-Job -ScriptBlock {
                            param($session,$drive,$config)
                            Import-Module -Name TX1Orchestrator -Force
                            try {
                                $template = @{ imagingMode='forensic'; targetType='E01'; hashing=@('MD5','SHA256'); compression=$true; metadata=@{ operator=$env:USERNAME; caseId='AUTO' } }
                                $job = Start-Tx1ImagingJob -Session $session -DriveId $drive.id -JobTemplate $template
                                if ($job) {
                                    $status = Wait-Tx1JobCompletion -Session $session -JobId $job.jobId
                                    if ($status.state -eq 'COMPLETED') {
                                        $folder = Fetch-JobArtifacts -Session $session -JobStatus $status
                                        $caseId = if ($status.metadata -and $status.metadata.caseId) { $status.metadata.caseId } else { 'UNKNOWN' }
                                        $dest = Transfer-ToSMB -LocalFolder $folder -CaseId $caseId
                                        # build reported hashes map
                                        $reported = @{}
                                        if ($status.report -and $status.report.hashes) {
                                            foreach ($h in $status.report.hashes) { $reported[$h.filename] = @{ md5=$h.md5; sha256=$h.sha256 } }
                                        }
                                        $mismatch = Verify-Hashes -LocalFolder $dest -ReportedHashes $reported
                                        if ($mismatch.Count -gt 0) { Write-Log "Hash mismatches: $($mismatch -join '; ')" 'ERROR' }
                                        else { Write-Log "Job $($job.jobId) verified and archived" 'INFO' }
                                    } else { Write-Log "Job ended: $($status.state)" 'WARN' }
                                }
                            } catch {
                                Write-Log "Worker job exception: $_" 'ERROR'
                            } finally { [System.Threading.Semaphore]::Release($config.MaxConcurrentJobs) | Out-Null }
                        } -ArgumentList ($session,$d,$Global:Tx1OrchConfig) | Out-Null
                    }
                }
            } catch {
                Write-Log "Main loop exception for $($t.Name): $_" 'ERROR'
            }
        }
        Start-Sleep -Seconds $Global:Tx1OrchConfig.PollingIntervalSeconds
    }
}

function Stop-Tx1Orchestrator {
    Write-Log "Stop-Tx1Orchestrator called — graceful stop not yet implemented" 'WARN'
    # For a production service, implement a signal file or service stop event.
}

#endregion

#region Service install / uninstall helpers
function Install-Tx1Service {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][string]$LauncherScript, # full path to a launcher .ps1 that imports module and invokes Start-Tx1Orchestrator
        [string]$DisplayName = 'TX1 Orchestrator Service',
        [string]$Description = 'Orchestrates Tableau TX1 devices and transfers evidence to network storage.'
    )
    if ($Global:Tx1OrchConfig.UseNssmIfAvailable -and (Get-Command nssm -ErrorAction SilentlyContinue)) {
        Write-Log "Installing service $ServiceName using NSSM" 'INFO'
        & nssm install $ServiceName 'powershell.exe' "-NoProfile -ExecutionPolicy Bypass -File `"$LauncherScript`""
        & nssm set $ServiceName DisplayName $DisplayName
        & nssm set $ServiceName Description $Description
        & nssm set $ServiceName Start SERVICE_AUTO_START
        Write-Log "Service $ServiceName installed via NSSM" 'INFO'
        return
    }
    # Fallback: create a scheduled task that runs at startup
    Write-Log "NSSM not available — creating scheduled task as a fallback" 'WARN'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LauncherScript`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Principal $principal -Description $Description -Force
    Write-Log "Scheduled task $ServiceName installed" 'INFO'
}

function Uninstall-Tx1Service {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ServiceName)
    if (Get-Command nssm -ErrorAction SilentlyContinue) {
        & nssm remove $ServiceName confirm
        Write-Log "Removed NSSM service $ServiceName" 'INFO'
        return
    }
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
        Write-Log "Removed scheduled task $ServiceName" 'INFO'
    }
}

#endregion

Export-ModuleMember -Function * -Variable *

# EOF: TX1Orchestrator.psm1


# FILE: TX1Orchestrator.Launcher.ps1
<#
Launcher script which can be used by NSSM or Scheduled Task.
Place next to module and adjust $ModulePath.
#>
$ModulePath = 'C:\ProgramFiles\TX1Orchestrator\TX1Orchestrator.psm1'  # <-- install path
Import-Module $ModulePath -Force
# Optional: set -Verbose to get verbose output in logs
Start-Tx1Orchestrator


# FILE: README.md
# TX1 Orchestrator PowerShell Module

This package includes:
- TX1Orchestrator.psm1 — main module
- TX1Orchestrator.Launcher.ps1 — launcher script for service wrapper

Quick install steps:
1. Copy `TX1Orchestrator.psm1` to `C:\ProgramFiles\TX1Orchestrator\` (create folder).
2. Copy `TX1Orchestrator.Launcher.ps1` alongside the module.
3. Edit the config at the top of the .psm1 or provide a hashtable to `Start-Tx1Orchestrator -Config`.
4. (Optional) Install Credential into Windows Credential Manager with target name set in config.

Installing the service (preferred: NSSM)
- Download NSSM (https://nssm.cc/) and place `nssm.exe` on the PATH.
- Run (as Administrator):
  `Import-Module 'C:\ProgramFiles\TX1Orchestrator\TX1Orchestrator.psm1' ; Install-Tx1Service -ServiceName 'TX1OrchSvc' -LauncherScript 'C:\ProgramFiles\TX1Orchestrator\TX1Orchestrator.Launcher.ps1'`

Fallback (no NSSM)
- The module will install a Scheduled Task running as SYSTEM at startup using the launcher.

Security notes
- Replace the ServerCertificateCustomValidationCallback acceptance in production.
- Use a secrets vault instead of Windows Credential Manager where possible.

Testing
- Run `Import-Module .\TX1Orchestrator.psm1` then `Start-Tx1Orchestrator -Config @{ Tx1List = @(...); LocalStaging='C:\temp' }` to test.


# EOF: README.md
