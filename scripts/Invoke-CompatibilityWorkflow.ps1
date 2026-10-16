#Requires -Version 5.1
<#
.SYNOPSIS
Read-only inspection/verification, or explicitly authorized installation of one pinned build.
.DESCRIPTION
Inspect and Verify do not execute Xiaomi code or change system configuration. They write
local JSON reports only. Install invokes the separately prepared installer with /S and
Windows elevation; the user handles UAC. No security settings or hardware IDs are changed.
This helper is the known 5.8.1.130 x64 fast path. Other builds and native architectures
continue through the Skill's adaptive analysis workflow, not this fixed installer.
Use a fresh, local, non-linked work directory for each installation attempt.
.EXAMPLE
.\Invoke-CompatibilityWorkflow.ps1 -WorkDirectory D:\XiaomiCompatibility\run-1 -SourceInstaller D:\Downloads\XiaomiPCManager_5.8.1.130.exe
.EXAMPLE
.\Invoke-CompatibilityWorkflow.ps1 -Action Install -WorkDirectory D:\XiaomiCompatibility\run-1 -PreparedInstaller D:\XiaomiCompatibility\prepared.exe -InstallationAuthorized
.EXAMPLE
.\Invoke-CompatibilityWorkflow.ps1 -Action Verify -WorkDirectory D:\XiaomiCompatibility\run-1
#>
[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Install', 'Verify')][string]$Action = 'Inspect',
    [string]$WorkDirectory,
    [string]$SourceInstaller,
    [string]$PreparedInstaller,
    [switch]$InstallationAuthorized,
    [string]$InstalledDirectory
)

$ErrorActionPreference = 'Stop'
$script:CompatPreparedHash = 'a7d35102dc1abdb5e8a5e45ba43c6a6b22f5b30cd9c456799a5bfea65f210e34'
$script:CompatPreparedSize = 766644624L
$script:CompatSourceHash = 'd812cf30805d172474eb33b2f97f37129593f9d50f09d4224f73d530a2cb40e9'
$script:CompatMinimumFreeBytes = 8GB
$script:CompatCoreHashes = [ordered]@{
    'XiaomiPcManager.exe' = 'f2b6c1cd42a1c4d52e8bd616b599eb7e4a2a45da53c911ede7372967b37dce0e'
    'XiaomiPcManager.dll' = '1b8a9c0d2a836ad6633527f03b38df416233b97703dd61dd82b28d1f0f76d312'
    'PcControlCenter.dll' = '07cf478b75ad5045a61e27da47dbdefb11e45aec2b67bd6d33458772b84adbcd'
    'MiSmartShareDLL.dll' = '0f6ad49f96c984809d232c388c88d1b1725fb77050af27cf7c6ae6c7acec98f6'
    'MiSmartShareClrWrapper.dll' = '72547031e06dda6ef015a4b0ebf1bc027985463676a5be7e886f94ff1fcb0eea'
}

function Assert-CompatLocalPath {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$MustExist)
    # Reject UNC/device paths, alternate streams, drive-relative paths and every existing
    # reparse-point ancestor. This also prevents ordinary junction/symlink redirection.
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')) {
        throw 'Use an absolute local drive path, without an alternate data stream.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Linked or redirected paths are not supported; choose a normal local directory.'
        }
        $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\', '/'))
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw 'A required local path does not exist.' }
    return $full
}

function Write-CompatJsonNew {
    param([string]$Path, $Value)
    $full = Assert-CompatLocalPath -Path $Path
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12))
    $stream = [IO.File]::Open($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    return $full
}

function New-CompatReportPath {
    param([string]$Directory, [string]$Kind)
    return Join-Path $Directory ('{0}-{1}-{2}.json' -f $Kind, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), [Guid]::NewGuid().ToString('N'))
}

function Get-CompatContextBinding {
    param([string]$Salt)
    # Persist only a salted digest in the local work directory, never the source identifiers.
    $machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $bytes = [Text.Encoding]::UTF8.GetBytes($Salt + '|' + $machine + '|' + $sid)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Get-CompatDiskSpace {
    param([string]$Directory)
    $result = @()
    foreach ($entry in @(@{purpose = 'system'; path = $env:SystemRoot}, @{purpose = 'workspace'; path = $Directory})) {
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($entry.path))
        $result += [pscustomobject]@{ purpose = $entry.purpose; available_bytes = $drive.AvailableFreeSpace; minimum_bytes = $script:CompatMinimumFreeBytes; meets_workflow_minimum = ($drive.AvailableFreeSpace -ge $script:CompatMinimumFreeBytes) }
    }
    return $result
}

function Assert-CompatNativeX64Host {
    # Query native processor architecture, not the PowerShell process: an x64 process
    # on ARM64 does not establish compatibility with the pinned installer's drivers.
    try { $processors = @(Get-CimInstance -ClassName Win32_Processor -Property Architecture -ErrorAction Stop) }
    catch { throw 'Native processor architecture could not be verified. Continue with the adaptive workflow in references/workflow.md; do not use the fixed x64 installation path.' }
    if ($processors.Count -eq 0 -or @($processors | Where-Object { $null -eq $_.Architecture -or $_.Architecture -ne 9 }).Count -gt 0) {
        throw 'The fixed 5.8.1.130 x64 installation path requires a verified native AMD64 host. Continue with the adaptive workflow in references/workflow.md for this host and package; ARM64 and other candidates are not rejected by the Skill.'
    }
}

function Get-CompatSnapshot {
    param([string]$Directory)
    $issues = [Collections.Generic.List[string]]::new()
    $os = $null
    $services = @(); $systemDrivers = @(); $driverPackages = @(); $tasks = @(); $versions = @(); $processes = @()
    try {
        $v = Get-CimInstance Win32_OperatingSystem
        $os = [pscustomobject]@{ version = $v.Version; build = $v.BuildNumber; architecture = $v.OSArchitecture }
    } catch { $issues.Add('os_inventory_unavailable') }
    try {
        $services = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -in @('MiService', 'MiDeviceService', 'MiServiceDaemon') } | ForEach-Object {
            [pscustomobject]@{ name = $_.Name; state = $_.State; start_mode = $_.StartMode }
        })
        $systemDrivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -in @('MiServiceDaemon', 'xiaomisysmon', 'XiaomiEcIo') } | ForEach-Object {
            [pscustomobject]@{ name = $_.Name; state = $_.State; start_mode = $_.StartMode }
        })
    } catch { $issues.Add('service_inventory_incomplete') }
    try {
        $driverPackages = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object {
            $_.DriverProviderName -match '(?i)xiaomi|timi' -or $_.DeviceName -match '(?i)xiaomi|virtualcontrolhid|mi(audio|play)'
        } | ForEach-Object {
            $category = 'other-xiaomi-device'
            if ($_.DeviceName -match '(?i)controlhid|virtualhid') { $category = 'virtual-hid' }
            elseif ($_.DeviceName -match '(?i)audio') { $category = 'virtual-audio' }
            elseif ($_.DeviceName -match '(?i)camera') { $category = 'virtual-camera' }
            elseif ($_.DeviceName -match '(?i)display') { $category = 'virtual-display' }
            elseif ($_.DeviceName -match '(?i)bus') { $category = 'virtual-bus' }
            elseif ($_.DeviceName -match '(?i)ecio') { $category = 'oem-ec' }
            [pscustomobject]@{ category = $category; version = $_.DriverVersion; inf = [IO.Path]::GetFileName($_.InfName); is_signed = $_.IsSigned }
        })
    } catch { $issues.Add('pnp_driver_inventory_unavailable') }
    try {
        $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -match '(?i)xiaomi|miservice|midevice' } | ForEach-Object {
            $name = 'other-xiaomi-task'
            if ($_.TaskName -eq 'XiaomiPCHostTask') { $name = 'XiaomiPCHostTask' }
            [pscustomobject]@{ category = $name; state = [string]$_.State; enabled = [bool]$_.Settings.Enabled }
        })
    } catch { $issues.Add('scheduled_task_inventory_unavailable') }
    try {
        $processes = @(Get-Process | Where-Object { $_.ProcessName -in @('XiaomiPcManager', 'MiService', 'MiDeviceService', 'MiScreenShare') } | Select-Object -ExpandProperty ProcessName -Unique)
    } catch { $issues.Add('process_inventory_unavailable') }
    foreach ($component in @(
        @{ name = 'XiaomiPCManager'; path = (Join-Path $env:ProgramFiles 'MI\XiaomiPCManager') },
        @{ name = 'MiService'; path = (Join-Path ${env:ProgramFiles(x86)} 'Timi Personal Computing\MiService') }
    )) {
        if (Test-Path -LiteralPath $component.path) {
            try {
                $safe = Assert-CompatLocalPath -Path $component.path -MustExist
                foreach ($folder in @(Get-ChildItem -LiteralPath $safe -Directory | Where-Object { $_.Name -match '^\d+(\.\d+){2,3}$' })) {
                    $versions += [pscustomobject]@{ component = $component.name; version = $folder.Name; detection = 'version_directory_present' }
                }
            } catch { $issues.Add('version_directory_inventory_incomplete') }
        }
    }
    return [ordered]@{
        schema = 'xiaomi-compat-snapshot-v1'; created_utc = [DateTime]::UtcNow.ToString('o')
        os = $os; installed_versions = $versions; services = $services; system_drivers = $systemDrivers
        associated_pnp_drivers = $driverPackages; scheduled_tasks = $tasks; known_running_processes = $processes
        disk = @(Get-CompatDiskSpace -Directory $Directory); issues = @($issues)
        coverage = 'Read-only selected inventory. Version folders are not proof of a complete install. PnP entries do not enumerate all driver-store packages. No usernames, account data, serials, device instance IDs, task arguments or application logs are collected.'
    }
}

function Read-CompatBaseline {
    param([string]$Directory)
    $statePath = Assert-CompatLocalPath -Path (Join-Path $Directory 'baseline.local.json') -MustExist
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.schema -ne 'xiaomi-compat-local-v1' -or $state.context_binding -ne (Get-CompatContextBinding -Salt $state.salt)) {
        throw 'Baseline does not belong to this Windows installation and user; Inspect in a fresh work directory.'
    }
    $created = [DateTimeOffset]::Parse($state.created_utc)
    $age = [DateTimeOffset]::UtcNow - $created
    if ($age.TotalHours -gt 24 -or $age.TotalMinutes -lt -5) { throw 'Baseline expired or has an invalid timestamp; Inspect in a fresh work directory.' }
    if ($state.baseline_file -notmatch '^baseline-[0-9TZ]+-[a-f0-9]{32}\.json$') { throw 'Invalid baseline filename.' }
    $baselinePath = Assert-CompatLocalPath -Path (Join-Path $Directory $state.baseline_file) -MustExist
    if ((Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $state.baseline_sha256) { throw 'Baseline content changed; Inspect in a fresh work directory.' }
    return Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
}

function Get-CompatPreparedInstaller {
    param([string]$Path)
    if (-not $Path) { throw 'Install requires -PreparedInstaller.' }
    $full = Assert-CompatLocalPath -Path $Path -MustExist
    if ([IO.Path]::GetExtension($full) -ne '.exe') { throw 'Prepared installer must have an .exe extension.' }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $script:CompatPreparedSize) { throw 'Prepared installer size mismatch.' }
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actual = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        if ($actual -ne $script:CompatPreparedHash) { throw 'Prepared installer SHA-256 mismatch.' }
        $signature = [string](Get-AuthenticodeSignature -LiteralPath $full).Status
        # The pinned hash identifies the experimental copy. Its original signature is invalid.
        # Certificate/offline policy can produce a different status, so report rather than
        # treating a platform status string as a replacement for the exact SHA-256 check.
        return [pscustomobject]@{ path = $full; stream = $stream; signature_status = $signature }
    } catch { $stream.Dispose(); throw }
}

function Get-CompatOriginalInstallerEvidence {
    param([string]$Path)
    if (-not $Path) { return [pscustomobject]@{ provided = $false; validated = $false } }
    $full = Assert-CompatLocalPath -Path $Path -MustExist
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $script:CompatPreparedSize) { throw 'Original installer size mismatch.' }
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actual = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        if ($actual -ne $script:CompatSourceHash) { throw 'Original installer SHA-256 mismatch for the fixed 5.8.1.130 path; continue with the adaptive workflow in references/workflow.md.' }
        $signature = [string](Get-AuthenticodeSignature -LiteralPath $full).Status
        if ($signature -ne 'Valid') { throw 'Original installer Authenticode signature is not Valid. Resolve signature verification before preparing an installation.' }
        return [pscustomobject]@{ provided = $true; validated = $true; sha256 = $actual; bytes = $stream.Length; signature_status = $signature; checked_utc = [DateTime]::UtcNow.ToString('o') }
    } finally { $stream.Dispose() }
}

function Invoke-CompatInspect {
    param([string]$Directory, [string]$Source)
    $statePath = Join-Path $Directory 'baseline.local.json'
    if (Test-Path -LiteralPath $statePath) { throw 'This work directory already has a baseline. Use a fresh directory; existing reports are never overwritten.' }
    $original = Get-CompatOriginalInstallerEvidence -Path $Source
    $snapshot = Get-CompatSnapshot -Directory $Directory
    $snapshot.original_installer = $original
    $baseline = Write-CompatJsonNew -Path (New-CompatReportPath -Directory $Directory -Kind 'baseline') -Value $snapshot
    $salt = [Guid]::NewGuid().ToString('N')
    $state = [ordered]@{
        schema = 'xiaomi-compat-local-v1'; created_utc = [DateTime]::UtcNow.ToString('o'); salt = $salt
        context_binding = Get-CompatContextBinding -Salt $salt
        baseline_file = [IO.Path]::GetFileName($baseline)
        baseline_sha256 = (Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash.ToLowerInvariant()
        privacy = 'Local context binding only. Keep this file and all generated reports out of GitHub.'
    }
    $null = Write-CompatJsonNew -Path $statePath -Value $state
    return [pscustomobject]@{ action = 'Inspect'; report = $baseline; issues = $snapshot.issues; system_changed = $false; note = 'Inventory is not a backup or a full rollback mechanism. The 8 GiB free-space check is a conservative workflow threshold, not a vendor requirement.' }
}

function Invoke-CompatInstall {
    param([string]$Directory, [string]$Installer, [bool]$Authorized)
    if (-not $Authorized) { throw 'Install requires explicit current-user authorization and -InstallationAuthorized. A skill invocation alone is not authorization to install services and drivers.' }
    $baseline = Read-CompatBaseline -Directory $Directory
    if (-not $baseline.original_installer.validated -or $baseline.original_installer.sha256 -ne $script:CompatSourceHash -or $baseline.original_installer.signature_status -ne 'Valid' -or $baseline.original_installer.bytes -ne $script:CompatPreparedSize) {
        throw 'Install requires a fresh Inspect baseline with -SourceInstaller that passed the pinned hash, size and official Authenticode validation.'
    }
    Assert-CompatNativeX64Host
    if ($baseline.issues -contains 'os_inventory_unavailable') { throw 'Operating-system inventory is unavailable; resolve that issue before installation.' }
    if ($baseline.issues.Count -gt 0) { Write-Warning ('Some optional baseline inventories are incomplete: ' + ($baseline.issues -join ', ') + '. Missing inventory must not be treated as absence of components.') }
    if (@(Get-CompatDiskSpace -Directory $Directory | Where-Object { -not $_.meets_workflow_minimum }).Count -gt 0) { throw 'At least 8 GiB free space is required on the system and workspace drives by this workflow.' }
    $held = Get-CompatPreparedInstaller -Path $Installer
    try {
        $installerName = [IO.Path]::GetFileNameWithoutExtension($held.path)
        if (Get-Process -Name $installerName, 'XiaomiPCManager_5.8.1.130*' -ErrorAction SilentlyContinue) { throw 'Another matching installer process is running. Close it normally before continuing.' }
        $run = [ordered]@{
            schema = 'xiaomi-compat-install-v1'; requested_utc = [DateTime]::UtcNow.ToString('o')
            authorization_asserted_by_caller = $true; installer_sha256 = $script:CompatPreparedHash
            signature_status = $held.signature_status; signature_expected = 'HashMismatch; the modified file does not retain a valid official signature'
            arguments = @('/S'); status = 'launch_requested'
            scope = 'Official installer payload including MiService and virtual drivers; no custom installation directory is supported by this workflow. Main-program uninstall is not a verified full rollback.'
        }
        # An exclusive marker deliberately prevents an unattended repeat after interruption.
        $null = Write-CompatJsonNew -Path (Join-Path $Directory 'install-attempt.local.json') -Value $run
        Write-Warning 'The prepared EXE is modified; its official signature is invalid (normally HashMismatch). Windows UAC must be handled by you. This installs services and virtual drivers; uninstall is not a complete rollback.'
        try {
            $process = Start-Process -FilePath $held.path -ArgumentList '/S' -WorkingDirectory ([IO.Path]::GetDirectoryName($held.path)) -Verb RunAs -WindowStyle Hidden -PassThru
            $run.status = 'running'; $run.started_utc = [DateTime]::UtcNow.ToString('o'); $run.process_id = $process.Id
            $null = Write-CompatJsonNew -Path (New-CompatReportPath -Directory $Directory -Kind 'install-started') -Value $run
            $process.WaitForExit()
            $process.Refresh()
            $run.status = 'process_exited'; $run.exit_code = $process.ExitCode
        } catch {
            $run.status = 'launch_or_wait_failed'; $run.error_type = $_.Exception.GetType().FullName
            $run.completed_utc = [DateTime]::UtcNow.ToString('o')
            $null = Write-CompatJsonNew -Path (New-CompatReportPath -Directory $Directory -Kind 'install-failed') -Value $run
            throw
        }
        $run.completed_utc = [DateTime]::UtcNow.ToString('o')
        $report = Write-CompatJsonNew -Path (New-CompatReportPath -Directory $Directory -Kind 'install-finished') -Value $run
        if ($run.exit_code -ne 0) { throw ('Installer returned exit code {0}; review the local report. Do not retry automatically.' -f $run.exit_code) }
        return [pscustomobject]@{ action = 'Install'; report = $report; exit_code = $run.exit_code; note = 'Exit code zero is not functional verification. Continue with Verify and user-operated acceptance tests.' }
    } finally { $held.stream.Dispose() }
}

function Invoke-CompatVerify {
    param([string]$Directory, [string]$ProgramDirectory)
    if (-not $ProgramDirectory) { $ProgramDirectory = Join-Path $env:ProgramFiles 'MI\XiaomiPCManager\5.8.1.130' }
    $ProgramDirectory = Assert-CompatLocalPath -Path $ProgramDirectory
    $files = @()
    foreach ($name in $script:CompatCoreHashes.Keys) {
        $path = Join-Path $ProgramDirectory $name
        $row = [ordered]@{ file = $name; present = (Test-Path -LiteralPath $path -PathType Leaf); expected_sha256 = $script:CompatCoreHashes[$name]; sha256 = $null; matches_official_sample = $false; signature_status = $null }
        if ($row.present) {
            $path = Assert-CompatLocalPath -Path $path -MustExist
            $row.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $row.matches_official_sample = ($row.sha256 -eq $row.expected_sha256)
            $row.signature_status = [string](Get-AuthenticodeSignature -LiteralPath $path).Status
        }
        $files += [pscustomobject]$row
    }
    $reportValue = [ordered]@{
        schema = 'xiaomi-compat-verification-v1'; created_utc = [DateTime]::UtcNow.ToString('o')
        target_version = '5.8.1.130'; core_files = $files; snapshot = Get-CompatSnapshot -Directory $Directory
        all_core_hashes_match = (@($files | Where-Object { -not $_.matches_official_sample }).Count -eq 0)
        all_core_signatures_valid = (@($files | Where-Object { $_.signature_status -ne 'Valid' }).Count -eq 0)
        manual_checks = @('User signs into their own Xiaomi account through the official UI.', 'User confirms their own phone, visible casting and mouse control.', 'Use a non-sensitive test file in each direction.', 'Use non-sensitive text for clipboard synchronization in each direction.')
        limitations = @('No application is launched by Verify.', 'A running service or matching file hash is not proof of functional success.', 'MiDeviceService can remain StartPending for about 17 minutes on some unsupported PCs; do not edit or restart it automatically.', 'Tablet/TV/OEM-specific functions, clean-machine compatibility, future updates and long-term account refresh are not established by this check.')
    }
    $report = Write-CompatJsonNew -Path (New-CompatReportPath -Directory $Directory -Kind 'verification') -Value $reportValue
    return [pscustomobject]@{ action = 'Verify'; report = $report; all_core_hashes_match = $reportValue.all_core_hashes_match; all_core_signatures_valid = $reportValue.all_core_signatures_valid; issues = $reportValue.snapshot.issues; system_changed = $false }
}

function Invoke-CompatibilityMain {
    param([string]$RequestedAction, [string]$Directory, [string]$Source, [string]$Installer, [bool]$Authorized, [string]$ProgramDirectory)
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'This workflow requires 64-bit Windows.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Run 64-bit Windows PowerShell or PowerShell, not a 32-bit host.' }
    if (-not $Directory) { throw 'Specify -WorkDirectory using a fresh local directory.' }
    $directoryFull = Assert-CompatLocalPath -Path $Directory
    if ($RequestedAction -eq 'Install') {
        $directoryFull = Assert-CompatLocalPath -Path $Directory -MustExist
    } elseif (-not (Test-Path -LiteralPath $directoryFull)) {
        $null = [IO.Directory]::CreateDirectory($directoryFull)
        $directoryFull = Assert-CompatLocalPath -Path $directoryFull -MustExist
    }
    if (-not (Test-Path -LiteralPath $directoryFull -PathType Container)) { throw 'WorkDirectory must be a directory.' }
    switch ($RequestedAction) {
        'Inspect' { Invoke-CompatInspect -Directory $directoryFull -Source $Source }
        'Install' { Invoke-CompatInstall -Directory $directoryFull -Installer $Installer -Authorized $Authorized }
        'Verify' { Invoke-CompatVerify -Directory $directoryFull -ProgramDirectory $ProgramDirectory }
        default { throw 'Unsupported action.' }
    }
}

# Dot-sourcing exposes the functions for isolated mock tests; it performs no workflow action.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CompatibilityMain -RequestedAction $Action -Directory $WorkDirectory -Source $SourceInstaller -Installer $PreparedInstaller -Authorized ([bool]$InstallationAuthorized) -ProgramDirectory $InstalledDirectory | ConvertTo-Json -Depth 6
}
