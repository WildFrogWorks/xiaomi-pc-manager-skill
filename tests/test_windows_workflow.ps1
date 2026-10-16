#Requires -Version 5.1
<#
Dependency-free PowerShell tests. Every successful Install test mocks Start-Process and
uses a tiny synthetic file. No Xiaomi executable, service or driver is ever started.
Test artifacts remain in the supplied directory for inspection.
#>
[CmdletBinding()]
param([string]$TestDirectory)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repo 'scripts\Invoke-CompatibilityWorkflow.ps1'
$tokens = $null; $parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
. $scriptPath
if (-not $TestDirectory) { $TestDirectory = Join-Path (Split-Path -Parent $repo) ('xiaomi-skill-test-work\' + [Guid]::NewGuid().ToString('N')) }
$TestDirectory = Join-Path $TestDirectory ('run-' + [Guid]::NewGuid().ToString('N'))
$TestDirectory = Assert-CompatLocalPath -Path $TestDirectory
$null = [IO.Directory]::CreateDirectory($TestDirectory)
$script:checks = 0
function Assert-True { param([bool]$Condition, [string]$Label); if (-not $Condition) { throw ('FAIL: ' + $Label) }; $script:checks++ }
function Assert-Throws { param([scriptblock]$Operation, [string]$Label, [string]$MessagePattern = '.*'); $caught = $false; try { & $Operation | Out-Null } catch { $caught = $true; if ($_.Exception.Message -notmatch $MessagePattern) { throw ('Unexpected failure in ' + $Label + ': ' + $_.Exception.Message) } }; Assert-True $caught $Label }
function New-TestDirectory { $d = Join-Path $TestDirectory ([Guid]::NewGuid().ToString('N')); $null = [IO.Directory]::CreateDirectory($d); return $d }
function Set-TestJson { param([string]$Path, $Value); [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false)) }

$profilePath = Join-Path $repo 'profiles\5.8.1.130.json'
if (Test-Path -LiteralPath $profilePath) {
    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    Assert-True ($profile.prepared_sha256 -eq $script:CompatPreparedHash) 'prepared profile hash agrees'
    Assert-True ($profile.source_sha256 -eq $script:CompatSourceHash) 'source profile hash agrees'
    Assert-True ($profile.size_bytes -eq $script:CompatPreparedSize) 'profile size agrees'
    foreach ($name in $script:CompatCoreHashes.Keys) { Assert-True ($profile.core_files.$name -eq $script:CompatCoreHashes[$name]) ('core profile hash agrees: ' + $name) }
} else { throw 'Version profile must be present for cross-file consistency tests.' }

Assert-Throws { Assert-CompatLocalPath '\\server\share\work' } 'UNC rejected'
Assert-Throws { Assert-CompatLocalPath 'C:relative' } 'drive-relative rejected'
Assert-Throws { Assert-CompatLocalPath 'C:\work:stream' } 'alternate stream rejected'
$tiny = Join-Path $TestDirectory 'synthetic.exe'
[IO.File]::WriteAllBytes($tiny, [byte[]](1, 2, 3))
Assert-Throws { Get-CompatPreparedInstaller $tiny } 'wrong prepared file rejected' 'size mismatch'
Assert-Throws { Get-CompatOriginalInstallerEvidence $tiny } 'wrong original file rejected' 'size mismatch'
$savedSize = $script:CompatPreparedSize
$savedSourceHash = $script:CompatSourceHash
$savedPreparedHash = $script:CompatPreparedHash
$script:CompatPreparedSize = 3L
Assert-Throws { Get-CompatPreparedInstaller $tiny } 'same-sized wrong prepared hash rejected' 'SHA-256 mismatch'
Assert-Throws { Get-CompatOriginalInstallerEvidence $tiny } 'same-sized wrong original hash rejected' 'SHA-256 mismatch'
$script:CompatSourceHash = (Get-FileHash -LiteralPath $tiny -Algorithm SHA256).Hash.ToLowerInvariant()
$script:CompatPreparedHash = $script:CompatSourceHash
$script:mockSignatureStatus = 'NotSigned'
function Get-AuthenticodeSignature { param($LiteralPath); return [pscustomobject]@{ Status = $script:mockSignatureStatus } }
Assert-Throws { Get-CompatOriginalInstallerEvidence $tiny } 'original signature must be Valid' 'signature is not Valid'
$script:mockSignatureStatus = 'Valid'
Assert-True ((Get-CompatOriginalInstallerEvidence $tiny).validated) 'original validation accepts valid signature with pinned test fixture'
$script:mockSignatureStatus = 'HashMismatch'
$held = Get-CompatPreparedInstaller $tiny
try { Assert-Throws { $w = [IO.File]::Open($tiny, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite); $w.Dispose() } 'prepared file stays locked against modification before launch' }
finally { $held.stream.Dispose() }
$script:CompatPreparedSize = $savedSize
$script:CompatSourceHash = $savedSourceHash
$script:CompatPreparedHash = $savedPreparedHash
Remove-Item Function:\Get-AuthenticodeSignature
$report = Join-Path $TestDirectory 'exclusive.json'
$null = Write-CompatJsonNew -Path $report -Value @{ preserved = 1 }
Assert-Throws { Write-CompatJsonNew -Path $report -Value @{ preserved = 2 } } 'reports cannot overwrite existing files'
Assert-True ((Get-Content -LiteralPath $report -Raw | ConvertFrom-Json).preserved -eq 1) 'existing report preserved'
$target = New-TestDirectory
$junction = Join-Path $TestDirectory 'junction'
$null = New-Item -ItemType Junction -Path $junction -Target $target
Assert-Throws { Assert-CompatLocalPath (Join-Path $junction 'report.json') } 'junction ancestor rejected' 'redirected'

# Replace every system inventory/context function before exercising successful workflows.
function Get-CompatSnapshot { param([string]$Directory); return [ordered]@{ schema = 'xiaomi-compat-snapshot-v1'; created_utc = [DateTime]::UtcNow.ToString('o'); issues = @(); services = @(); disk = @() } }
function Get-CompatContextBinding { param([string]$Salt); return 'synthetic-context-' + $Salt }
function Get-CompatDiskSpace { param([string]$Directory); return @([pscustomobject]@{ purpose = 'system'; available_bytes = 20GB; meets_workflow_minimum = $true }) }
function Get-CompatOriginalInstallerEvidence { param([string]$Path); return [pscustomobject]@{ provided = [bool]$Path; validated = [bool]$Path; sha256 = $script:CompatSourceHash; bytes = $script:CompatPreparedSize; signature_status = 'Valid' } }
function New-TestBaseline { param([switch]$NoSource); $d = New-TestDirectory; $s = 'synthetic-source.exe'; if ($NoSource) { $s = $null }; $null = Invoke-CompatInspect -Directory $d -Source $s; return $d }

$normal = New-TestBaseline
Assert-True ((Read-CompatBaseline $normal).schema -eq 'xiaomi-compat-snapshot-v1') 'fresh same-context baseline accepted'
Assert-Throws { Invoke-CompatInspect -Directory $normal } 'baseline not overwritten'
Assert-Throws { Invoke-CompatInstall -Directory $normal -Installer $tiny -Authorized $false } 'installation requires authorization' 'authorization'
$noOriginal = New-TestBaseline -NoSource
Assert-Throws { Invoke-CompatInstall -Directory $noOriginal -Installer $tiny -Authorized $true } 'installation requires validated original source' 'SourceInstaller'
$wrongContext = New-TestBaseline
$statePath = Join-Path $wrongContext 'baseline.local.json'
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$state.context_binding = 'different-user-or-machine'
Set-TestJson $statePath $state
Assert-Throws { Read-CompatBaseline $wrongContext } 'different context rejected' 'does not belong'
$stale = New-TestBaseline
$statePath = Join-Path $stale 'baseline.local.json'
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$state.created_utc = [DateTime]::UtcNow.AddDays(-2).ToString('o')
Set-TestJson $statePath $state
Assert-Throws { Read-CompatBaseline $stale } 'stale baseline rejected' 'expired'
$tampered = New-TestBaseline
$state = Get-Content -LiteralPath (Join-Path $tampered 'baseline.local.json') -Raw | ConvertFrom-Json
[IO.File]::AppendAllText((Join-Path $tampered $state.baseline_file), ' ')
Assert-Throws { Read-CompatBaseline $tampered } 'changed baseline rejected' 'content changed'
$traversal = New-TestBaseline
$statePath = Join-Path $traversal 'baseline.local.json'
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$state.baseline_file = '..\another.json'
Set-TestJson $statePath $state
Assert-Throws { Read-CompatBaseline $traversal } 'baseline path traversal rejected' 'filename'
$verifyDir = New-TestDirectory
$verify = Invoke-CompatVerify -Directory $verifyDir -ProgramDirectory (Join-Path $verifyDir 'absent-program')
Assert-True (-not $verify.all_core_hashes_match) 'missing installed core files never pass'
Assert-True (-not $verify.all_core_signatures_valid) 'missing installed signatures never pass'
$verifyContent = Get-Content -LiteralPath $verify.report -Raw | ConvertFrom-Json
Assert-True ($verifyContent.core_files.Count -eq 5) 'Verify checks all five core files'

# No real executable can reach Start-Process in this test: the call itself is replaced.
function Get-CompatPreparedInstaller { param([string]$Path); return [pscustomobject]@{ path = $tiny; stream = [IO.File]::OpenRead($tiny); signature_status = 'HashMismatch' } }
function Get-Process { param($Name, $ErrorAction); return $null }
$script:launchCalls = 0; $script:simulateLaunchFailure = $false; $script:simulatedExitCode = 0
function Start-Process {
    param($FilePath, $ArgumentList, $WorkingDirectory, $Verb, $WindowStyle, [switch]$PassThru)
    $script:launchCalls++
    Assert-True ($FilePath -eq $tiny) 'only synthetic path reaches mocked launch'
    Assert-True ($ArgumentList -eq '/S') 'only verified /S flag is sent'
    Assert-True ($Verb -eq 'RunAs' -and $WindowStyle -eq 'Hidden') 'elevation is user-operated with hidden helper window'
    if ($script:simulateLaunchFailure) { throw [ComponentModel.Win32Exception]::new(1223) }
    $fake = [pscustomobject]@{ Id = 12345; ExitCode = $script:simulatedExitCode }
    $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
    $fake | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
    return $fake
}
# Keep architecture tests independent of the machine running the suite. Win32_Processor
# is queried even when the PowerShell process is 64-bit; no real CIM call is made here.
$script:processorArchitectureRows = @([pscustomobject]@{ Architecture = 9 })
$script:simulateArchitectureFailure = $false
function Get-CimInstance {
    param($ClassName, $Property, $ErrorAction)
    if ($ClassName -ne 'Win32_Processor' -or $Property -ne 'Architecture' -or $ErrorAction -ne 'Stop') { throw 'Unexpected CIM query in isolated architecture test.' }
    if ($script:simulateArchitectureFailure) { throw 'Synthetic architecture query failure.' }
    return $script:processorArchitectureRows
}
$architectureCases = @(
    @{ name = 'ARM64'; rows = @([pscustomobject]@{ Architecture = 12 }); query_failure = $false },
    @{ name = 'unknown'; rows = @([pscustomobject]@{ Architecture = 65535 }); query_failure = $false },
    @{ name = 'missing value'; rows = @([pscustomobject]@{ Architecture = $null }); query_failure = $false },
    @{ name = 'no processors'; rows = @(); query_failure = $false },
    @{ name = 'mixed architectures'; rows = @([pscustomobject]@{ Architecture = 9 }, [pscustomobject]@{ Architecture = 12 }); query_failure = $false },
    @{ name = 'query failure'; rows = @([pscustomobject]@{ Architecture = 9 }); query_failure = $true }
)
foreach ($case in $architectureCases) {
    $script:processorArchitectureRows = $case.rows
    $script:simulateArchitectureFailure = $case.query_failure
    $architectureDir = New-TestBaseline
    Assert-Throws { Invoke-CompatInstall -Directory $architectureDir -Installer $tiny -Authorized $true } ($case.name + ' leaves fixed installation for adaptive analysis') 'adaptive workflow'
    Assert-True ($script:launchCalls -eq 0) ($case.name + ' never launches an installer')
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $architectureDir 'install-attempt.local.json'))) ($case.name + ' does not record an installation attempt')
}
$script:processorArchitectureRows = @([pscustomobject]@{ Architecture = 9 })
$script:simulateArchitectureFailure = $false
$success = New-TestBaseline
$install = Invoke-CompatInstall -Directory $success -Installer $tiny -Authorized $true
Assert-True ($install.exit_code -eq 0 -and $script:launchCalls -eq 1) 'native AMD64 permits authorized mocked installation'
Assert-True (@(Get-ChildItem -LiteralPath $success -Filter 'install-started-*.json').Count -eq 1) 'started status preserved'
Assert-True (@(Get-ChildItem -LiteralPath $success -Filter 'install-finished-*.json').Count -eq 1) 'finished status preserved'
Assert-Throws { Invoke-CompatInstall -Directory $success -Installer $tiny -Authorized $true } 'repeat installation prevented'
Assert-True ($script:launchCalls -eq 1) 'repeat did not launch'
$failed = New-TestBaseline
$script:simulateLaunchFailure = $true
Assert-Throws { Invoke-CompatInstall -Directory $failed -Installer $tiny -Authorized $true } 'UAC cancellation reported'
Assert-True (@(Get-ChildItem -LiteralPath $failed -Filter 'install-failed-*.json').Count -eq 1) 'launch failure report preserved'
Assert-True (Test-Path -LiteralPath (Join-Path $failed 'install-attempt.local.json')) 'failed attempt marker preserved'
$script:simulateLaunchFailure = $false; $script:simulatedExitCode = 7
$nonzero = New-TestBaseline
Assert-Throws { Invoke-CompatInstall -Directory $nonzero -Installer $tiny -Authorized $true } 'nonzero installer exit is failure' 'exit code 7'
Assert-True (@(Get-ChildItem -LiteralPath $nonzero -Filter 'install-finished-*.json').Count -eq 1) 'nonzero exit evidence preserved'
[pscustomobject]@{ passed = $true; checks = $script:checks; directory = $TestDirectory; target_executions = 0; note = 'Install calls were mocked. No Xiaomi application, service or driver was launched.' } | ConvertTo-Json
