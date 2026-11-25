param(
    [string]$Exe = 'rust\target\release\Linkerino.exe',
    [string]$Screenshot = 'docs\images\linkerino-rust-window.png',
    [string]$ResultScreenshot = 'docs\images\linkerino-rust-result.png',
    [string]$DarkScreenshot = 'docs\images\linkerino-rust-dark.png',
    [switch]$SkipGui
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class LinkerinoRustWin {
    public delegate bool EnumProc(IntPtr window, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr window, StringBuilder name, int size);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr window, StringBuilder name, int size);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    public const uint WM_CLOSE = 0x0010;
}
"@

function Find-AppWindow {
    param([int]$ProcessId, [int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $script:appWindow = [IntPtr]::Zero
        $callback = {
            param($window, $lParam)
            $owner = 0
            [void][LinkerinoRustWin]::GetWindowThreadProcessId($window, [ref]$owner)
            if ($owner -eq $ProcessId) {
                $className = New-Object System.Text.StringBuilder 256
                [void][LinkerinoRustWin]::GetClassName($window, $className, 256)
                $title = New-Object System.Text.StringBuilder 256
                [void][LinkerinoRustWin]::GetWindowText($window, $title, 256)
                if ($className.ToString() -eq 'Window Class' -and $title.ToString() -eq 'Linkerino') {
                    $script:appWindow = $window
                    return $false
                }
            }
            return $true
        }
        [void][LinkerinoRustWin]::EnumWindows($callback, [IntPtr]::Zero)
        if ($script:appWindow -ne [IntPtr]::Zero) {
            return $script:appWindow
        }
        Start-Sleep -Milliseconds 250
    }
    return [IntPtr]::Zero
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Output ('PASS: ' + $Message)
    } else {
        Write-Output ('FAIL: ' + $Message)
        $script:failed = $true
    }
}

$script:failed = $false
if (-not (Test-Path -LiteralPath $Exe)) {
    Write-Output ('FAIL: executable not found: ' + $Exe)
    exit 1
}
$exePath = (Resolve-Path -LiteralPath $Exe).Path

$root = Join-Path $env:TEMP ('linkerino-rust-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null

function Invoke-Cli {
    param([string[]]$Arguments)
    $tag = [guid]::NewGuid().ToString('N')
    $stdout = Join-Path $root ('cli-' + $tag + '.out.txt')
    $stderr = Join-Path $root ('cli-' + $tag + '.err.txt')
    $process = Start-Process -FilePath $exePath -ArgumentList $Arguments -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -PassThru -Wait
    [pscustomobject]@{
        Code = $process.ExitCode
        Out = (Get-Content -LiteralPath $stdout -Raw -Encoding UTF8)
        Err = (Get-Content -LiteralPath $stderr -Raw -Encoding UTF8)
    }
}

$help = Invoke-Cli @('--help')
Assert-True ($help.Code -eq 0 -and $help.Out -match '--plan' -and $help.Out -match '--json' -and $help.Out -match '--journals') 'cli --help lists commands and options'

$version = Invoke-Cli @('--version')
Assert-True ($version.Code -eq 0 -and $version.Out -match 'Linkerino \d') 'cli --version reports the program version'

$source = Join-Path $root 'src\Data'
$destParent = Join-Path $root 'dest'
$destFinal = Join-Path $destParent 'Data'
New-Item -ItemType Directory -Path (Join-Path $source 'nested') -Force | Out-Null
New-Item -ItemType Directory -Path $destParent -Force | Out-Null
Set-Content -LiteralPath (Join-Path $source 'hello.txt') -Value 'hello rust' -Encoding UTF8
Set-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Value 'payload' -Encoding UTF8

$plan = Invoke-Cli @('--plan', $source, $destParent)
$planLink = ([System.IO.File]::GetAttributes($source) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
Assert-True ($plan.Code -eq 0 -and -not $planLink -and $plan.Out -match 'Data') 'cli --plan only checks the paths'

$dryOnly = Invoke-Cli @('--dry-run', $source, $destParent)
$dryOnlyLink = ([System.IO.File]::GetAttributes($source) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
Assert-True ($dryOnly.Code -eq 0 -and -not $dryOnlyLink) 'cli --dry-run alone behaves like --plan'

$usage = Invoke-Cli @('--transfer', $source)
Assert-True ($usage.Code -eq 2) ('cli usage error returns exit code 2 (got ' + $usage.Code + ')')

$unknown = Invoke-Cli @('--nonsense')
Assert-True ($unknown.Code -eq 2) ('cli unknown option returns exit code 2 (got ' + $unknown.Code + ')')

$usageJson = Invoke-Cli @('--nonsense', '--json')
$usageJsonOk = $null
try { $usageJsonOk = ($usageJson.Out | ConvertFrom-Json).ok } catch { }
Assert-True ($usageJson.Code -eq 2 -and $usageJsonOk -eq $false) 'cli usage error with --json keeps stdout machine-readable'

$sw = [Diagnostics.Stopwatch]::StartNew()
$cli = Invoke-Cli @('--transfer', $source, $destParent, '--json', '--quiet')
$sw.Stop()
$result = $null
try { $result = $cli.Out | ConvertFrom-Json } catch { }
Assert-True ($cli.Code -eq 0) ('cli transfer exit code 0 (got ' + $cli.Code + ')')
if ($cli.Code -ne 0) { Write-Output ('cli output: ' + $cli.Out + ' ' + $cli.Err) }
Assert-True ($null -ne $result -and $result.ok -eq $true) 'cli --json returns a successful JSON result'
Assert-True ($null -ne $result -and $result.dest -eq $destFinal) 'cli --json reports the destination'

$attributes = [System.IO.File]::GetAttributes($source)
Assert-True (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) 'source became a symlink'
Assert-True (Test-Path -LiteralPath (Join-Path $destFinal 'hello.txt')) 'copy published'
$content = Get-Content -LiteralPath (Join-Path $source 'hello.txt') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $content -and $content.Trim() -eq 'hello rust') 'source reads data through the link'
$nested = Get-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $nested -and $nested.Trim() -eq 'payload') 'nested file readable'
Write-Output ('INFO: transfer took ' + [math]::Round($sw.Elapsed.TotalSeconds, 2) + ' s')

$journals = Invoke-Cli @('--journals', '--json')
$journalCount = -1
try { $journalCount = ($journals.Out | ConvertFrom-Json).count } catch { }
Assert-True ($journals.Code -eq 0 -and $journalCount -eq 0) 'cli --journals reports no pending transfers'

$missing = Invoke-Cli @('--plan', (Join-Path $root 'missing-folder'), $destParent, '--json')
$missingOk = $null
try { $missingOk = ($missing.Out | ConvertFrom-Json).ok } catch { }
Assert-True ($missing.Code -eq 1 -and $missingOk -eq $false) 'cli --plan reports a bad path with exit code 1 and JSON ok=false'

if (-not $SkipGui) {
    $shots = @(
        @{ Path = $Screenshot; Extra = '--demo --theme light' },
        @{ Path = $ResultScreenshot; Extra = '--demo-result --theme light' },
        @{ Path = $DarkScreenshot; Extra = '--demo --theme dark' }
    )
    foreach ($shot in $shots) {
        if (-not $shot.Path) { continue }
        $directory = Split-Path -Parent $shot.Path
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        if (Test-Path -LiteralPath $shot.Path) { Remove-Item -LiteralPath $shot.Path -Force }
        $consoleOut = Join-Path $root ('gui-out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $consoleErr = Join-Path $root ('gui-err-' + [guid]::NewGuid().ToString('N') + '.txt')
        $extraArgs = $shot.Extra.Split(' ')
        $arguments = @('--screenshot', ('"' + $shot.Path + '"')) + $extraArgs
        $gui = Start-Process -FilePath $exePath -ArgumentList $arguments `
            -RedirectStandardOutput $consoleOut -RedirectStandardError $consoleErr -PassThru -Wait
        $code = [string]$gui.ExitCode
        Assert-True ($code -eq '0') ('gui screenshot ' + $shot.Extra + ' exit code 0 (got ' + $code + ')')
        $saved = Test-Path -LiteralPath $shot.Path
        Assert-True ($saved -and (Get-Item -LiteralPath $shot.Path).Length -gt 5000) ('screenshot saved: ' + $shot.Path)
    }
    $app = Start-Process -FilePath $exePath -PassThru
    $window = Find-AppWindow -ProcessId $app.Id
    Assert-True ($window -ne [IntPtr]::Zero) 'gui window created'
    if ($window -ne [IntPtr]::Zero) {
        [void][LinkerinoRustWin]::PostMessage($window, [LinkerinoRustWin]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
        if ($app.WaitForExit(15000)) {
            Write-Output 'PASS: application closed cleanly'
        } else {
            Stop-Process -Id $app.Id -Force
            Assert-True $false 'application did not exit'
        }
    } else {
        Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue
    }
}

try {
    [System.IO.Directory]::Delete($source)
} catch { }
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue

if ($script:failed) {
    Write-Output 'RESULT: FAIL'
    exit 1
}
Write-Output 'RESULT: PASS'
exit 0
