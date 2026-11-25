param(
    [string]$Exe = 'rust\target\release\Linkerino.exe',
    [string]$Screenshot = 'docs\images\linkerino-rust-window.png',
    [string]$ResultScreenshot = 'docs\images\linkerino-rust-result.png',
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
$helpOut = Join-Path $root 'help-out.txt'
$help = Start-Process -FilePath $exePath -ArgumentList '--help' -RedirectStandardOutput $helpOut `
    -RedirectStandardError (Join-Path $root 'help-err.txt') -PassThru -Wait
$helpText = Get-Content -LiteralPath $helpOut -Raw -Encoding UTF8
Assert-True ($help.ExitCode -eq 0 -and $helpText -match 'transfer') 'cli help lists --transfer'

$source = Join-Path $root 'src\Data'
$destParent = Join-Path $root 'dest'
$destFinal = Join-Path $destParent 'Data'
New-Item -ItemType Directory -Path (Join-Path $source 'nested') -Force | Out-Null
New-Item -ItemType Directory -Path $destParent -Force | Out-Null
Set-Content -LiteralPath (Join-Path $source 'hello.txt') -Value 'hello rust' -Encoding UTF8
Set-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Value 'payload' -Encoding UTF8

$outFile = Join-Path $root 'cli-out.txt'
$errFile = Join-Path $root 'cli-err.txt'
$sw = [Diagnostics.Stopwatch]::StartNew()
$cli = Start-Process -FilePath $exePath -ArgumentList '--transfer', ('"' + $source + '"'), ('"' + $destParent + '"') `
    -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -Wait
$sw.Stop()
$cliOut = (Get-Content -LiteralPath $outFile -Raw -Encoding UTF8) + (Get-Content -LiteralPath $errFile -Raw -Encoding UTF8)
Assert-True ($cli.ExitCode -eq 0) ('cli transfer exit code 0 (got ' + $cli.ExitCode + ')')
if ($cli.ExitCode -ne 0) { Write-Output ('cli output: ' + $cliOut) }

$attributes = [System.IO.File]::GetAttributes($source)
Assert-True (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) 'source became a symlink'
Assert-True (Test-Path -LiteralPath (Join-Path $destFinal 'hello.txt')) 'copy published'
$content = Get-Content -LiteralPath (Join-Path $source 'hello.txt') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $content -and $content.Trim() -eq 'hello rust') 'source reads data through the link'
$nested = Get-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $nested -and $nested.Trim() -eq 'payload') 'nested file readable'
Write-Output ('INFO: transfer took ' + [math]::Round($sw.Elapsed.TotalSeconds, 2) + ' s')

if (-not $SkipGui) {
    $shots = @(
        @{ Path = $Screenshot; Extra = '--demo' },
        @{ Path = $ResultScreenshot; Extra = '--demo-result' }
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
        $gui = Start-Process -FilePath $exePath -ArgumentList '--screenshot', ('"' + $shot.Path + '"'), $shot.Extra `
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
