param(
    [string]$Exe = 'build\win32\Release\Linkerino.exe'
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class LinkerinoWin {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindWindow(string className, string windowName);

    [DllImport("user32.dll")]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, string lParam);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumProc callback, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr window, StringBuilder name, int size);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr window);

    public delegate bool EnumProc(IntPtr window, IntPtr lParam);

    public const uint WM_SETTEXT = 0x000C;
    public const uint WM_COMMAND = 0x0111;
    public const uint WM_CLOSE = 0x0010;
}
"@

function Wait-Window {
    param([int]$ProcessId, [string]$ClassName, [int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $found = [IntPtr]::Zero
        $callback = {
            param($window, $lParam)
            $owner = 0
            [void][LinkerinoWin]::GetWindowThreadProcessId($window, [ref]$owner)
            if ($owner -eq $ProcessId -and [LinkerinoWin]::IsWindowVisible($window)) {
                $name = New-Object System.Text.StringBuilder 256
                [void][LinkerinoWin]::GetClassName($window, $name, 256)
                if ($name.ToString() -eq $ClassName) {
                    $script:foundWindow = $window
                    return $false
                }
            }
            return $true
        }
        $script:foundWindow = [IntPtr]::Zero
        [void][LinkerinoWin]::EnumWindows($callback, [IntPtr]::Zero)
        if ($script:foundWindow -ne [IntPtr]::Zero) {
            return $script:foundWindow
        }
        Start-Sleep -Milliseconds 200
    }
    return [IntPtr]::Zero
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Output ("PASS: " + $Message)
    } else {
        Write-Output ("FAIL: " + $Message)
        $script:failed = $true
    }
}

$script:failed = $false
$root = Join-Path $env:TEMP ("linkerino-gui-" + [guid]::NewGuid().ToString('N'))
$source = Join-Path $root 'src\Data'
$destParent = Join-Path $root 'dest'
$destFinal = Join-Path $destParent 'Data'
New-Item -ItemType Directory -Path (Join-Path $source 'nested'), $destParent -Force | Out-Null
Set-Content -LiteralPath (Join-Path $source 'hello.txt') -Value 'hello world' -Encoding UTF8
Set-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Value 'payload' -Encoding UTF8

if (-not (Test-Path -LiteralPath $Exe)) {
    Write-Output ("FAIL: executable not found: " + $Exe)
    exit 1
}

$process = Start-Process -FilePath (Resolve-Path -LiteralPath $Exe) -PassThru
$main = Wait-Window -ProcessId $process.Id -ClassName 'LinkerinoMainWindow'
if ($main -eq [IntPtr]::Zero) {
    Write-Output 'FAIL: main window not found'
    try { Stop-Process -Id $process.Id -Force } catch { }
    exit 1
}
Write-Output 'PASS: main window created'

$sourceEdit = [LinkerinoWin]::GetDlgItem($main, 1001)
$destEdit = [LinkerinoWin]::GetDlgItem($main, 1003)
$startButton = [LinkerinoWin]::GetDlgItem($main, 1005)
Assert-True ($sourceEdit -ne [IntPtr]::Zero -and $destEdit -ne [IntPtr]::Zero -and $startButton -ne [IntPtr]::Zero) 'controls exist'

[void][LinkerinoWin]::SendMessage($sourceEdit, [LinkerinoWin]::WM_SETTEXT, [IntPtr]::Zero, $source)
[void][LinkerinoWin]::SendMessage($destEdit, [LinkerinoWin]::WM_SETTEXT, [IntPtr]::Zero, $destParent)
Start-Sleep -Milliseconds 300

[void][LinkerinoWin]::PostMessage($main, [LinkerinoWin]::WM_COMMAND, [IntPtr]1005, $startButton)
$confirm = Wait-Window -ProcessId $process.Id -ClassName '#32770' -TimeoutSeconds 10
Assert-True ($confirm -ne [IntPtr]::Zero) 'confirmation dialog shown'
if ($confirm -ne [IntPtr]::Zero) {
    $yes = [LinkerinoWin]::GetDlgItem($confirm, 6)
    [void][LinkerinoWin]::PostMessage($confirm, [LinkerinoWin]::WM_COMMAND, [IntPtr]6, $yes)
}

$result = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    $result = Wait-Window -ProcessId $process.Id -ClassName '#32770' -TimeoutSeconds 1
    if ($result -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 300
}
Assert-True ($result -ne [IntPtr]::Zero) 'result dialog shown'
if ($result -ne [IntPtr]::Zero) {
    $ok = [LinkerinoWin]::GetDlgItem($result, 1)
    [void][LinkerinoWin]::PostMessage($result, [LinkerinoWin]::WM_COMMAND, [IntPtr]1, $ok)
}

Start-Sleep -Milliseconds 500
$attributes = [System.IO.File]::GetAttributes($source)
Assert-True (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) 'source path is a symlink'
Assert-True (Test-Path -LiteralPath (Join-Path $destFinal 'hello.txt')) 'copy published'
$content = Get-Content -LiteralPath (Join-Path $source 'hello.txt') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $content -and $content.Trim() -eq 'hello world') 'source path reads copied data'
$contentNested = Get-Content -LiteralPath (Join-Path $source 'nested\data.bin') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $contentNested -and $contentNested.Trim() -eq 'payload') 'nested file readable'

[void][LinkerinoWin]::PostMessage($main, [LinkerinoWin]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
if (-not $process.WaitForExit(10000)) {
    Stop-Process -Id $process.Id -Force
    Write-Output 'FAIL: application did not exit'
    $script:failed = $true
} else {
    Write-Output 'PASS: application closed cleanly'
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
