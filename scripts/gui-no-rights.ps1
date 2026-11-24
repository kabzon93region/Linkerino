param(
    [string]$Exe = 'build\win32\Release\Linkerino.exe'
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class LinkerinoNoRights {
    [DllImport("user32.dll")]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, string lParam);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

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

function Find-Window {
    param([string]$ClassName)
    $script:found = [IntPtr]::Zero
    $callback = {
        param($window, $lParam)
        if ([LinkerinoNoRights]::IsWindowVisible($window)) {
            $name = New-Object System.Text.StringBuilder 256
            [void][LinkerinoNoRights]::GetClassName($window, $name, 256)
            if ($name.ToString() -eq $ClassName) {
                $script:found = $window
                return $false
            }
        }
        return $true
    }
    [void][LinkerinoNoRights]::EnumWindows($callback, [IntPtr]::Zero)
    return $script:found
}

function Wait-Window {
    param([string]$ClassName, [int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $window = Find-Window -ClassName $ClassName
        if ($window -ne [IntPtr]::Zero) { return $window }
        Start-Sleep -Milliseconds 200
    }
    return [IntPtr]::Zero
}

$script:failed = $false
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { Write-Output ("PASS: " + $Message) }
    else { Write-Output ("FAIL: " + $Message); $script:failed = $true }
}

$root = Join-Path $env:TEMP ("linkerino-norights-" + [guid]::NewGuid().ToString('N'))
$source = Join-Path $root 'src\Data'
$destParent = Join-Path $root 'dest'
$destFinal = Join-Path $destParent 'Data'
New-Item -ItemType Directory -Path $source, $destParent -Force | Out-Null
Set-Content -LiteralPath (Join-Path $source 'keep.txt') -Value 'important data' -Encoding UTF8

$fullExe = (Resolve-Path -LiteralPath $Exe).Path
Start-Process -FilePath 'runas.exe' -ArgumentList ('/trustlevel:0x20000 "' + $fullExe + '"') -WindowStyle Hidden
$main = Wait-Window -ClassName 'LinkerinoMainWindow' -TimeoutSeconds 25
Assert-True ($main -ne [IntPtr]::Zero) 'window opened without administrator rights'
if ($main -eq [IntPtr]::Zero) {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output 'RESULT: FAIL'
    exit 1
}

$sourceEdit = [LinkerinoNoRights]::GetDlgItem($main, 1001)
$destEdit = [LinkerinoNoRights]::GetDlgItem($main, 1003)
$startButton = [LinkerinoNoRights]::GetDlgItem($main, 1005)
[void][LinkerinoNoRights]::SendMessage($sourceEdit, [LinkerinoNoRights]::WM_SETTEXT, [IntPtr]::Zero, $source)
[void][LinkerinoNoRights]::SendMessage($destEdit, [LinkerinoNoRights]::WM_SETTEXT, [IntPtr]::Zero, $destParent)
Start-Sleep -Milliseconds 300
[void][LinkerinoNoRights]::PostMessage($main, [LinkerinoNoRights]::WM_COMMAND, [IntPtr]1005, $startButton)

$confirm = Wait-Window -ClassName '#32770' -TimeoutSeconds 10
Assert-True ($confirm -ne [IntPtr]::Zero) 'confirmation dialog shown'
if ($confirm -ne [IntPtr]::Zero) {
    [void][LinkerinoNoRights]::PostMessage($confirm, [LinkerinoNoRights]::WM_COMMAND, [IntPtr]6,
        [LinkerinoNoRights]::GetDlgItem($confirm, 6))
}

$result = Wait-Window -ClassName '#32770' -TimeoutSeconds 60
Assert-True ($result -ne [IntPtr]::Zero) 'result dialog shown'
if ($result -ne [IntPtr]::Zero) {
    [void][LinkerinoNoRights]::PostMessage($result, [LinkerinoNoRights]::WM_COMMAND, [IntPtr]1,
        [LinkerinoNoRights]::GetDlgItem($result, 1))
}
Start-Sleep -Milliseconds 700

$question = Wait-Window -ClassName '#32770' -TimeoutSeconds 10
Assert-True ($question -ne [IntPtr]::Zero) 'elevation restart question shown'
if ($question -ne [IntPtr]::Zero) {
    [void][LinkerinoNoRights]::PostMessage($question, [LinkerinoNoRights]::WM_COMMAND, [IntPtr]7,
        [LinkerinoNoRights]::GetDlgItem($question, 7))
}
Start-Sleep -Milliseconds 400

$attributes = [System.IO.File]::GetAttributes($source)
Assert-True (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) 'source folder is not a symlink'
Assert-True (-not (Test-Path -LiteralPath $destFinal)) 'nothing copied to the new place'
$content = Get-Content -LiteralPath (Join-Path $source 'keep.txt') -Raw -ErrorAction SilentlyContinue
Assert-True ($null -ne $content -and $content.Trim() -eq 'important data') 'source data intact'

[void][LinkerinoNoRights]::PostMessage($main, [LinkerinoNoRights]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 500
Get-Process -Name Linkerino -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force }

Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Linkerino') -Filter 'journal-*.txt' -ErrorAction SilentlyContinue |
    Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8) -match 'linkerino-norights-' } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
if ($script:failed) {
    Write-Output 'RESULT: FAIL'
    exit 1
}
Write-Output 'RESULT: PASS'
exit 0
