param(
    [string]$Exe = 'build\win32\Release\Linkerino.exe',
    [string]$Out = 'docs\images\linkerino-window.png'
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class LinkerinoCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string className, string windowName);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr window, IntPtr hdc, uint flags);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
"@

$directory = Split-Path -Parent $Out
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$process = Start-Process -FilePath (Resolve-Path -LiteralPath $Exe) -PassThru
$window = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline -and $window -eq [IntPtr]::Zero) {
    $window = [LinkerinoCapture]::FindWindow('LinkerinoMainWindow', [NullString]::Value)
    if ($window -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 300 }
}
if ($window -eq [IntPtr]::Zero) {
    Stop-Process -Id $process.Id -Force
    throw 'Main window not found'
}
Start-Sleep -Milliseconds 700
$rect = New-Object LinkerinoCapture+RECT
[void][LinkerinoCapture]::GetWindowRect($window, [ref]$rect)
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
$bitmap = New-Object System.Drawing.Bitmap $width, $height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$hdc = $graphics.GetHdc()
[void][LinkerinoCapture]::PrintWindow($window, $hdc, 2)
$graphics.ReleaseHdc($hdc)
$graphics.Dispose()
$full = Join-Path (Get-Location) $Out
$bitmap.Save($full, [System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()
[void][LinkerinoCapture]::PostMessage($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
if (-not $process.WaitForExit(10000)) {
    Stop-Process -Id $process.Id -Force
}
Write-Output ('saved: ' + $full + ' (' + $width + 'x' + $height + ')')
