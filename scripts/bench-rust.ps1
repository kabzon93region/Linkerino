# Development benchmark: measures one real transfer of a synthetic tree.
# Not part of the shipped program. ASCII only.
param(
    [string]$Exe = 'rust\target\release\Linkerino.exe',
    [int]$SmallFiles = 4000,
    [int]$LargeFiles = 4,
    [int]$Runs = 3
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ('linkerino-bench-' + [guid]::NewGuid().ToString('N'))
$exePath = (Resolve-Path -LiteralPath $Exe).Path
New-Item -ItemType Directory -Path $root -Force | Out-Null

function New-Tree([string]$path) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $payload = New-Object byte[] 1024
    for ($i = 0; $i -lt $SmallFiles; $i++) {
        $dir = Join-Path $path ('d{0:d2}' -f ($i % 40))
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [IO.File]::WriteAllBytes((Join-Path $dir ('f{0:d5}.bin' -f $i)), $payload)
    }
    $big = New-Object byte[] (8 * 1024 * 1024)
    for ($i = 0; $i -lt $LargeFiles; $i++) {
        [IO.File]::WriteAllBytes((Join-Path $path ('big{0}.bin' -f $i)), $big)
    }
}

$results = @()
for ($run = 1; $run -le $Runs; $run++) {
    $case = Join-Path $root ('case' + $run)
    $src = Join-Path $case 'src\Data'
    $dest = Join-Path $case 'dest'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    New-Tree $src

    $jobs = Join-Path $env:TEMP ('linkerino-bench-j-' + [guid]::NewGuid().ToString('N'))
    $env:LINKERINO_JOURNAL_DIR = $jobs
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $exePath `
        -ArgumentList @('--transfer', $src, $dest, '--quiet', '--json') `
        -PassThru -Wait -RedirectStandardOutput (Join-Path $root ('out' + $run + '.json'))
    $watch.Stop()
    $json = Get-Content -LiteralPath (Join-Path $root ('out' + $run + '.json')) -Raw
    $ok = $json -match '"ok":true'
    $link = (Get-Item -LiteralPath $src).LinkType
    $results += [pscustomobject]@{
        Run = $run
        Seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 2)
        ExitCode = $process.ExitCode
        Ok = $ok
        LinkType = $link
    }
    Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $jobs -Recurse -Force -ErrorAction SilentlyContinue
}

$results | Format-Table -AutoSize | Out-String | Write-Output
$median = ($results | Sort-Object Seconds | Select-Object -Index ([int][Math]::Floor($results.Count / 2))).Seconds
$size = (Get-Item -LiteralPath $exePath).Length
Write-Output ('MEDIAN_SECONDS=' + $median)
Write-Output ('EXE_BYTES=' + $size)
Write-Output ('TREE=small:' + $SmallFiles + 'x1KiB,large:' + $LargeFiles + 'x8MiB')
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
