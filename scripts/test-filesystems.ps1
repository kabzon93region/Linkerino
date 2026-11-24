param(
    [string]$Exe = 'build\win32\Release\Linkerino.exe',
    [switch]$SkipVhd,
    [switch]$SkipSmb
)

$ErrorActionPreference = 'Stop'
$script:failed = $false

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Output ("PASS: " + $Message)
    } else {
        Write-Output ("FAIL: " + $Message)
        $script:failed = $true
    }
}

function New-Source {
    param([string]$Name)
    $root = Join-Path $env:TEMP ("linkerino-fs-" + $Name + "-" + [guid]::NewGuid().ToString('N'))
    $source = Join-Path $root 'Data'
    New-Item -ItemType Directory -Path (Join-Path $source 'sub') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'payload.txt') -Value 'filesystem payload' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $source 'sub\deep.txt') -Value 'nested payload' -Encoding UTF8
    New-Item -ItemType HardLink -Path (Join-Path $source 'payload-link.txt') -Target (Join-Path $source 'payload.txt') -ErrorAction SilentlyContinue | Out-Null
    return $source
}

function Remove-Source {
    param([string]$Source)
    try {
        [System.IO.Directory]::Delete($Source)
    } catch { }
    $parent = Split-Path -Parent $Source
    Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-Transfer {
    param([string]$Source, [string]$DestParent)
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'gui-smoke.ps1') -Exe $Exe -Source $Source -DestParent $DestParent 2>&1
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Host ("    " + $_ ) }
    return [bool]($code -eq 0)
}

function Get-FreeLetter {
    $used = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
    foreach ($letter in @('V', 'W', 'X', 'Y')) {
        if ($used -notcontains $letter) {
            return $letter
        }
    }
    throw 'No free drive letter for the test VHD'
}

function New-TestVhd {
    param([string]$FileSystem, [string]$Letter)
    $path = Join-Path $env:TEMP ("linkerino-" + $FileSystem + "-" + [guid]::NewGuid().ToString('N') + ".vhdx")
    $script = Join-Path $env:TEMP ("diskpart-" + [guid]::NewGuid().ToString('N') + ".txt")
    $lines = @(
        "create vdisk file=`"$path`" maximum=512 type=expandable",
        "select vdisk file=`"$path`"",
        "attach vdisk",
        "create partition primary",
        ("format fs=" + $FileSystem + " quick label=LINKERINO"),
        ("assign letter=" + $Letter)
    )
    Set-Content -LiteralPath $script -Value $lines -Encoding ASCII
    $out = diskpart /s $script 2>&1
    Remove-Item -LiteralPath $script -Force
    Start-Sleep -Seconds 2
    if (-not (Test-Path -LiteralPath ($Letter + ':\'))) {
        Write-Host ('diskpart output: ' + ($out -join ' '))
        return $null
    }
    return $path
}

function Remove-TestVhd {
    param([string]$Path)
    $script = Join-Path $env:TEMP ("diskpart-" + [guid]::NewGuid().ToString('N') + ".txt")
    $lines = @(
        "select vdisk file=`"$Path`"",
        "detach vdisk"
    )
    Set-Content -LiteralPath $script -Value $lines -Encoding ASCII
    diskpart /s $script | Out-Null
    Remove-Item -LiteralPath $script -Force
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

if (-not $SkipVhd) {
    foreach ($fileSystem in @('exFAT', 'FAT32')) {
        Write-Output ("--- VHD " + $fileSystem + " ---")
        $letter = Get-FreeLetter
        $vhd = New-TestVhd -FileSystem $fileSystem -Letter $letter
        if (-not $vhd) {
            Write-Output ("SKIP: cannot create " + $fileSystem + " VHD")
            continue
        }
        try {
            $source = New-Source -Name $fileSystem
            $ok = Invoke-Transfer -Source $source -DestParent ($letter + ':\dest')
            Assert-True $ok ("transfer to " + $fileSystem + " succeeded")
            Remove-Source -Source $source
        } finally {
            Remove-TestVhd -Path $vhd
        }
    }
}

if (-not $SkipSmb) {
    Write-Output '--- SMB share ---'
    if (-not (Get-Command New-SmbShare -ErrorAction SilentlyContinue)) {
        Write-Output 'SKIP: SMB cmdlets are not available'
    } else {
        $shareRoot = Join-Path $env:TEMP ("linkerino-share-" + [guid]::NewGuid().ToString('N'))
        $shareName = 'Linkerino' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        New-Item -ItemType Directory -Path $shareRoot -Force | Out-Null
        try {
            New-SmbShare -Name $shareName -Path $shareRoot -FullAccess ([Security.Principal.WindowsIdentity]::GetCurrent().Name) | Out-Null
            $unc = '\\localhost\' + $shareName
            $source = New-Source -Name 'smb'
            $probeFile = Join-Path $source 'payload.txt'
            $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
            $acl = Get-Acl -LiteralPath $probeFile
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($everyoneSid, 'WriteData', 'Deny')))
            Set-Acl -LiteralPath $probeFile -AclObject $acl
            $ok = Invoke-Transfer -Source $source -DestParent $unc
            Assert-True $ok 'transfer to SMB share succeeded'
            $destFile = Join-Path (Join-Path $unc 'Data') 'payload.txt'
            $destAcl = Get-Acl -LiteralPath $destFile -ErrorAction SilentlyContinue
            $denyRules = @($destAcl.Access | Where-Object {
                $_.AccessControlType -eq 'Deny' -and
                (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0) -and
                (($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value) -eq 'S-1-1-0')
            })
            Assert-True ($denyRules.Count -gt 0) 'ACL deny rule copied to the SMB share'
            Assert-True ($destAcl.AreAccessRulesProtected) 'DACL is protected on the share'
        } finally {
            Remove-SmbShare -Name $shareName -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $shareRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($script:failed) {
    Write-Output 'RESULT: FAIL'
    exit 1
}
Write-Output 'RESULT: PASS'
exit 0
