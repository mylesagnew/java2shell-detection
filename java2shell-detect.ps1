<#
.SYNOPSIS
    Host-side exposure check for CVE-2026-114938 (Java2Shell / Java4Shell) on Windows.

.DESCRIPTION
    The bug is a heap overflow in HotSpot's AVX-512 VBMI Base64 decode intrinsic (C2 JIT).
    A JVM is exposed when ALL of these hold:
      1. its version is in the affected range,
      2. the CPU has AVX512F + AVX512BW + AVX512VBMI + BMI2 (x86-64 only),
      3. the intrinsic is not switched off (-XX:-UseBASE64Intrinsics, -XX:UseAVX<=2, -Xint ...).

    Checks Java installs on disk and every running process that has jvm.dll loaded
    (java.exe, javaw.exe, and service wrappers such as Tomcat/procrun used by Jira and
    Confluence). Read-only. Never sends the malformed Base64 trigger to anything: that
    input corrupts memory in the target, so a network probe would be an attack.

    Runs on Windows PowerShell 5.1 and PowerShell 7+. Run elevated to see all processes.
    PowerShell 7.1+ reads the CPU flags exactly (CPUID); 5.1 can only rule a CPU out.

.EXAMPLE
    .\java2shell-detect.ps1

.EXAMPLE
    .\java2shell-detect.ps1 -Json | Out-File "java2shell-$env:COMPUTERNAME.json"

.EXAMPLE
    .\java2shell-detect.ps1 -Path D:\Apps -AssumeCpuCapable -NoProcesses

.NOTES
    Exit codes: 0 clean, 1 VULNERABLE or RESTART_REQUIRED, 2 needs review/patch, 3 error.
#>
[CmdletBinding()]
param(
    [string[]]$Path = @(),
    [switch]$Deep,
    [int]$MaxDepth = 6,
    [switch]$NoInstalls,
    [switch]$NoProcesses,
    [switch]$NoJcmd,
    [switch]$AssumeCpuCapable,
    [switch]$Json,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:ToolVersion = '1.0.0'
$Script:Cve = 'CVE-2026-114938'
$Script:Order = @('VULNERABLE', 'RESTART_REQUIRED', 'MITIGATED', 'AFFECTED_VERSION_CPU_NOT_EXPOSED', 'REVIEW', 'OK')

# ---------------------------------------------------------------- versions

function ConvertTo-JavaVersion {
    <# '17.0.21.1', '17.0.21+9-LTS', '1.8.0_412', '21' -> int[] or $null #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $s = $Text.Trim().Trim('"')
    if ($s -match '^1\.(\d+)\.\d+(?:_(\d+))?') {
        $upd = 0
        if ($Matches[2]) { $upd = [int]$Matches[2] }
        return , @([int]$Matches[1], 0, $upd)
    }
    if ($s -match '^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?') {
        $parts = @()
        for ($i = 1; $i -le 4; $i++) { if ($Matches[$i]) { $parts += [int]$Matches[$i] } }
        return , $parts
    }
    return $null
}

function Compare-JavaVersion {
    <# -1 / 0 / 1, missing components count as 0 #>
    param([int[]]$A, [int[]]$B)
    for ($i = 0; $i -lt 4; $i++) {
        $x = 0; $y = 0
        if ($i -lt $A.Count) { $x = $A[$i] }
        if ($i -lt $B.Count) { $y = $B[$i] }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

function Get-VersionStatus {
    <# Returns @{ Status = affected|fixed|not_affected|unknown; Note = ... } #>
    param($Version)
    # First fixed build per line (17 Nov 2026 releases). Vendor build numbers can differ.
    $fixedBuilds = @{ 17 = @(17, 0, 21, 1); 21 = @(21, 0, 13, 1); 25 = @(25, 0, 5, 1); 27 = @(27, 0, 1, 1) }
    $firstAffected17 = @(17, 0, 6)
    if (-not $Version) { return @{ Status = 'unknown'; Note = 'version could not be read' } }
    $major = $Version[0]
    if ($major -le 8) {
        return @{ Status = 'not_affected'; Note = 'Java 8 is not affected, except one Oracle Java 8 Performance Pack build: check if this is Oracle Performance Pack' }
    }
    if ($major -le 16) { return @{ Status = 'not_affected'; Note = 'older than the vulnerable intrinsic' } }
    if ($major -eq 17 -and (Compare-JavaVersion $Version $firstAffected17) -lt 0) {
        return @{ Status = 'not_affected'; Note = '17 before 17.0.6 has no VBMI decode intrinsic' }
    }
    if ($fixedBuilds.ContainsKey($major)) {
        $fix = $fixedBuilds[$major]
        if ((Compare-JavaVersion $Version $fix) -ge 0) {
            return @{ Status = 'fixed'; Note = "at or above $($fix -join '.')" }
        }
        return @{ Status = 'affected'; Note = "below fixed build $($fix -join '.')" }
    }
    if ($major -lt 27) {
        return @{ Status = 'affected'; Note = "Java $major is an end-of-life feature release with no fix: move to a patched 17/21/25/27 build" }
    }
    return @{ Status = 'unknown'; Note = "Java $major is newer than the advisory: check vendor notes" }
}

# ---------------------------------------------------------------- CPU

function Get-CpuExposure {
    $info = [ordered]@{ Arch = $null; Flags = [ordered]@{}; Source = $null; Capable = $null }
    $arch = $null
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        # 9 = x64, 12 = ARM64, 0 = x86, 5 = ARM
        $arch = @{ 0 = 'x86'; 5 = 'arm'; 9 = 'x64'; 12 = 'arm64' }[[int]$cpu.Architecture]
        $info.Name = $cpu.Name.Trim()
    } catch { }
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    $info.Arch = $arch
    if ($arch -notin @('x64', 'AMD64')) {
        $info.Source = 'not x86-64'
        $info.Capable = $false
        return $info
    }

    # PowerShell 7.1+ (.NET 5+): exact CPUID leaf 7.
    $x86Base = 'System.Runtime.Intrinsics.X86.X86Base' -as [type]
    if ($x86Base -and $x86Base.GetMethod('CpuId')) {
        try {
            $r = $x86Base::CpuId(7, 0)          # (eax, ebx, ecx, edx)
            $ebx = [int64]$r.Item2; $ecx = [int64]$r.Item3
            $info.Flags.avx512f = [bool]($ebx -band (1 -shl 16))
            $info.Flags.avx512bw = [bool]($ebx -band (1 -shl 30))
            $info.Flags.bmi2 = [bool]($ebx -band (1 -shl 8))
            $info.Flags.avx512vbmi = [bool]($ecx -band (1 -shl 1))
            $info.Source = 'CPUID'
            $info.Capable = $info.Flags.avx512f -and $info.Flags.avx512bw -and $info.Flags.bmi2 -and $info.Flags.avx512vbmi
            # The OS must also enable AVX-512 state; .NET reports that through IsSupported.
            $avx512f = 'System.Runtime.Intrinsics.X86.Avx512F' -as [type]
            if ($info.Capable -and $avx512f -and -not $avx512f::IsSupported) {
                $info.Capable = $false
                $info.Source = 'CPUID (AVX-512 disabled by the OS)'
            }
            return $info
        } catch { }
    }

    # Windows PowerShell 5.1: kernel32 only knows AVX512F (feature 41). No AVX512F rules it out.
    try {
        if (-not ('J2S.Native' -as [type])) {
            Add-Type -Namespace J2S -Name Native -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint f);'
        }
        $f = [J2S.Native]::IsProcessorFeaturePresent(41)
        $info.Flags.avx512f = $f
        if (-not $f) {
            $info.Source = 'IsProcessorFeaturePresent (no AVX-512F)'
            $info.Capable = $false
        } else {
            $info.Source = 'AVX-512F present; VBMI/BW/BMI2 unknown on PowerShell 5.1, assuming capable (run under pwsh 7 for an exact answer)'
            $info.Capable = $true
        }
        return $info
    } catch { }
    $info.Source = 'unreadable (assuming capable)'
    $info.Capable = $true
    return $info
}

# ---------------------------------------------------------------- JVM options

function Split-CommandLine {
    param([string]$CommandLine)
    if (-not $CommandLine) { return , @() }
    $out = @()
    foreach ($m in [regex]::Matches($CommandLine, '(?:"[^"]*"|[^\s"])+')) { $out += $m.Value.Replace('"', '') }
    return , $out
}

function Get-Mitigation {
    <# Walk JVM options in order (last wins). Returns @{ Mitigated; Reasons } #>
    param([string[]]$JvmArgs)
    $b64 = $null; $useAvx = $null; $xint = $false; $tiered = $null
    foreach ($a in $JvmArgs) {
        if ($a -ceq '-XX:-UseBASE64Intrinsics') { $b64 = $false }
        elseif ($a -ceq '-XX:+UseBASE64Intrinsics') { $b64 = $true }
        elseif ($a -ceq '-Xint') { $xint = $true }
        elseif ($a -cmatch '^-XX:UseAVX=(\d+)$') { $useAvx = [int]$Matches[1] }
        elseif ($a -cmatch '^-XX:TieredStopAtLevel=(\d+)$') { $tiered = [int]$Matches[1] }
    }
    $reasons = @()
    if ($b64 -eq $false) { $reasons += '-XX:-UseBASE64Intrinsics' }
    if ($null -ne $useAvx -and $useAvx -lt 3) { $reasons += "-XX:UseAVX=$useAvx" }
    if ($xint) { $reasons += '-Xint (no JIT)' }
    if ($null -ne $tiered -and $tiered -lt 4) { $reasons += "-XX:TieredStopAtLevel=$tiered (no C2)" }
    return @{ Mitigated = ($reasons.Count -gt 0); Reasons = $reasons }
}

function Get-OrderedJvmArgs {
    <# HotSpot reads JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS (launcher), embedded/service
       options, the command line, then _JAVA_OPTIONS; later entries override earlier. #>
    param([hashtable]$EnvOptions, [string[]]$ServiceOptions, [string[]]$CommandArgs)
    $list = @()
    foreach ($n in @('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS')) {
        if ($EnvOptions.ContainsKey($n)) { $list += Split-CommandLine $EnvOptions[$n] }
    }
    if ($ServiceOptions) { $list += $ServiceOptions }
    if ($CommandArgs) { $list += $CommandArgs }
    if ($EnvOptions.ContainsKey('_JAVA_OPTIONS')) { $list += Split-CommandLine $EnvOptions['_JAVA_OPTIONS'] }
    return , $list
}

function ConvertFrom-JcmdFlags {
    param([string]$Text)
    $flags = @{}
    if ($Text -match '\bUseBASE64Intrinsics\s*:?=\s*(true|false)') { $flags.UseBASE64Intrinsics = ($Matches[1] -eq 'true') }
    if ($Text -match '\bUseAVX\s*:?=\s*(\d+)') { $flags.UseAVX = [int]$Matches[1] }
    return $flags
}

function ConvertFrom-JcmdVersion {
    param([string]$Text)
    if ($Text -match '(?m)^JDK\s+([0-9][0-9._+\-A-Za-z]*)') { return $Matches[1] }
    return $null
}

# ---------------------------------------------------------------- helpers

function Invoke-Tool {
    <# Run an exe with a timeout; returns stdout+stderr or '' #>
    param([string]$File, [string]$Arguments, [int]$TimeoutMs = 15000)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $File
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; return '' }
        return $outTask.Result + $errTask.Result
    } catch { return '' }
}

function Read-ReleaseFile {
    param([string]$JavaHome)
    $data = @{}
    $file = Join-Path $JavaHome 'release'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $data }
    try {
        foreach ($line in Get-Content -LiteralPath $file -ErrorAction Stop) {
            $i = $line.IndexOf('=')
            if ($i -gt 0) { $data[$line.Substring(0, $i).Trim()] = $line.Substring($i + 1).Trim().Trim('"') }
        }
    } catch { }
    return $data
}

function New-InstallRecord {
    param([string]$JavaHome)
    $rel = Read-ReleaseFile $JavaHome
    if ($rel.Count -eq 0 -and (Split-Path $JavaHome -Leaf) -eq 'jre') {
        $rel = Read-ReleaseFile (Split-Path $JavaHome -Parent)   # JDK 8: release sits beside jre\
    }
    $ver = $null; $src = $null
    if ($rel.ContainsKey('JAVA_VERSION')) { $ver = $rel['JAVA_VERSION']; $src = 'release file' }
    else {
        # No release file: use the PE version resource instead of executing java.exe.
        $exe = Join-Path $JavaHome 'bin\java.exe'
        try {
            $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
            if ($fvi.ProductVersion) { $ver = $fvi.ProductVersion.Trim(); $src = 'java.exe version resource' }
        } catch { }
    }
    $impl = $null
    if ($rel.ContainsKey('IMPLEMENTOR')) { $impl = $rel['IMPLEMENTOR'] }
    $rt = $null
    if ($rel.ContainsKey('JAVA_RUNTIME_VERSION')) { $rt = $rel['JAVA_RUNTIME_VERSION'] }
    return [ordered]@{
        Kind = 'install'; JavaHome = $JavaHome; Version = $ver; VersionSource = $src
        RuntimeVersion = $rt; Implementor = $impl
    }
}

function Get-Verdict {
    param([string]$Status, [bool]$CpuCapable, [bool]$Mitigated, [bool]$RestartNeeded = $false)
    if ($RestartNeeded) { return 'RESTART_REQUIRED' }
    if ($Status -eq 'affected') {
        if (-not $CpuCapable) { return 'AFFECTED_VERSION_CPU_NOT_EXPOSED' }
        if ($Mitigated) { return 'MITIGATED' }
        return 'VULNERABLE'
    }
    if ($Status -eq 'unknown') { return 'REVIEW' }
    return 'OK'
}

# ---------------------------------------------------------------- discovery: installs

function Get-RegistryJavaHomes {
    $homes = @()
    $keys = @(
        'HKLM:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft',
        'HKLM:\SOFTWARE\Eclipse Adoptium', 'HKLM:\SOFTWARE\Eclipse Foundation',
        'HKLM:\SOFTWARE\Amazon Corretto', 'HKLM:\SOFTWARE\Azul Systems',
        'HKLM:\SOFTWARE\Microsoft\JDK', 'HKLM:\SOFTWARE\BellSoft', 'HKLM:\SOFTWARE\Semeru'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        foreach ($item in Get-ChildItem -Path $k -Recurse -ErrorAction SilentlyContinue) {
            foreach ($name in @('JavaHome', 'Path', 'InstallationPath')) {
                $v = $item.GetValue($name)
                if ($v -and (Test-Path -LiteralPath (Join-Path $v 'bin\java.exe'))) { $homes += $v.TrimEnd('\') }
            }
        }
    }
    return $homes
}

function Get-SearchRoots {
    param([string[]]$Extra, [bool]$Deep)
    if ($Deep) {
        $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID + '\' })
        return $drives + $Extra
    }
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData,
        (Join-Path $env:SystemDrive '\Java'), (Join-Path $env:SystemDrive '\Atlassian'),
        (Join-Path $env:SystemDrive '\Tools'), (Join-Path $env:SystemDrive '\hostedtoolcache\windows'))
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA 'Programs') }
    if ($env:USERPROFILE) {
        $roots += (Join-Path $env:USERPROFILE '.jdks'), (Join-Path $env:USERPROFILE '.gradle\jdks'),
        (Join-Path $env:USERPROFILE 'scoop\apps')
    }
    return @($roots | Where-Object { $_ }) + $Extra
}

function Find-JavaInstalls {
    param([string[]]$Roots, [int]$Depth)
    $homes = @{}
    $direct = @()
    if ($env:JAVA_HOME) { $direct += $env:JAVA_HOME }
    $direct += Get-RegistryJavaHomes
    try {
        foreach ($c in @(Get-Command java.exe -All -CommandType Application -ErrorAction SilentlyContinue)) {
            $direct += (Split-Path (Split-Path $c.Source -Parent) -Parent)
        }
    } catch { }
    foreach ($d in $direct) {
        if ($d -and (Test-Path -LiteralPath (Join-Path $d 'bin\java.exe'))) {
            try {
                $full = (Resolve-Path -LiteralPath $d).ProviderPath.TrimEnd('\')
                $homes[$full.ToLowerInvariant()] = $full
            } catch { }
        }
    }
    foreach ($root in ($Roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $found = Get-ChildItem -LiteralPath $root -Filter 'java.exe' -File -Recurse -Depth $Depth -Force -ErrorAction SilentlyContinue
        foreach ($f in $found) {
            if ($f.Directory.Name -ne 'bin') { continue }
            $h = $f.Directory.Parent.FullName.TrimEnd('\')
            $homes[$h.ToLowerInvariant()] = $h
        }
    }
    # Drop JDK 8's nested jre\ when its parent JDK is also listed; skip the Oracle javapath shim.
    $keys = @($homes.Keys)
    $result = @()
    foreach ($k in $keys) {
        $h = $homes[$k]
        if ($k -like '*\common files\oracle\java*') { continue }
        if ((Split-Path $k -Leaf) -eq 'jre' -and $homes.ContainsKey((Split-Path $k -Parent))) { continue }
        $result += $h
    }
    return $result | Sort-Object
}

# ---------------------------------------------------------------- discovery: processes

function Get-ProcrunOptions {
    <# Tomcat/procrun services (Jira, Confluence, Tomcat) keep JVM options in the registry. #>
    param([string]$ServiceName)
    $opts = @()
    foreach ($base in @('HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0',
                        'HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0')) {
        $k = Join-Path $base "$ServiceName\Parameters\Java"
        if (Test-Path $k) {
            $item = Get-Item $k
            foreach ($n in @('Options', 'Options9')) {
                $v = $item.GetValue($n)
                if ($v) { $opts += @($v) }
            }
        }
    }
    return , $opts
}

function Get-MachineEnvOptions {
    <# Other processes' environments are not readable from PowerShell; use the machine-wide
       values every service inherits, plus this session's values. #>
    $envOpts = @{}
    $machine = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    foreach ($n in @('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')) {
        $v = $null
        try { $v = (Get-ItemProperty -Path $machine -Name $n -ErrorAction Stop).$n } catch { }
        if ($v) { $envOpts[$n] = $v }
    }
    return $envOpts
}

function Get-JvmProcesses {
    $cim = @{}
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $cim[[int]$p.ProcessId] = $p }
    $svc = @{}
    foreach ($s in @(Get-CimInstance Win32_Service -Filter 'State="Running"' -ErrorAction SilentlyContinue)) {
        if ($s.ProcessId) { $svc[[int]$s.ProcessId] = $s.Name }
    }
    $list = @()
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        if ($proc.Id -eq $PID -or $proc.Id -le 4) { continue }
        $jvm = $null
        try {
            $jvm = $proc.Modules | Where-Object { $_.ModuleName -ieq 'jvm.dll' } | Select-Object -First 1
        } catch { }
        $info = $null
        if ($cim.ContainsKey($proc.Id)) { $info = $cim[$proc.Id] }
        $isJavaExe = $proc.ProcessName -in @('java', 'javaw')
        if (-not $jvm -and -not $isJavaExe) { continue }

        $javaHome = $null; $jvmPath = $null
        if ($jvm) {
            $jvmPath = $jvm.FileName
            # <home>\bin\server\jvm.dll  or  <jdk8>\jre\bin\server\jvm.dll
            $javaHome = Split-Path (Split-Path (Split-Path $jvmPath -Parent) -Parent) -Parent
        } elseif ($info -and $info.ExecutablePath) {
            $javaHome = Split-Path (Split-Path $info.ExecutablePath -Parent) -Parent
        }
        $owner = $null
        if ($info) {
            try {
                $o = Invoke-CimMethod -InputObject $info -MethodName GetOwner -ErrorAction Stop
                if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
            } catch { }
        }
        $service = $null
        if ($svc.ContainsKey($proc.Id)) { $service = $svc[$proc.Id] }
        $cmd = $null
        if ($info) { $cmd = $info.CommandLine }
        $list += [ordered]@{
            Pid = $proc.Id; Name = $proc.ProcessName; User = $owner; Service = $service
            CommandLine = $cmd; JavaHome = $javaHome; JvmDll = $jvmPath
            ModulesRead = [bool]$jvm
        }
    }
    return $list
}

function Invoke-JcmdProbe {
    param($Proc)
    $jcmd = $null
    if ($Proc.JavaHome) {
        $c = Join-Path $Proc.JavaHome 'bin\jcmd.exe'
        if (Test-Path -LiteralPath $c) { $jcmd = $c }
    }
    if (-not $jcmd) {
        $c = Get-Command jcmd.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $jcmd = $c.Source }
    }
    if (-not $jcmd) { return $null }
    $ver = Invoke-Tool $jcmd "$($Proc.Pid) VM.version"
    $flags = Invoke-Tool $jcmd "$($Proc.Pid) VM.flags -all"
    $res = @{ Version = (ConvertFrom-JcmdVersion $ver); Flags = (ConvertFrom-JcmdFlags $flags) }
    if (-not $res.Version -and $res.Flags.Count -eq 0) { return $null }
    return $res
}

function Get-ProcessAssessment {
    param($Proc, [bool]$CpuCapable, [hashtable]$EnvOptions, [bool]$UseJcmd = $true)
    $rec = $null
    if ($Proc.JavaHome) { $rec = New-InstallRecord $Proc.JavaHome }
    else { $rec = [ordered]@{ Kind = 'install'; JavaHome = '?'; Version = $null; VersionSource = $null; RuntimeVersion = $null; Implementor = $null } }
    $rec.Kind = 'process'
    $rec.Pid = $Proc.Pid
    $rec.User = $Proc.User
    $rec.Service = $Proc.Service
    $cmdText = "$($Proc.CommandLine)"
    if ($cmdText.Length -gt 300) { $cmdText = $cmdText.Substring(0, 300) }
    $rec.Command = $cmdText

    $probe = $null
    if ($UseJcmd) { $probe = Invoke-JcmdProbe $Proc }
    $rec.Jcmd = $probe

    $svcOpts = @()
    if ($Proc.Service) { $svcOpts = Get-ProcrunOptions $Proc.Service }
    $cmdArgs = Split-CommandLine $Proc.CommandLine
    if ($cmdArgs.Count -gt 1) { $cmdArgs = $cmdArgs[1..($cmdArgs.Count - 1)] } else { $cmdArgs = @() }
    $m = Get-Mitigation (Get-OrderedJvmArgs $EnvOptions $svcOpts $cmdArgs)
    $mitigated = $m.Mitigated; $reasons = $m.Reasons
    if ($probe -and $probe.Flags.ContainsKey('UseBASE64Intrinsics')) {
        # The live flag value beats our reading of the command line.
        $liveB64 = $probe.Flags.UseBASE64Intrinsics
        $liveAvx = $null
        if ($probe.Flags.ContainsKey('UseAVX')) { $liveAvx = $probe.Flags.UseAVX }
        $noC2 = @($reasons | Where-Object { $_ -match 'Xint|TieredStop' }).Count -gt 0
        $mitigated = (-not $liveB64) -or ($null -ne $liveAvx -and $liveAvx -lt 3) -or $noC2
        $r = "live: UseBASE64Intrinsics=$($liveB64.ToString().ToLower())"
        if ($null -ne $liveAvx) { $r += ", UseAVX=$liveAvx" }
        $reasons = @($r)
    }
    $rec.Mitigation = $reasons

    $disk = Get-VersionStatus (ConvertTo-JavaVersion $rec.Version)
    $runningVer = $null
    if ($probe) { $runningVer = $probe.Version }
    $notes = @()
    $runStatus = $null
    if ($runningVer) {
        $rec.RunningVersion = $runningVer
        $run = Get-VersionStatus (ConvertTo-JavaVersion $runningVer)
        $runStatus = $run.Status
        $status = $runStatus
        if ($disk.Status -eq 'fixed' -and $runStatus -eq 'affected') { $notes += "patched on disk, but this JVM still runs $runningVer" }
        $notes += $run.Note
    } else {
        $status = $disk.Status
        $notes += $disk.Note
    }
    $stale = $Proc.JvmDll -and -not (Test-Path -LiteralPath $Proc.JvmDll)
    if ($stale) { $notes += 'the jvm.dll this process loaded is no longer on disk (upgraded after start)' }
    if (-not $Proc.ModulesRead) { $notes += 'could not read process modules (run elevated)' }
    if ($UseJcmd -and -not $probe) { $notes += 'jcmd attach failed: flags taken from command line, service registry and machine environment only' }

    $restart = ($disk.Status -eq 'fixed' -and $runStatus -eq 'affected') -or ($stale -and -not $runningVer)
    $rec.VersionStatus = $status
    $rec.Note = ($notes | Where-Object { $_ }) -join '; '
    $rec.Verdict = Get-Verdict $status $CpuCapable $mitigated $restart
    return $rec
}

function Get-InstallAssessment {
    param($Rec, [bool]$CpuCapable)
    $vs = Get-VersionStatus (ConvertTo-JavaVersion $Rec.Version)
    $Rec.VersionStatus = $vs.Status
    $Rec.Note = $vs.Note
    $Rec.Verdict = Get-Verdict $vs.Status $CpuCapable $false
    if ($Rec.Verdict -eq 'VULNERABLE') { $Rec.Note += '; any JVM started from here without the workaround flag is exposed' }
    return $Rec
}

# ---------------------------------------------------------------- output

function Write-Report {
    param($Report, [bool]$Color)
    $colors = @{ VULNERABLE = 'Red'; RESTART_REQUIRED = 'Red'; MITIGATED = 'Yellow'
        AFFECTED_VERSION_CPU_NOT_EXPOSED = 'Yellow'; REVIEW = 'Cyan'; OK = 'Green' }
    $cpu = $Report.Cpu
    Write-Output "java2shell-detect $($Script:ToolVersion)  $($Script:Cve)  host=$($Report.Host)"
    $flags = ($cpu.Flags.Keys | ForEach-Object { "$_=$(if ($cpu.Flags[$_]) { 'yes' } else { 'no' })" }) -join ' '
    if (-not $flags) { $flags = '-' }
    $state = 'not exposed'
    if ($cpu.Capable) { $state = 'AVX-512 VBMI path AVAILABLE' }
    Write-Output "CPU: $($cpu.Arch)  $flags  -> $state ($($cpu.Source))"
    if ($Report.CpuOverride) { Write-Output '     (CPU treated as capable because of -AssumeCpuCapable)' }
    Write-Output ''
    if ($Report.Findings.Count -eq 0) { Write-Output 'No Java runtimes or JVM processes found. Try -Deep or -Path DIR.' }
    $sorted = $Report.Findings | Sort-Object { [array]::IndexOf($Script:Order, $_.Verdict) }, { $_.Kind }
    foreach ($f in $sorted) {
        $ver = $f.Version
        if ($f.Contains('RunningVersion') -and $f.RunningVersion) { $ver = $f.RunningVersion }
        if (-not $ver) { $ver = '?' }
        if ($f.Kind -eq 'process') {
            $who = $f.User; if (-not $who) { $who = '?' }
            $where = "pid $($f.Pid) ($who) $($f.JavaHome)"
            if ($f.Service) { $where += " [service $($f.Service)]" }
        } else { $where = $f.JavaHome }
        $line = '{0,-33} {1,-8} {2,-14} {3}' -f $f.Verdict, $f.Kind, $ver, $where
        if ($Color) { Write-Host $line -ForegroundColor $colors[$f.Verdict] } else { Write-Output $line }
        $pad = ' ' * 34
        if ($f.Implementor) { Write-Output "${pad}vendor: $($f.Implementor)" }
        if ($f.Contains('Mitigation') -and $f.Mitigation -and @($f.Mitigation).Count -gt 0) { Write-Output "${pad}mitigation: $(@($f.Mitigation) -join ', ')" }
        if ($f.Note) { Write-Output "$pad$($f.Note)" }
    }
    Write-Output ''
    $counts = ($Script:Order | Where-Object { $Report.Summary[$_] } | ForEach-Object { "$_=$($Report.Summary[$_])" }) -join ', '
    if (-not $counts) { $counts = 'none' }
    Write-Output "Summary: $counts"
    if ($Report.Summary['VULNERABLE'] -or $Report.Summary['RESTART_REQUIRED']) {
        Write-Output "Fix: upgrade to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (or your vendor's equivalent) and RESTART the JVM."
        Write-Output 'Stop-gap: add -XX:-UseBASE64Intrinsics (machine JAVA_TOOL_OPTIONS, or the service''s Java Options) and restart.'
    }
}

function Invoke-Java2ShellDetect {
    $cpu = Get-CpuExposure
    $capable = [bool]$cpu.Capable
    if ($AssumeCpuCapable) { $capable = $true }
    $findings = @()

    if (-not $NoProcesses) {
        $envOpts = Get-MachineEnvOptions
        foreach ($p in Get-JvmProcesses) {
            $findings += Get-ProcessAssessment $p $capable $envOpts (-not $NoJcmd)
        }
    }
    if (-not $NoInstalls) {
        $extra = @($Path | ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath })
        $depth = $MaxDepth
        if ($Deep) { $depth = 64 }
        foreach ($h in Find-JavaInstalls (Get-SearchRoots $extra $Deep.IsPresent) $depth) {
            $findings += Get-InstallAssessment (New-InstallRecord $h) $capable
        }
    }

    $summary = [ordered]@{}
    foreach ($k in $Script:Order) { $summary[$k] = @($findings | Where-Object { $_.Verdict -eq $k }).Count }
    $report = [ordered]@{
        Tool = 'java2shell-detect'; ToolVersion = $Script:ToolVersion; Cve = $Script:Cve
        Host = $env:COMPUTERNAME; Platform = 'windows'; PowerShell = $PSVersionTable.PSVersion.ToString()
        Cpu = $cpu; CpuOverride = [bool]$AssumeCpuCapable; Summary = $summary; Findings = $findings
    }
    if ($Json) { $report | ConvertTo-Json -Depth 8 }
    else { Write-Report $report (-not $NoColor -and -not [Console]::IsOutputRedirected) }

    $Script:ExitCode = 0
    if ($summary['MITIGATED'] -or $summary['AFFECTED_VERSION_CPU_NOT_EXPOSED'] -or $summary['REVIEW']) { $Script:ExitCode = 2 }
    if ($summary['VULNERABLE'] -or $summary['RESTART_REQUIRED']) { $Script:ExitCode = 1 }
}

# Dot-sourcing (". .\java2shell-detect.ps1") only loads the functions, for tests.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Java2ShellDetect
        exit $Script:ExitCode
    } catch {
        Write-Error "java2shell-detect failed: $_"
        exit 3
    }
}
