# Pester 5 tests for java2shell-detect.ps1 (logic only; run on Windows).
BeforeAll {
    . (Join-Path $PSScriptRoot '..\java2shell-detect.ps1')
    Set-StrictMode -Off
    $ErrorActionPreference = 'Continue'

    function Status([string]$v) { (Get-VersionStatus (ConvertTo-JavaVersion $v)).Status }

    function New-FakeHome([string]$Root, [string]$Name, [string]$Version) {
        $h = Join-Path $Root $Name
        New-Item -ItemType Directory -Path (Join-Path $h 'bin') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $h 'bin\java.exe') -Value ''
        if ($Version) { Set-Content -LiteralPath (Join-Path $h 'release') -Value "JAVA_VERSION=`"$Version`"`nIMPLEMENTOR=`"Eclipse Adoptium`"" }
        return $h
    }

    function New-FakeProc([string]$JavaHome, [string]$CommandLine) {
        [ordered]@{ Pid = 1234; Name = 'java'; User = 'APP\svc'; Service = $null
            CommandLine = $CommandLine; JavaHome = $JavaHome; JvmDll = $null; ModulesRead = $true }
    }
}

Describe 'version parsing' {
    It 'parses common formats' {
        (ConvertTo-JavaVersion '1.8.0_412') -join '.' | Should -Be '8.0.412'
        (ConvertTo-JavaVersion '"17.0.21+9-LTS"') -join '.' | Should -Be '17.0.21'
        (ConvertTo-JavaVersion '21.0.13.1') -join '.' | Should -Be '21.0.13.1'
        (ConvertTo-JavaVersion '25') -join '.' | Should -Be '25'
        ConvertTo-JavaVersion 'garbage' | Should -BeNullOrEmpty
    }
}

Describe 'affected ranges' {
    It 'handles the 17 line' {
        Status '17.0.5' | Should -Be 'not_affected'
        Status '17.0.6' | Should -Be 'affected'
        Status '17.0.21' | Should -Be 'affected'
        Status '17.0.21.1' | Should -Be 'fixed'
        Status '17.0.22' | Should -Be 'fixed'
    }
    It 'handles 21, 25, 27' {
        Status '21.0.13' | Should -Be 'affected'
        Status '21.0.13.1' | Should -Be 'fixed'
        Status '25.0.5' | Should -Be 'affected'
        Status '25.0.5.1' | Should -Be 'fixed'
        Status '27.0.1' | Should -Be 'affected'
        Status '27.0.1.1' | Should -Be 'fixed'
    }
    It 'handles unaffected, EOL and unknown' {
        Status '1.8.0_412' | Should -Be 'not_affected'
        Status '8.0.4120.8' | Should -Be 'not_affected'
        Status '11.0.25' | Should -Be 'not_affected'
        Status '23.0.2' | Should -Be 'affected'
        Status '28.0.0' | Should -Be 'unknown'
        Status '' | Should -Be 'unknown'
    }
}

Describe 'workaround flags' {
    It 'detects each workaround' {
        (Get-Mitigation @('-XX:-UseBASE64Intrinsics')).Mitigated | Should -BeTrue
        (Get-Mitigation @('-XX:UseAVX=2')).Mitigated | Should -BeTrue
        (Get-Mitigation @('-Xint')).Mitigated | Should -BeTrue
        (Get-Mitigation @('-XX:TieredStopAtLevel=1')).Mitigated | Should -BeTrue
        (Get-Mitigation @('-Xmx2g', '-XX:UseAVX=3')).Mitigated | Should -BeFalse
    }
    It 'lets the last flag win' {
        (Get-Mitigation @('-XX:-UseBASE64Intrinsics', '-XX:+UseBASE64Intrinsics')).Mitigated | Should -BeFalse
    }
    It 'applies option sources in HotSpot order' {
        $env1 = @{ JAVA_TOOL_OPTIONS = '-XX:-UseBASE64Intrinsics'; _JAVA_OPTIONS = '-XX:+UseBASE64Intrinsics' }
        (Get-Mitigation (Get-OrderedJvmArgs $env1 @() @('-jar', 'a.jar'))).Mitigated | Should -BeFalse
        $env2 = @{ JAVA_TOOL_OPTIONS = '-XX:-UseBASE64Intrinsics' }
        (Get-Mitigation (Get-OrderedJvmArgs $env2 @() @())).Mitigated | Should -BeTrue
        (Get-Mitigation (Get-OrderedJvmArgs @{} @('-Xmx1g', '-XX:-UseBASE64Intrinsics') @())).Mitigated | Should -BeTrue
    }
    It 'splits quoted Windows command lines' {
        $a = Split-CommandLine '"C:\Program Files\Java\bin\java.exe" -XX:-UseBASE64Intrinsics -jar "C:\my app\x.jar"'
        $a.Count | Should -Be 4
        $a[0] | Should -Be 'C:\Program Files\Java\bin\java.exe'
        $a[3] | Should -Be 'C:\my app\x.jar'
    }
}

Describe 'jcmd parsing' {
    It 'reads flags and version' {
        $f = ConvertFrom-JcmdFlags "     bool UseBASE64Intrinsics   = false   {ARCH product} {command line}`n     intx UseAVX  = 3  {ARCH product} {default}"
        $f.UseBASE64Intrinsics | Should -BeFalse
        $f.UseAVX | Should -Be 3
        ConvertFrom-JcmdVersion "1234:`nOpenJDK 64-Bit Server VM version 21.0.13+11-LTS`nJDK 21.0.13`n" | Should -Be '21.0.13'
    }
}

Describe 'verdicts' {
    It 'follows the matrix' {
        Get-Verdict 'affected' $true $false | Should -Be 'VULNERABLE'
        Get-Verdict 'affected' $true $true | Should -Be 'MITIGATED'
        Get-Verdict 'affected' $false $false | Should -Be 'AFFECTED_VERSION_CPU_NOT_EXPOSED'
        Get-Verdict 'fixed' $true $false | Should -Be 'OK'
        Get-Verdict 'fixed' $true $false $true | Should -Be 'RESTART_REQUIRED'
        Get-Verdict 'unknown' $true $false | Should -Be 'REVIEW'
    }
}

Describe 'installs and processes' {
    BeforeAll {
        $root = Join-Path ([IO.Path]::GetTempPath()) ("j2s-" + [guid]::NewGuid())
        $h17 = New-FakeHome $root 'opt\jdk-17.0.9' '17.0.9'
        $h21 = New-FakeHome $root 'opt\jdk-21.0.13.1' '21.0.13.1'
        $jdk8 = New-FakeHome $root 'opt\jdk1.8.0_412' '1.8.0_412'
        New-FakeHome $root 'opt\jdk1.8.0_412\jre' $null | Out-Null
    }
    AfterAll { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'finds installs under a root and drops nested JDK 8 jre' {
        $found = @(Find-JavaInstalls @($root) 6 | Where-Object { $_ -like "$root*" })
        $found.Count | Should -Be 3
        ($found -join '|') | Should -Not -Match '\\jre$'
    }
    It 'reads the parent release file for a JDK 8 jre' {
        (New-InstallRecord (Join-Path $jdk8 'jre')).Version | Should -Be '1.8.0_412'
    }
    It 'rates installs' {
        (Get-InstallAssessment (New-InstallRecord $h17) $true).Verdict | Should -Be 'VULNERABLE'
        (Get-InstallAssessment (New-InstallRecord $h17) $false).Verdict | Should -Be 'AFFECTED_VERSION_CPU_NOT_EXPOSED'
        (Get-InstallAssessment (New-InstallRecord $h21) $true).Verdict | Should -Be 'OK'
    }
    It 'rates processes from the command line' {
        $p = New-FakeProc $h17 "`"$h17\bin\java.exe`" -jar app.jar"
        (Get-ProcessAssessment $p $true @{} $false).Verdict | Should -Be 'VULNERABLE'
        $p = New-FakeProc $h17 "`"$h17\bin\java.exe`" -XX:-UseBASE64Intrinsics -jar app.jar"
        (Get-ProcessAssessment $p $true @{} $false).Verdict | Should -Be 'MITIGATED'
        $p = New-FakeProc $h17 "`"$h17\bin\java.exe`""
        (Get-ProcessAssessment $p $true @{ JAVA_TOOL_OPTIONS = '-XX:UseAVX=2' } $false).Verdict | Should -Be 'MITIGATED'
    }
    It 'flags a process whose jvm.dll was removed after an upgrade' {
        $p = New-FakeProc $h21 "`"$h21\bin\java.exe`" -jar app.jar"
        $p.JvmDll = Join-Path $root 'gone\bin\server\jvm.dll'
        (Get-ProcessAssessment $p $true @{} $false).Verdict | Should -Be 'RESTART_REQUIRED'
    }
}
