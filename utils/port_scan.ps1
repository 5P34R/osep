# OSEP - PowerShell TCP Port Scanner
# . .\port_scan.ps1
# Invoke-PortScan -target 10.10.10.5 -ports 22,80,135,139,443,445,1433,3389,5985,8080
# Invoke-PortScan -target 10.10.10.0/24 -ports 445,3389    (subnet sweep)
# Invoke-PortScan -target 10.10.10.5 -range 1-1024

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][Scan][$l] $m" -EA SilentlyContinue}catch{}}

function Test-TcpPort {
    param([string]$host, [int]$port, [int]$timeout = 500)
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($host, $port, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne($timeout, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.Close(); return $true
        }
        $tcp.Close(); return $false
    } catch { return $false }
}

function Expand-CIDR {
    param([string]$cidr)
    $parts = $cidr.Split('/')
    $ip    = [Net.IPAddress]::Parse($parts[0])
    $mask  = [int]$parts[1]
    $base  = [BitConverter]::ToUInt32($ip.GetAddressBytes()[3..0], 0)
    $count = [Math]::Pow(2, 32 - $mask) - 2
    $hosts = @()
    for ($i = 1; $i -le $count; $i++) {
        $bytes = [BitConverter]::GetBytes([uint32]($base + $i))
        $hosts += "$($bytes[3]).$($bytes[2]).$($bytes[1]).$($bytes[0])"
    }
    return $hosts
}

function Invoke-PortScan {
    param(
        [Parameter(Mandatory)][string]$target,
        [int[]]$ports,
        [string]$range,        # e.g. "1-1024"
        [int]$timeout = 500,
        [int]$threads = 50
    )

    # Build port list
    if ($range) {
        $a, $b = $range.Split('-') | ForEach-Object { [int]$_ }
        $ports  = $a..$b
    }
    if (-not $ports) {
        $ports = @(21,22,23,25,53,80,110,135,139,143,389,443,445,
                   636,1433,1521,3306,3389,5432,5985,5986,6379,8080,8443,9200)
        Write-Host "[*] Using default common ports"
    }

    # Build host list
    $hosts = if ($target -match '/\d+$') { Expand-CIDR $target } else { @($target) }

    wl "Scan: $($hosts.Count) host(s), $($ports.Count) port(s)"
    Write-Host "[*] Scanning $($hosts.Count) host(s) × $($ports.Count) port(s) (timeout=${timeout}ms)"

    $open = @()

    foreach ($h in $hosts) {
        $jobs = @()

        foreach ($p in $ports) {
            # Throttle parallelism via runspaces
            $rs = [RunspaceFactory]::CreateRunspace()
            $rs.Open()
            $ps = [PowerShell]::Create()
            $ps.Runspace = $rs

            [void]$ps.AddScript({
                param($hh,$pp,$tt)
                try {
                    $c = New-Object Net.Sockets.TcpClient
                    $r = $c.BeginConnect($hh,$pp,$null,$null)
                    $ok= $r.AsyncWaitHandle.WaitOne($tt,$false)
                    if($ok -and $c.Connected){$c.Close();return "$hh`:$pp OPEN"}
                    $c.Close()
                } catch {}
            }).AddArgument($h).AddArgument($p).AddArgument($timeout)

            $jobs += @{ ps=$ps; rs=$rs; ia=$ps.BeginInvoke() }

            # Flush when thread pool is full
            if ($jobs.Count -ge $threads) {
                foreach ($j in $jobs) {
                    $res = $j.ps.EndInvoke($j.ia)
                    if ($res) { Write-Host "[+] $res"; $open += $res; wl $res }
                    $j.ps.Dispose(); $j.rs.Close()
                }
                $jobs = @()
            }
        }

        # Flush remainder
        foreach ($j in $jobs) {
            $res = $j.ps.EndInvoke($j.ia)
            if ($res) { Write-Host "[+] $res"; $open += $res; wl $res }
            $j.ps.Dispose(); $j.rs.Close()
        }
    }

    Write-Host "`n[*] Open ports ($($open.Count)):"
    $open | ForEach-Object { Write-Host "  $_" }
    wl "Scan complete. $($open.Count) open"
}
