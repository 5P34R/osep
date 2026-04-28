#!/usr/bin/env python3
"""
OSEP - Universal encoder for any payload.
Usage:
  python3 invoke_encode.py b64   input.ps1          # Base64 UTF-16LE (-enc compatible)
  python3 invoke_encode.py xor   input.bin  0x41    # XOR single-byte
  python3 invoke_encode.py hex   input.bin           # hex dump
  python3 invoke_encode.py ps1b64 input.ps1          # print ready powershell -enc command
"""
import sys, base64, os

def b64_utf16le(data: bytes) -> str:
    if data[:2] not in (b'\xff\xfe', b'\xfe\xff'):
        data = data.decode('utf-8', errors='replace').encode('utf-16-le')
    return base64.b64encode(data).decode()

def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)

    mode, infile = sys.argv[1], sys.argv[2]

    if not os.path.isfile(infile):
        print(f"[!] Not found: {infile}"); sys.exit(1)

    raw = open(infile, 'rb').read()

    if mode == 'b64':
        print(base64.b64encode(raw).decode())

    elif mode == 'ps1b64':
        enc = b64_utf16le(raw)
        print(f"powershell -nop -ep bypass -w hidden -enc {enc}")

    elif mode == 'xor':
        key = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x41
        out = xor(raw, key)
        # Print as PowerShell byte array
        print(','.join(f'0x{b:02X}' for b in out))

    elif mode == 'hex':
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            h = ' '.join(f'{b:02x}' for b in chunk)
            a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f'{i:06x}  {h:<48}  {a}')

    else:
        print(f"Unknown mode: {mode}"); sys.exit(1)

main()
