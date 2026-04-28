# OSEP - AD Enumeration (pure .NET LDAP, no extra tools needed)
# . .\ad_enum.ps1
# Invoke-ADEnum             ← full dump
# Invoke-ADEnum -query users|computers|groups|admins|spns|gpos|trusts

$LOG = "C:\Windows\Temp\osep_log.txt"
function wl($m,$l="INFO"){try{Add-Content $LOG "[$((Get-Date).ToString('HH:mm:ss'))][ADEnum][$l] $m" -EA SilentlyContinue}catch{}}

function Get-LDAPResults {
    param([string]$filter, [string[]]$props)

    $domain  = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root    = "LDAP://$($domain.PdcRoleOwner.Name)/$($domain.GetDirectoryEntry().distinguishedName)"
    wl "LDAP root: $root  filter: $filter"

    $searcher            = New-Object DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($root)
    $searcher.Filter     = $filter
    $searcher.PageSize   = 1000
    foreach ($p in $props) { $searcher.PropertiesToLoad.Add($p) | Out-Null }

    try {
        $results = $searcher.FindAll()
        wl "Got $($results.Count) results"
        return $results
    } catch {
        wl "LDAP search failed: $_" "ERROR"
        Write-Host "[-] LDAP error: $_"
        return @()
    }
}

function Enum-Users {
    Write-Host "`n[*] == Domain Users =="
    $r = Get-LDAPResults '(&(objectClass=user)(objectCategory=person))' @('samaccountname','description','memberof','lastlogon','pwdlastset','useraccountcontrol')
    foreach ($obj in $r) {
        $p = $obj.Properties
        $uac = [int]$p['useraccountcontrol'][0]
        $noExpire  = ($uac -band 0x10000) -ne 0
        $disabled  = ($uac -band 0x2)     -ne 0
        Write-Host "  $($p['samaccountname'][0])  $(if($disabled){'[DISABLED]'})  $(if($noExpire){'[NOEXPIRE]'})  desc=$($p['description'])"
    }
    wl "Users enumerated: $($r.Count)"
}

function Enum-Computers {
    Write-Host "`n[*] == Domain Computers =="
    $r = Get-LDAPResults '(objectClass=computer)' @('dnshostname','operatingsystem','operatingsystemversion')
    foreach ($obj in $r) {
        $p = $obj.Properties
        Write-Host "  $($p['dnshostname'][0])  OS=$($p['operatingsystem'][0]) $($p['operatingsystemversion'][0])"
    }
    wl "Computers enumerated: $($r.Count)"
}

function Enum-Groups {
    Write-Host "`n[*] == Domain Groups =="
    $r = Get-LDAPResults '(objectClass=group)' @('name','member','description')
    foreach ($obj in $r) {
        $p = $obj.Properties
        Write-Host "  $($p['name'][0])  members=$($p['member'].Count)  desc=$($p['description'])"
    }
    wl "Groups enumerated: $($r.Count)"
}

function Enum-Admins {
    Write-Host "`n[*] == Domain Admins =="
    $r = Get-LDAPResults '(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)(name=Administrators)))' @('name','member')
    foreach ($obj in $r) {
        $p = $obj.Properties
        Write-Host "  Group: $($p['name'][0])"
        foreach ($m in $p['member']) { Write-Host "    $m" }
    }
    wl "Admin groups enumerated"
}

function Enum-SPNs {
    Write-Host "`n[*] == Kerberoastable SPNs =="
    $r = Get-LDAPResults '(&(objectClass=user)(servicePrincipalName=*))' @('samaccountname','serviceprincipalname','memberof')
    foreach ($obj in $r) {
        $p = $obj.Properties
        Write-Host "  $($p['samaccountname'][0])"
        foreach ($spn in $p['serviceprincipalname']) { Write-Host "    SPN: $spn" }
    }
    wl "SPNs enumerated: $($r.Count)"
}

function Enum-Trusts {
    Write-Host "`n[*] == Domain Trusts =="
    try {
        $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($t in $d.GetAllTrustRelationships()) {
            Write-Host "  $($t.SourceName) → $($t.TargetName)  Direction=$($t.TrustDirection)  Type=$($t.TrustType)"
        }
    } catch {
        wl "Trust enum failed: $_" "WARN"
        Write-Host "  (no trusts or insufficient rights)"
    }
}

function Invoke-ADEnum {
    param(
        [ValidateSet('users','computers','groups','admins','spns','trusts','all')]
        [string]$query = 'all'
    )
    wl "=== ADEnum started. Query=$query ==="
    switch ($query) {
        'users'     { Enum-Users }
        'computers' { Enum-Computers }
        'groups'    { Enum-Groups }
        'admins'    { Enum-Admins }
        'spns'      { Enum-SPNs }
        'trusts'    { Enum-Trusts }
        'all'       { Enum-Users; Enum-Computers; Enum-Groups; Enum-Admins; Enum-SPNs; Enum-Trusts }
    }
    wl "=== ADEnum complete ==="
}
