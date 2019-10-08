strFileName = "C:\Destination\Target%"
Set objWMIService = GetObject("winmgmts:")
Set objFileSecuritySettings = _
objWMIService.Get("Win32_LogicalFileSecuritySetting='" & strFileName & "'")
intRetVal = objFileSecuritySettings.GetSecurityDescriptor(objSD)

If intRetVal = 0 Then
WScript.Echo "The owner is: " & objSD.Owner.Domain & "\" & objSD.Owner.Name
Else
WScript.Echo "Couldn't retrieve, exiting."
End If
