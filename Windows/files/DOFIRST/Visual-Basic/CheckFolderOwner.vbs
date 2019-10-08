strFolderName = "C:\Destination\Target%"
Set objWMIService = GetObject("winmgmts:")
Set objFolderSecuritySettings = _
objWMIService.Get("Win32_LogicalFileSecuritySetting='" & strFolderName & "'")
intRetVal = objFolderSecuritySettings.GetSecurityDescriptor(objSD)

If intRetVal = 0 Then
WScript.Echo "Owner: " & objSD.Owner.Domain & "\" & objSD.Owner.Name
Else
WScript.Echo "Couldn't retrieve. exiting."
End If
