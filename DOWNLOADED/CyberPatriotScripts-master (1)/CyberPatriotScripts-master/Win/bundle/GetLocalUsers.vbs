Set accounts = GetObject("WinNT://.")
accounts.Filter = Array("user")
For Each user In accounts
  If Not exclude.Exists(user.Name) Then WScript.Echo user.Name
Next
