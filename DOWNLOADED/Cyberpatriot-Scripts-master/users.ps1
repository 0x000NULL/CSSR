$newpass = "CyberPatriots13579";

while(1 -eq 1)
{
    $choice = Read-Host "Enter '1' for delete user, '2' for add user, and '3' for change user"
    $name = Read-Host "Enter username";
    if($choice -eq 1)
    {        
        iex "net user $name /delete";
    }
    elseif($choice -eq 2)
    {
        iex "net user $name $newpass /add";
        $admin = Read-Host "Make user an admin? (y=yes, n=no)";
        if($admin -eq "y")
        {
            iex "net localgroup Administrators $name /add"; 
        }
    }
    elseif($choice -eq 3)
    {
        $u = $name;
        $admin = $null;
        $admin = (net localgroup administrators | Where{$_-match $u});
        $choice = Read-Host "What would you like to change? (1 = Password, 2 = Admin Status, 3 = Both"

        if($choice -eq 1)
        {
            iex "net user $name $newpass"
            Write-Output "Password set to $newpass"
        }
        elseif($choice -eq 2)
        {
            if($admin -ne $null)
            {
                iex "net localgroup Administrators $name /delete"
            }
            else
            {
                iex "net localgroup Administrators $name /add"
            }
        }
        elseif($choice -eq 3)
        {
            iex "net user $name $newpass"
            Write-Output "Password set to $newpass"

            if($admin -ne $null)
            {
                iex "net localgroup Administrators $name /delete"
            }
            else
            {
                iex "net localgroup Administrators $name /add"
            }
        }
    }
}