<#
.DESCRIPTION
    A set of Windows Firewall tools to create PowerShell firewall commands or to import/export rules to/from group policy objects. It contains blocked connection scanning and
    navigation between Windows Forms via a back button (BackButton). 
.NOTES
    ExportExistingRulesToPowerShellCommands
        If a policy is created from the output of this script and that policy is linked to the same OU as the source policy the link order will determine which rule is applied.
        Because the GUID is copied from the source they are not unique across policies, under normal conditions both rules with the same display name would be applied but
        because they conflict the policy higher in the link order will have it's rule applied and that will overwrite the lower policy rule.
    Build 1811.1
#>

class WindowsFirewallRule
{
    [string] $PolicyStore
    [string] $Name
    [string] $DisplayName
    [string] $Description
    [string] $Group 
    [ValidateSet("True", "False")]
    [String] $Enabled = $true
    [ValidateSet("Any", "Domain", "Private", "Public")]
    [System.collections.arraylist] $Profile  = @("Any")
    [ValidateSet("Inbound", "Outbound")]
    [string] $Direction = "Inbound"
    [ValidateSet("Allow", "Block")]
    [string] $Action = "Allow"
    [System.collections.arraylist] $LocalAddress  = @("Any")
    [System.collections.arraylist] $RemoteAddress  = @("Any")
    [string] $Protocol = "Any"
    [System.collections.arraylist] $LocalPort  = @("Any")
    [System.collections.arraylist] $RemotePort  = @("Any")
    [string] $Program = "Any"
    [string] $Package = "Any"
    [string] $Service = @("Any")
    [Object] Clone()
    {
        $ClonedObject = $this.MemberwiseClone()
        foreach ($Name in ($this| Get-Member).Where({$_.Definition -like "System.Collections.*"}).Name)
        { # Clone (deep copy) objects within an object
            $ClonedObject.$Name = $this.$Name.Clone()
        }
        return $ClonedObject
    }
}
    
function DefaultDomainResources ($DefaultDomainResourcesStatusBar)
{
    # Version 0.7.0 domain resources
    $DomainControllers = "127.0.0.1","SERVERNAME"
    $ProxyServerPorts = "8080"
    $ProxyServers = "LocalSubnet","Intranet"
    $DnsServers = $DomainControllers # Specify these if you do not have DNS on each domain controller or you have additional DNS servers
    $CrlServers = "LocalSubnet","Intranet"
    $Wpad_PacFileServers = "LocalSubnet","Intranet"
    $TierXManagementServers = "LocalSubnet","Intranet" # These are used in tier X firewall baselines to define which computers can manage the device at a particular tier
    $SqlServers = "127.0.0.4"
    $WebServers = "LocalSubnet","Intranet"
    $FileServers = "LocalSubnet","Intranet"
    $KeyManagementServers = "LocalSubnet","Intranet"
    $BackupServers = "127.0.0.1"
    $ClusteredNodesAndManagementAddresses = "LocalSubnet","Intranet"
    $ExternalVpnEndpoints = "127.0.0.2 -  127.0.0.3" # This is the externally resolvable IPSec hostname or address
    $DirectAccessServers = "127.0.0.128/25" # This is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint
    $TrustedDhcpSubnets = "Any" # This is client enterprise subnets and includes subnets issued by the VPN server, "Predefined set of computers" cannot be used here
    # END of version 0.7.0 domain resources
    # Version 0.8.0 domain resources
    $ServerRoleAdministrationServers = "LocalSubnet","Intranet" # These are trusted machines used by tier administrators permitted to administer a server role
    # END of version 0.8.0 domain resources
    # Version 0.9.0 domain resources
    $MicrosoftSubnets += "13.64.0.0 - 13.107.255.255", "40.64.0.0 - 40.71.255.255", "40.74.0.0 - 40.125.127.255", "52.132.0.0 - 52.143.255.255", "52.145.0.0 - 52.191.255.255", "64.4.0.0 - 64.4.63.255", "65.52.0.0 - 65.55.255.255", "104.40.0.0 - 104.47.255.255", "111.221.64.0 - 111.221.127.255", "131.253.61.0 - 131.253.255.255", "134.170.0.0 - 134.170.255.255", "137.117.0.0 - 137.117.255.255", "157.54.0.0 - 157.60.255.255", "207.46.0.0 - 207.46.255.255"
    # END of version 0.9.0 domain resources

    $Resources = "DomainControllers","ProxyServers","DnsServers","CrlServers","Wpad_PacFileServers","TierXManagementServers","SqlServers","WebServers","FileServers","KeyManagementServers","BackupServers","ClusteredNodesAndManagementAddresses","ExternalVpnEndpoints","DirectAccessServers","TrustedDhcpSubnets","ServerRoleAdministrationServers", "MicrosoftSubnets"
    $InitialStatusBarText = $DefaultDomainResourcesStatusBar.Text
    foreach ($Resource in $Resources)
    {
        $DefaultDomainResourcesStatusBar.Text = "$($Language[36]) $Resource"
        $Addresses = @()
        foreach ($Name in (Get-Variable -Name $Resource).Value.replace(" ",""))
        {
            switch -Wildcard ($Name)
            {
                "*/*"
                { # A forward slash indicates a subnet has been specified
                    $Addresses += $Name
                    break
                }
                "LocalSubnet"
                {
                    $Addresses += $Name
                    break
                }
                "Intranet"
                {
                    $Addresses += $Name
                    break
                }
                "DNS"
                {
                    $Addresses += $Name
                    break
                }
                "DHCP"
                {
                    $Addresses += $Name
                    break
                }
                "DefaultGateway"
                {
                    $Addresses += $Name
                    break
                }
                "Internet"
                {
                    $Addresses += $Name
                    break
                }
                "Any"
                {
                    $Addresses += $Name
                    break
                }
                "*-*"
                {
                    try
                    {
                        if ([ipaddress]$Name.Split("-")[0] -and [ipaddress]$Name.Split("-")[1])
                        { # If each side of the hyphen is an IP address then a range has been specified
                            $Addresses += $Name
                        }
                    }
                    catch [Management.Automation.PSInvalidCastException]
                    {
                        $Addresses += AttemptResolveDnsName $Name
                    }
                }
                default
                {
                    try
                    {
                        if ([ipaddress]$Name)
                        {
                            $Addresses += $Name
                        }
                    }
                    catch [Management.Automation.PSInvalidCastException]
                    {
                        $Addresses += AttemptResolveDnsName $Name
                    }
                }
            }
        }
        if (-not $Addresses)
        {
            $Addresses = @("127.0.0.1")
        }
        New-Variable -Name $Resource -Value ([System.Collections.ArrayList]$Addresses) -Scope "Script"
    }
    $Ports = @()
    foreach ($ProxyServerPort in $ProxyServerPorts)
    {
        try
        {
            $ProxyServerPort = $ProxyServerPort.replace(" ", "")
            if ($ProxyServerPort -like "*-*" -and (($ProxyServerPort).Split("-").Count -eq 2))
            {
                if (([int]($ProxyServerPort).Split("-")[0] -in 1..65535) -and ([int]($ProxyServerPort).Split("-")[1] -in 1..65535) -and ([int]($ProxyServerPort).Split("-")[0] -lt [int]($ProxyServerPort).Split("-")[1]))
                {
                    $Ports += $ProxyServerPort
                }
                else
                {
                    PopUpMessage -Message ($ProxyServerPort + $Language[38])
                }
            }
            elseif ([int]$ProxyServerPort -in 1..65535)
            {
                $Ports += $ProxyServerPort
            }
            else
            {
                PopUpMessage -Message ($ProxyServerPort + $Language[38])
            }
        }
        catch
        {
            PopUpMessage -Message ($ProxyServerPort + $Language[38])
        }
    }
    if (-not $Ports)
    {
        $Ports = @("Any")
    }
    New-Variable -Name "ProxyServerPorts" -Value ([System.Collections.ArrayList]$Ports) -Scope "Script"
    [System.Collections.ArrayList]$Script:ResourcesAndProxyPorts = $Resources + "ProxyServerPorts"| Sort-Object
    [System.Collections.ArrayList]$Script:Resources = $Resources| Sort-Object
    $DefaultDomainResourcesStatusBar.Text = $InitialStatusBarText
}

function GroupPoliciesWithExistingFirewallRules ($GroupPoliciesWithExistingFirewallRulesStatusBar)
{
    $GroupPolicyObjects = (Get-GPO -All).DisplayName
    foreach ($GroupPolicyObject in $GroupPolicyObjects)
    {
        $GroupPolicyObjectIndex ++
        if (Get-NetFirewallRule -PolicyStore "$DomainName\$GroupPolicyObject" -ErrorAction SilentlyContinue)
        {
            $ProgressBar.Value = ($GroupPolicyObjectIndex * ($OneHundredPercent/$GroupPolicyObjects.Count))
            $GroupPoliciesWithExistingFirewallRulesStatusBar.Text = "$($Language[35]) $GroupPolicyObject"
            [string[]]$Script:GroupPoliciesWithExistingFirewallRules += $GroupPolicyObject
        }
    }
    Remove-Variable -Name "GroupPolicyObjectIndex" -Force
    $Script:GroupPoliciesWithExistingFirewallRules = $Script:GroupPoliciesWithExistingFirewallRules| Sort-Object
}

function PopUpMessage ($Message) # Need to use `r`n for newline
{
    $PopUpMessageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        StartPosition = "CenterParent"
        MinimumSize = @{
            Width = 150
            Height = 100
        }
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
        AutoScroll = $true
    }
    $PopUpMessageBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $PopUpMessageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $PopUpMessageAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "OK"
        Anchor = "Right"
    }
    $PopUpMessageAcceptButton.Add_Click(
    {
        $PopUpMessageForm.Close()
    })
    $PopUpMessageAcceptButton.Left = $PopUpMessageBottomButtonPanel.Width - $PopUpMessageAcceptButton.Width - 5
    $PopUpMessageForm.CancelButton = $PopUpMessageAcceptButton
    $PopUpMessageForm.AcceptButton = $PopUpMessageAcceptButton
    $PopUpMessageTextBox = New-Object -TypeName "System.Windows.Forms.TextBox" -Property @{
        Multiline = $true
        BackColor = "GhostWhite"
        ReadOnly = $true
        Text = $Message
        MinimumSize = @{
            Width = 141
            Height = 70
        }
        MaximumSize = @{
            Width = 500
            Height = 500
        }
    }
    $PopUpMessageTextBox.Size = $PopUpMessageTextBox.PreferredSize
    $PopUpMessageForm.Width = $PopUpMessageTextBox.Width + 9
    $PopUpMessageForm.Height = $PopUpMessageTextBox.Height + 30
    $PopUpMessageBottomButtonPanel.Controls.Add($PopUpMessageAcceptButton)
    $PopUpMessageForm.Controls.Add($PopUpMessageBottomButtonPanel)
    $PopUpMessageForm.Controls.Add($PopUpMessageTextBox)
    [void]$PopUpMessageForm.ShowDialog()
}

function CancelAccept ($Message,$CancelButtonText,$AcceptButtonText) # Need to use `r`n for newline
{
    $CancelAcceptForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        StartPosition = "CenterParent"
        MinimumSize = @{
            Width = 200
            Height = 100
        }
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
        KeyPreview = $true
    }
    $CancelAcceptForm.Add_Shown(
    {
        $CancelAcceptAcceptButton.Focus()
    })
    $CancelAcceptForm.Add_KeyPress(
    {
        if ($_.KeyChar -eq "y")
        {
            $CancelAcceptAcceptButton.PerformClick()
        }
        elseif ($_.KeyChar -eq "n")
        {
            $CancelAcceptCancelButton.PerformClick()
        }
    })
    $CancelAcceptBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $CancelAcceptForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $CancelAcceptCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $CancelButtonText
        Anchor = "Right"
    }
    $CancelAcceptCancelButton.Left = $CancelAcceptBottomButtonPanel.Width - $CancelAcceptCancelButton.Width - 5
    $CancelAcceptAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $AcceptButtonText
        Anchor = "Right"
        DialogResult = "OK"
    }
    $CancelAcceptAcceptButton.Left = $CancelAcceptCancelButton.Left - $CancelAcceptAcceptButton.Width - 5
    $CancelAcceptForm.CancelButton = $CancelAcceptCancelButton
    $CancelAcceptForm.AcceptButton = $CancelAcceptAcceptButton
    $CancelAcceptTextBox = New-Object -TypeName "System.Windows.Forms.TextBox" -Property @{
        Multiline = $true
        BackColor = "GhostWhite"
        ReadOnly = $true
        Text = $Message
        MinimumSize = @{
            Width = 191
            Height = 70}
        }
    $CancelAcceptTextBox.Size = $CancelAcceptTextBox.PreferredSize
    $CancelAcceptForm.Width = $CancelAcceptTextBox.Width + 9
    $CancelAcceptForm.Height = $CancelAcceptTextBox.Height + 30
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptCancelButton)
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptAcceptButton)
    $CancelAcceptForm.Controls.Add($CancelAcceptBottomButtonPanel)
    $CancelAcceptForm.Controls.Add($CancelAcceptTextBox)
    return $CancelAcceptForm.ShowDialog() 
}

function UpdateDataSourceForComboBoxCell ($ArrayList,$DataGridView)
{
    $ComboBoxColumns = ($DataGridView.Columns.Where({$_.CellType.Name -eq "DataGridViewComboBoxCell"})).Name
    for ($Row = 0; $Row -lt $DataGridView.Rowcount; $Row++)
    {
        foreach ($ComboBoxColumn in $ComboBoxColumns)
        {
            $DataGridView.rows[$Row].Cells[$ComboBoxColumn].DataSource = $ArrayList[$Row].$ComboBoxColumn
            $DataGridView.rows[$Row].Cells[$ComboBoxColumn].DropDownWidth = (($DataGridView.rows[$Row].Cells[$ComboBoxColumn].DataSource).ForEach({$_.Length})| Sort-Object -Descending| Select-Object -First 1) * $DropDownWidthMultiplier
            $DataGridView.rows[$Row].Cells[$ComboBoxColumn].Value = $ArrayList[$Row].$ComboBoxColumn[0]
        } 
    }
}

function AttemptResolveDnsName ($Name)
{
    try
    {
        return (Resolve-DnsName $Name -ErrorAction Stop).IPAddress
    }
    catch
    {
        PopUpMessage -Message ($Name + $Language[37])
    }
}

function SelectAll ($Control)
{
    if ($_.KeyData -eq "A, Control")
    {
        $_.SuppressKeyPress = $true
        $Control.BeginUpdate()
        for ($i = 0; $i -lt $Control.Items.Count; $i++)
        {
            $Control.SetSelected($i, $true)
        }
        $Control.EndUpdate()
    }
}

function ResetDataSource ($ResetDataSourceData) # The data object can be a combobox cell or a listbox
{ 
    $ResetDataSourceDataSource = $ResetDataSourceData.DataSource  
    if ($ResetDataSourceData.Value)
    {
        $ResetDataSourceData.Value = $ResetDataSourceData.DataSource| Select-Object -Last 1
        $ResetDataSourceData.DataSource = [System.Collections.ArrayList]@($ResetDataSourceData.Value) # Rather than setting the data source to $null set it to a temporary valid value to prevent errors
        $ResetDataSourceData.DataSource = $ResetDataSourceDataSource
        $ResetDataSourceData.DropDownWidth = (($ResetDataSourceData.DataSource).ForEach({$_.Length})| Sort-Object -Descending| Select-Object -First 1) * $DropDownWidthMultiplier
    }
    else
    {
        $ResetDataSourceData.DataSource = $null
        $ResetDataSourceData.DataSource = $ResetDataSourceDataSource
    }
}

function AddResource ($AddResourceProperty,$AddResourceValues)
{
    function AnyResource
    {
        foreach ($AddResourceValue in $AddResourceValues)
        {
            if ("Any" -in $AddResourceValue.Items)
            {
                PopUpMessage -Message "`"Any`" is already in the list."
            }
            else
            {
                if ((CancelAccept -Message "All other items in the list will be`r`nremoved, do you want to continue?" -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "OK")
                {
                    $AddResourceValue.DataSource.Clear()
                    $AddResourceTextBox.Text = "Any" # This will be used to set the value in the data source.
                    $AddResourceValue.DataSource.Add($AddResourceTextBox.Text)
                    ResetDataSource -ResetDataSourceData $AddResourceValue
                }
            }
        }
    }
    $AddResourceForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        StartPosition = "CenterParent"
        Width = 280
        Height = 140
        Text = "Add resource"
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
    }
    $AddResourceBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $AddResourceForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $AddResourceCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[26]
        Anchor = "Right"
    } # This is not the default cancel button because the form size is different to the tool form?
    $AddResourceCancelButton.Left = $AddResourceBottomButtonPanel.Width - $AddResourceCancelButton.Width - 5
    $AddResourceAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Add"
        Anchor = "Right"
    } 
    $AddResourceAcceptButton.Left = $AddResourceCancelButton.Left - $AddResourceAcceptButton.Width - 5
    $AddResourcePanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $AddResourceForm.Width - 16
        Height = $AddResourceForm.Height - 60
    }
    $AddResourceTextBox = New-Object -TypeName "System.Windows.Forms.TextBox" -Property @{
        width = $AddResourcePanel.Width - 20
        Location = @{
            X = 10
            Y= 5
        }
    }
    $AddResourceLabel = New-Object -TypeName "System.Windows.Forms.Label" -Property @{
        TextAlign = "MiddleLeft"
        width = 80
        Height = 20
        Location = @{
            X = 12
            Y = $AddResourcePanel.Height - 50
        }
        Text= "Resource type:"
    }
    if ($AddResourceProperty -in "LocalPort", "ProxyServerPorts", "RemotePort")
    {
        $AddResourceAcceptButton.Add_Click(
        {
            function AddResourceValue ($AddResourceValueSource)
            {
                foreach ($AddResourceValue in $AddResourceValues)
                {
                    if ($AddResourceValueSource -in $AddResourceValue.Items)
                    {
                        PopUpMessage -Message "`"$($AddResourceValueSource)`" is already in the list."
                    }
                    else
                    {
                        $AddResourceValue.DataSource.Add($AddResourceValueSource)
                        ResetDataSource -ResetDataSourceData $AddResourceValue
                    }
                }
                foreach ($AddResourceValue in $AddResourceValues)
                {
                    if ("Any" -in $AddResourceValue.Items -and $AddResourceValue.Items.Count -gt 1)
                    {
                        $AddResourceValue.DataSource.Remove("Any")
                        ResetDataSource -ResetDataSourceData $AddResourceValue
                    }
                }
            }
            if ($AddResourceComboBox1.SelectedItem -eq "Any")
            {
                AnyResource
            }
            elseif ($AddResourceComboBox1.SelectedItem -eq "Proxy server ports")
            {
                foreach ($ProxyServerPort in $ProxyServerPorts)
                {
                    AddResourceValue -AddResourceValueSource $ProxyServerPort
                }
            }
            else
            {
                try
                {
                    $TextBoxValue = $AddResourceTextBox.Text.replace(" ", "")
                    if ($TextBoxValue -like "*-*" -and (($TextBoxValue).Split("-").Count -eq 2))
                    {
                        if (([int]($TextBoxValue).Split("-")[0] -in 1..65535) -and ([int]($TextBoxValue).Split("-")[1] -in 1..65535) -and ([int]($TextBoxValue).Split("-")[0] -lt [int]($TextBoxValue).Split("-")[1]))
                        {
                            AddResourceValue -AddResourceValueSource $TextBoxValue
                        }
                        else
                        {
                            PopUpMessage -Message "Invalid input."
                        }
                    }
                    elseif ([int]$TextBoxValue -in 1..65535)
                    {
                        AddResourceValue -AddResourceValueSource $TextBoxValue
                    }
                    else
                    {
                        PopUpMessage -Message "Invalid input."
                    }
                }
                catch
                {
                    PopUpMessage -Message "Invalid input."
                }
            }
        })
        $AddResourceComboBox1 = New-Object -TypeName "System.Windows.Forms.ComboBox" -Property @{
            width = 155
            Location = @{
                X = $AddResourcePanel.Width - 165
                Y = $AddResourcePanel.Height - 50
            }
            BackColor = "WhiteSmoke"
            DropDownStyle = "DropDownList"
        }
        $AddResourceComboBox1.DataSource = @("Port number", "Proxy server ports", "Any")
        $AddResourceComboBox1.Add_SelectedValueChanged(
        {
            switch ($AddResourceComboBox1.SelectedItem)
            {
                "Any"
                {
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourceStatusBar.Text = "Add `"Any IP address.`" "
                    break
                }
                "Proxy server ports"
                {   
                    if ($null -eq $DomainControllers)
                    {
                        DefaultDomainResources -DefaultDomainResourcesStatusBar $AddResourceStatusBar
                    }
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourceStatusBar.Text = "Add proxy server ports."
                    break
                }
                "Port number"
                {
                    $AddResourceTextBox.Text = ""
                    $AddResourcePanel.Controls.Add($AddResourceTextBox)
                    $AddResourceStatusBar.Text = "Enter a port number or range from 1 to 65535."
                    $AddResourceTextBox.Focus()
                }
            }
        })
        $AddResourceStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a port number or range from 1 to 65535."
        }
    }
    else
    {
        $AddResourceAcceptButton.Add_Click(
        {
            switch ($AddResourceComboBox1.SelectedItem)                                                                                                                                                                                                                                                                                                                                                                                                                {
            "Any"
            {
                AnyResource
                break
            }
            "Microsoft subnets"
            {
                foreach ($AddResourceValue in $AddResourceValues)
                {
                    if ($AddResourceComboBox2.SelectedValue -in $AddResourceValue.Items)
                    {
                        PopUpMessage -Message "`"$($AddResourceComboBox2.SelectedValue)`" is already in the list."
                    }
                    else
                    {
                        $AddResourceValue.DataSource.Add($AddResourceComboBox2.SelectedValue)
                        $AddResourceTextBox.Text = $AddResourceComboBox2.SelectedValue
                        ResetDataSource -ResetDataSourceData $AddResourceValue  
                    }
                }
                break
            }
            "Predefined set of computers"
            {
                foreach ($AddResourceValue in $AddResourceValues)
                {
                    if ($AddResourceComboBox2.SelectedValue -in $AddResourceValue.Items)
                    {
                        PopUpMessage -Message "`"$($AddResourceComboBox2.SelectedValue)`" is already in the list."
                    }
                    else
                    {
                        $AddResourceValue.DataSource.Add($AddResourceComboBox2.SelectedValue)
                        $AddResourceTextBox.Text = $AddResourceComboBox2.SelectedValue
                        ResetDataSource -ResetDataSourceData $AddResourceValue  
                    }
                }
                break
            }
            "Domain resource"
            {
                foreach ($Value in (Get-Variable -Name $AddResourceComboBox2.SelectedValue).Value)
                {
                    foreach ($AddResourceValue in $AddResourceValues)
                    {
                        if ($Value -in $AddResourceValue.Items)
                        {
                            PopUpMessage -Message "`"$Value`" is already in the list."
                        }
                        else
                        {
                            $AddResourceValue.DataSource.Add($Value)
                        }
                        ResetDataSource -ResetDataSourceData $AddResourceValue
                    }  
                }
                break
            }
            "Computer name/IP address"
            {
                foreach ($AddResourceValue in $AddResourceValues)
                {
                    $TextBoxValue = $AddResourceTextBox.Text.replace(" ", "")
                    switch -Wildcard ($TextBoxValue)
                    {
                        "*/*"   { # A forward slash indicates a subnet has been specified, the subnet is not being validated in this build.
                                    if ($TextBoxValue -in $AddResourceValue.Items)
                                    {
                                        PopUpMessage -Message "$TextBoxValue is already in the list."
                                        break
                                    }
                                    else
                                    {
                                        $AddResourceValue.DataSource.Add($TextBoxValue)
                                        break
                                    }
                                }
                        "*-*"   {
                                    try
                                    { # If each side of the hyphen is an IP address then a range has been specified
                                        if ([ipaddress]$TextBoxValue.Split("-")[0] -and [ipaddress]$TextBoxValue.Split("-")[1])
                                        { 
                                            if ($TextBoxValue -in $AddResourceValue.Items)
                                            {
                                                PopUpMessage -Message "$TextBoxValue is already in the list."
                                                break
                                            }
                                            else
                                            {
                                                $AddResourceValue.DataSource.Add($TextBoxValue)
                                                break
                                            }
                                        }
                                    }
                                    catch [Management.Automation.PSInvalidCastException]
                                    {
                                        $IpAddresses = AttemptResolveDnsName -Name $TextBoxValue
                                    }
                                }
                        default {
                                    try
                                    {
                                        if ([ipaddress]$TextBoxValue)
                                        {
                                            $IpAddresses = $TextBoxValue
                                        }
                                    }
                                    catch [Management.Automation.PSInvalidCastException]
                                    {
                                        $IpAddresses = AttemptResolveDnsName -Name $TextBoxValue
                                    }
                                }
                    }
                    if ($IpAddresses)
                    {
                        foreach ($IpAddress in $IpAddresses)
                        {
                            if ($IpAddress -in $AddResourceValue.Items)
                            {
                                PopUpMessage -Message "$IpAddress is already in the list."
                            }
                            else
                            {
                                $AddResourceValue.DataSource.Add($IpAddress)
                            }
                        }
                    }
                    ResetDataSource -ResetDataSourceData $AddResourceValue
                }
            }
        }
            foreach ($AddResourceValue in $AddResourceValues)
            {
                if ("Any" -in $AddResourceValue.Items -and $AddResourceValue.Items.Count -gt 1)
                {
                    $AddResourceValue.DataSource.Remove("Any")
                    ResetDataSource -ResetDataSourceData $AddResourceValue
                }
            }
        })
        $AddResourceComboBox1 = New-Object -TypeName "System.Windows.Forms.ComboBox" -Property @{
            width = 155
            Location = @{
                X = $AddResourcePanel.Width - 165
                Y = $AddResourcePanel.Height - 50
            }
            BackColor = "WhiteSmoke"
            DropDownStyle = "DropDownList"
        }
        $AddResourceComboBox1.DataSource = @("Computer name/IP address", "Domain resource", "Predefined set of computers", "Microsoft subnets", "Any")
        $AddResourceComboBox1.Add_SelectedValueChanged(
        {
            switch ($AddResourceComboBox1.SelectedItem)
            {
                "Any"
                {
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourcePanel.Controls.Remove($AddResourceComboBox2)
                    $AddResourceStatusBar.Text = "Add `"Any IP address.`" "
                    break
                }
                "Microsoft subnets"
                {   
                    if ($null -eq $DomainControllers)
                    {
                        DefaultDomainResources -DefaultDomainResourcesStatusBar $AddResourceStatusBar
                    }
                    $AddResourceComboBox2.DataSource = $MicrosoftSubnets
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourcePanel.Controls.Add($AddResourceComboBox2)
                    $AddResourceStatusBar.Text = "Select an Microsoft subnet to add."
                    $AddResourceComboBox2.Focus()
                    break
                }
                "Predefined set of computers"
                {
                    $AddResourceComboBox2.DataSource = "DefaultGateway", "DHCP", "DNS", "Internet", "Intranet", "LocalSubnet"
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourcePanel.Controls.Add($AddResourceComboBox2)
                    $AddResourceStatusBar.Text = "Select a predefined set of computers to add."
                    $AddResourceTextBox.Focus()
                    break
                }
                "Domain resource"
                {   
                    if ($null -eq $DomainControllers)
                    {
                        DefaultDomainResources -DefaultDomainResourcesStatusBar $AddResourceStatusBar
                    }
                    $AddResourceComboBox2.DataSource = $Resources
                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                    $AddResourcePanel.Controls.Add($AddResourceComboBox2)
                    $AddResourceStatusBar.Text = "Select an existing domain resource to add."
                    $AddResourceComboBox2.Focus()
                    break
                }
                "Computer name/IP address"
                {
                    $AddResourceTextBox.Text = ""
                    $AddResourcePanel.Controls.Remove($AddResourceComboBox2)
                    $AddResourcePanel.Controls.Add($AddResourceTextBox)
                    $AddResourceStatusBar.Text = "Enter a computer name or IP address to add."
                    $AddResourceTextBox.Focus()
                }
            }
        })
        $AddResourceComboBox2 = New-Object -TypeName "System.Windows.Forms.ComboBox" -Property @{
            width = $AddResourcePanel.Width - 20
            Location = @{
                X = 10
                Y= 5
            }
            DropDownStyle = "DropDownList"
        }
        $AddResourceStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a computer name or IP address to add."
        }
    }
    $AddResourceForm.CancelButton = $AddResourceCancelButton
    $AddResourceForm.AcceptButton = $AddResourceAcceptButton
    $AddResourceBottomButtonPanel.Controls.Add($AddResourceCancelButton)
    $AddResourceBottomButtonPanel.Controls.Add($AddResourceAcceptButton)
    $AddResourcePanel.Controls.Add($AddResourceTextBox)
    $AddResourcePanel.Controls.Add($AddResourceLabel)
    $AddResourcePanel.Controls.Add($AddResourceComboBox1)
    $AddResourceForm.Controls.Add($AddResourcePanel) # Added to the form first to set focus on this panel
    $AddResourceForm.Controls.Add($AddResourceBottomButtonPanel)
    $AddResourceForm.Controls.Add($AddResourceStatusBar)
    [void]$AddResourceForm.ShowDialog()
}

function RemoveResource ($RemoveResourceProperty,$RemoveResourceDataObjects,$RemoveResourceSelectedItems)
{
    if ($RemoveResourceDataObjects[0].DataGridView)
    {
        $RemoveResourceDataObjects[0].DataGridView.BeginEdit($true) # Required to reset the selected index in the GUI
    }
    foreach ($RemoveResourceDataObject in $RemoveResourceDataObjects)
    {
        foreach ($RemoveResourceSelectedItem in $RemoveResourceSelectedItems)
        {
            $RemoveResourceDataObject.DataSource.Remove($RemoveResourceSelectedItem)
        }
        if ($RemoveResourceDataObject.DataSource.Count -eq 0)
        {
            $RemoveResourceDataObject.DataSource.Add("Any")
        }
        ResetDataSource -ResetDataSourceData $RemoveResourceDataObject
    }
    if ($RemoveResourceDataObjects[0].DataGridView)
    {
        $RemoveResourceDataObjects[0].DataGridView.EndEdit()
    }
}

function ChangeValue ($ChangeValueProperty,$ChangeValueDataObjects)
{
    if ($ChangeValueProperty -in "Enabled", "Direction", "Action")
    {
        switch ($ChangeValueProperty)
        {
            "Enabled"
            { # 1 value (True/False)
                $Value1 = $true
                $Value2 = $false
            }
            "Direction"
            { # 1 value (Inbound/Outbound)
                $Value1 = "Inbound"
                $Value2 = "Outbound"
            }
            "Action"
            { # 1 value (Allow/Block)
                $Value1 = "Allow"
                $Value2 = "Block"
            }
        }
        foreach ($ChangeValueDataObject in $ChangeValueDataObjects)
        {
            if ($ChangeValueDataObject.Value -eq $Value1)
            {
                $ChangeValueDataObject.Value = $Value2    
            }
            else
            {
                $ChangeValueDataObject.Value = $Value1
            }
        }
    }
    elseif ($ChangeValueProperty -in "Package", "Service")
    {
        switch ($ChangeValueProperty)
        {
            "Package"
            { # 1 value, any package or any
                ResourceSelection -ResourceSelectionData (($Language[52], $Language[53]) + $($Mappings.Keys| Sort-Object)) -ResourceSelectionStatusBarText $Language[50] -ResourceSelectionSelectionMode One
            }
            "Service"
            { # 1 value, any service or any
                ResourceSelection -ResourceSelectionData (($Language[52], $Language[54]) + $($Services.DisplayName| Sort-Object)) -ResourceSelectionStatusBarText $Language[55] -ResourceSelectionSelectionMode One
            }
        }
        if ($SelectedItems)
        {
            foreach ($ChangeValueDataObject in $ChangeValueDataObjects)
            {
                $ChangeValueDataObject.Value = $($SelectedItems)
            }
        }
    }
    elseif ($ChangeValueProperty -in  "Profile", "Protocol", "Program")
    {
        PopUpMessage -Message "Not available in this build."
    }
    else
    {
        function ChangeDataObject
        {
            foreach ($ChangeValueDataObject in $ChangeValueDataObjects)
            {
                $ChangeValueDataObject.Value = $ChangeValueTextBox.Text
            }
            $ChangeValueForm.Close()
        }
        $ChangeValueForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
            FormBorderStyle = "FixedDialog"
            KeyPreview = $true
            StartPosition = "CenterParent"
            Width = 250
            Height = 110
            Text = "Change value"
            MaximizeBox = $false
            MinimizeBox = $false
            ControlBox = $false
        }
        $ChangeValueBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
            Width = $ChangeValueForm.Width - 16
            Height = 22
            Dock = "Bottom"
            BackColor = "WhiteSmoke"
        }
        $ChangeValueCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
            Text = $Language[26]
            Anchor = "Right"
        } # This is not the default cancel button because the form size is different to the tool form?
        $ChangeValueCancelButton.Left = $ChangeValueBottomButtonPanel.Width - $ChangeValueCancelButton.Width - 5
        $ChangeValueAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
            Text = "Change"
            Anchor = "Right"
        }
        $ChangeValueAcceptButton.Left = $ChangeValueCancelButton.Left - $ChangeValueAcceptButton.Width - 5
        $ChangeValueAcceptButton.Add_Click(
        {
            switch ($ChangeValueProperty)
            {
                "DisplayName"
                { # 1 value
                    if ($ChangeValueTextBox.Text -eq "")
                    {
                        PopUpMessage -Message "DisplayName needs a value."
                    }
                    else
                    {
                        ChangeDataObject
                    }
                    break
                }
                "Description"
                { # 1 value or blank
                    ChangeDataObject
                    break
                }
                "Group"
                { # 1 value or blank
                if ($EditExistingFirewallRulesPanel.Parent)
                {
                    PopUpMessage -Message "Not available in this build."
                    break
                }
                    ChangeDataObject
                    break
                }
                "Profile"
                { # 1 value, 2 values or any
                    break
                }
                "Protocol"
                { # Only supporting Any, TCP, UDP, ICMPv4 and ICMPv6 in this build
                    break
                }
                "Program"
                { # 1 value or any
                    break
                }
            }
        })
        $ChangeValueForm.CancelButton = $ChangeValueCancelButton
        $ChangeValueForm.AcceptButton = $ChangeValueAcceptButton
        $ChangeValueTextBox = New-Object -TypeName "System.Windows.Forms.TextBox" -Property @{
            width = $ChangeValueForm.Width - 36
            Location = @{
                X = 10
                Y= 5
            }
        }
        if ($ChangeValueProperty -in "DisplayName", "Description" -and $ChangeValueDataObjects.Count -eq 1)
        {
            $ChangeValueTextBox.Text = $ChangeValueDataObjects.Value
        }
        $ChangeValueStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a new value for $ChangeValueProperty."
        }
        $ChangeValuePanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
            AutoScroll = $true
            Anchor = "Top, Bottom, Left, Right"
            Width = $ChangeValueForm.Width - 16
            Height = $ChangeValueForm.Height - 82
        }
        if ($ChangeValueProperty -in "DisplayName", "Description", "Group")
        {
            $ChangeValuePanel.Controls.Add($ChangeValueTextBox)
        }
        $ChangeValueBottomButtonPanel.Controls.Add($ChangeValueCancelButton)
        $ChangeValueBottomButtonPanel.Controls.Add($ChangeValueAcceptButton)
        $ChangeValueForm.Controls.Add($ChangeValuePanel) # Added to the form first to set focus on this panel
        $ChangeValueForm.Controls.Add($ChangeValueBottomButtonPanel)
        $ChangeValueForm.Controls.Add($ChangeValueStatusBar)
        [void]$ChangeValueForm.ShowDialog()
    }
}

function BuildCommands ([ValidateSet("True", "False")]$ExistingRules = $false)
{
    function ReviewAndSave
    {
        $ReviewAndSaveForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
            FormBorderStyle = "Sizable"
            StartPosition = "CenterParent"
            Size = $ToolPageForm.Size
            MinimumSize = $ToolPageForm.MinimumSize
            WindowState = $ToolPageForm.WindowState
            Text = "Review and save"
        }
        $ReviewAndSaveBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
            Width = $ReviewAndSaveForm.Width - 16
            Height = 22
            Dock = "Bottom"
            BackColor = "WhiteSmoke"
        }
        $ReviewAndSaveCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
            Text = $Language[26]
            Anchor = "Right"
        }
        $ReviewAndSaveCancelButton.Left = $ReviewAndSaveBottomButtonPanel.Width - $ReviewAndSaveCancelButton.Width - 16
        $ReviewAndSaveSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
        $ReviewAndSaveSaveFileDialog.Filter = "PowerShell Files (*.ps1)|*.ps1|All files (*.*)|*.*"
        $ReviewAndSaveSaveAsButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
            Text = "Save As"
            Anchor = "Right"
        }
        $ReviewAndSaveSaveAsButton.Add_Click(
        {
            if ($ReviewAndSaveSaveFileDialog.ShowDialog() -eq "OK")
            {
                $ReviewAndSaveCommandsListBox.Items| Out-File -FilePath $ReviewAndSaveSaveFileDialog.FileName
            }
        })
        $ReviewAndSaveSaveAsButton.Left = $ReviewAndSaveCancelButton.Left - $ReviewAndSaveSaveAsButton.Width - 5 
        $ReviewAndSaveSaveToGpoButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
            Text = "Save to GPO"
            Anchor = "Right"
            Width = 80
        }
        $ReviewAndSaveSaveToGpoButton.Add_Click(
        {
            if (CheckForGpoModule)
            {
                function UpdateGroupPolicyObject
                {
                    $ReviewAndSaveStatusBar.Text = "Updating domain group policy object."
                    foreach ($Command in $Commands)
                    {
                        try
                        {
                            Invoke-Expression -Command "$Command -ErrorAction Stop"
                        }
                        catch [Microsoft.Management.Infrastructure.CimException]
                        {
                            if ($error[0].FullyQualifiedErrorId -eq "Windows System Error 1306,Set-NetFirewallRule")
                            {
                                PopUpMessage -Message ($Language[57] + $error[0].InvocationInfo.Line + $Language[58])
                            }
                            else
                            {
                                PopUpMessage -Message ($Language[57] + $error[0].InvocationInfo.Line + $error[0])
                            }
                        }
                    }
                    PopUpMessage -Message $Language[59]
                }
                if($ExistingRules -eq $false)
                {
                    Remove-Variable -Name "SelectedItems" -Scope 1 -Force -ErrorAction SilentlyContinue
                    ResourceSelection -ResourceSelectionData ((Get-GPO -All).DisplayName| Sort-Object) -ResourceSelectionStatusBarText $Language[23]
                    if ($SelectedItems)
                    {
                        $Commands.Insert(0, "`$GpoSession = Open-NetGPO -PolicyStore `"$DomainName\$(($SelectedItems -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$'))`"")
                        $Commands.Add("Save-NetGPO -GPOSession `$GpoSession")
                        UpdateGroupPolicyObject
                    }
                }
                else
                {
                    UpdateGroupPolicyObject
                }
                $ReviewAndSaveStatusBar.Text = "Review the commands and save them to a .ps1 or back to the domain GPO."
            }
        })
        $ReviewAndSaveSaveToGpoButton.Left = $ReviewAndSaveSaveAsButton.Left - $ReviewAndSaveSaveToGpoButton.Width - 5 
        $ReviewAndSaveForm.CancelButton = $ReviewAndSaveCancelButton
        $ReviewAndSaveCommandsListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
            DataSource = $Commands
            Dock = "Fill"
            HorizontalScrollbar = $true
            SelectionMode = "None"
        }
        $ReviewAndSaveStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Review the commands and save them to a .ps1 or back to the domain GPO."
        }
        $ReviewAndSavePanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
            Anchor = "Top, Bottom, Left, Right"
            AutoScroll = $true
            Width = $ReviewAndSaveForm.Width - 16
            Height = $ReviewAndSaveForm.Height - 82
        }
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveCancelButton)
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveSaveAsButton)
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveSaveToGpoButton)
        $ReviewAndSavePanel.Controls.Add($ReviewAndSaveCommandsListBox)
        $ReviewAndSaveForm.Controls.Add($ReviewAndSavePanel) # Added to the form first to set focus on this panel
        $ReviewAndSaveForm.Controls.Add($ReviewAndSaveBottomButtonPanel)
        $ReviewAndSaveForm.Controls.Add($ReviewAndSaveStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
        [void]$ReviewAndSaveForm.ShowDialog()
    }
    function ReplaceProperty ($PropertyName, $WindowsFirewallRuleProperty)
    {
        $WindowsFirewallRuleProperty = ($WindowsFirewallRuleProperty -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$').Replace("RPC", "135").Replace("IPHTTPS", "443")
        if ($WindowsFirewallRuleProperty.Count -gt 0)
        {
            $WindowsFirewallRuleProperty = ($WindowsFirewallRuleProperty -join '", "')
        }
        if ($PropertyName -in "Package", "Service" -and $WindowsFirewallRuleProperty -ne $Language[52])
        {
            if ($WindowsFirewallRuleProperty -in $Language[53], $Language[54])
            {
                $WindowsFirewallRuleProperty = "*"
            }
            elseif ($PropertyName -eq "Package")
            {
                $WindowsFirewallRuleProperty = $($Mappings."$($WindowsFirewallRuleProperty)")
            }
            else
            {
                $WindowsFirewallRuleProperty = ($Services).Where({$_.DisplayName -eq $WindowsFirewallRuleProperty}).Name
            }
        }
        return $WindowsFirewallRuleProperty
    }
    if ($ExistingRules)
    {
        $ChangesFound = $false
        $Commands = New-Object -TypeName "System.Collections.ArrayList"
        $Commands.Add("`$GpoSession = Open-NetGPO -PolicyStore `"$(($WindowsFirewallRules[0].PolicyStore -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$'))`"")
        foreach ($SelectedIndex in $SelectedIndices)
        {
            $NewLine = $true
            foreach ($PropertyName in ($WindowsFirewallRules[0].PsObject.Properties).name)
            {
                if (Compare-Object -ReferenceObject $WindowsFirewallRulesClone[$SelectedIndex] -DifferenceObject $WindowsFirewallRules[$SelectedIndex] -Property $PropertyName)
                {
                    $WindowsFirewallRuleProperty = ReplaceProperty -PropertyName $PropertyName -WindowsFirewallRuleProperty $WindowsFirewallRules[$SelectedIndex].$PropertyName
                    if ($NewLine)
                    {
                        $ChangesFound = $true
                        $NewLine = $false
                        $Index = $Commands.Add("Set-NetFirewallRule -GPOSession `$GpoSession -Name `"$($WindowsFirewallRules[$SelectedIndex].Name)`"") # .Add returns the index of the new line and is used to append additional changed properties
                    }
                    $Commands[$Index] = $Commands[$Index] + " -" + $PropertyName.Replace("DisplayName", "NewDisplayName") + (" `"$($WindowsFirewallRuleProperty)`"")
                }
            }
        }
        if (-not $ChangesFound)
        {
            PopUpMessage -Message "No changes were found in the selected rules."
        }
        else
        {
            $Commands.Add("Save-NetGPO -GPOSession `$GpoSession")
            ReviewAndSave
        }
    }
    else
    {
        $Commands = New-Object -TypeName "System.Collections.ArrayList"
        foreach ($SelectedIndex in $SelectedIndices)
        { # This function does not check for the properties InterfaceAlias, InterfaceType and Security. These may be added in a future build.
            $Index = $Commands.Add("New-NetFirewallRule -GPOSession `$GpoSession") # .Add returns the index of the new line and is used to append additional changed properties
            foreach ($PropertyName in "Name", "DisplayName")
            { # These properties are always needed
                $WindowsFirewallRuleProperty = ReplaceProperty -PropertyName $PropertyName -WindowsFirewallRuleProperty $WindowsFirewallRules[$SelectedIndex].$PropertyName
                $Commands[$Index] = $Commands[$Index] + " -$PropertyName `"$($WindowsFirewallRuleProperty)`""
            }
            foreach ($PropertyName in "Description", "Group", "Platform", "Owner")
            {
                if ($WindowsFirewallRules[$SelectedIndex].$PropertyName)
                { # These properties are added if they have a value
                    $WindowsFirewallRuleProperty = ReplaceProperty -PropertyName $PropertyName -WindowsFirewallRuleProperty $WindowsFirewallRules[$SelectedIndex].$PropertyName
                    $Commands[$Index] = $Commands[$Index] + " -$PropertyName `"$($WindowsFirewallRuleProperty)`""
                }
            }
            if ($WindowsFirewallRules[$SelectedIndex].Enabled -eq $false)
            { # This property is added if it's not the default
                $Commands[$Index] = $Commands[$Index] + " -Enabled $false" 
            }
            foreach ($PropertyName in "Profile", "RemoteAddress", "LocalAddress", "Protocol", "LocalPort", "RemotePort", "IcmpType", "DynamicTarget", "Program", "Package", "Service")
            {
                if ($WindowsFirewallRules[$SelectedIndex].$PropertyName -and $WindowsFirewallRules[$SelectedIndex].$PropertyName -ne "Any")
                { # These properties are added if they are not the default
                    $WindowsFirewallRuleProperty = ReplaceProperty -PropertyName $PropertyName -WindowsFirewallRuleProperty $WindowsFirewallRules[$SelectedIndex].$PropertyName
                    $Commands[$Index] = $Commands[$Index] + " -$PropertyName `"$($WindowsFirewallRuleProperty)`""
                }
            }
            if ($WindowsFirewallRules[$SelectedIndex].Direction -eq "Outbound")
            { # This property is added if it's not the default
                $Commands[$Index] = $Commands[$Index] + " -Direction `"Outbound`"" 
            }
            if ($WindowsFirewallRules[$SelectedIndex].Action -eq "Block")
            { # This property is added if it's not the default
                $Commands[$Index] = $Commands[$Index] + " -Action `"Block`"" 
            }
            if ($WindowsFirewallRules[$SelectedIndex].EdgeTraversalPolicy -eq "Allow")
            { # This property is added if it's not the default
                $Commands[$Index] = $Commands[$Index] + " -EdgeTraversalPolicy `"Allow`"" 
            }
            foreach ($PropertyName in "LooseSourceMapping", "LocalOnlyMapping")
            {
                if ($WindowsFirewallRules[$SelectedIndex].$PropertyName -eq $true)
                { # These properties are added if they are not the default
                    $Commands[$Index] = $Commands[$Index] + " -$PropertyName $true" 
                }
            }
        }
        ReviewAndSave
    }
}

function EditFirewallRules 
{ # This is designed to be called from inside a click event, the object will be placed in the scope of the calling function.
    Set-Variable -Name "EditFirewallRulesPanel" -Value (New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Dock = "Fill"
        BackColor = "WhiteSmoke"
    }) -Scope 2
    $EditFirewallRulesPanel.Add_SizeChanged(
    {
        $EditFirewallRulesDataGridViewButtonPanel.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = 22
        }
        $EditFirewallRulesDataGridView.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
    })
    Set-Variable -Name "EditFirewallRulesDataGridView" -Value (New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{
        AutoSize = $true
        SelectionMode = "CellSelect"
        BackGroundColor = "WhiteSmoke"
        Dock = "None"
        AutoGenerateColumns = $false
        ColumnHeadersHeightSizeMode = "AutoSize"
        MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
        RowHeadersVisible = $false
    }) -Scope 2
    $EditFirewallRulesDataGridView.Add_CurrentCellChanged(
    {
        if ($EditFirewallRulesDataGridView.CurrentCell.DropDownWidth)
        {
            $EditFirewallRulesDataGridView.CurrentCell.DropDownWidth = (($EditFirewallRulesDataGridView.CurrentCell.DataSource).ForEach({$_.Length})| Sort-Object -Descending| Select-Object -First 1) * $DropDownWidthMultiplier
        }
        if ($EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -eq 0)
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $false
            $EditFirewallRulesDataGridViewAddButton.Visible = $false
            $EditFirewallRulesDataGridViewNsLookupButton.Visible = $false
            $EditFirewallRulesDataGridViewChangeButton.Visible = $false
        }
        elseif ($EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -in "LocalAddress", "RemoteAddress", "LocalPort", "RemotePort")
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $true
            $EditFirewallRulesDataGridViewAddButton.Visible = $true
            $EditFirewallRulesDataGridViewNsLookupButton.Visible = $false
            $EditFirewallRulesDataGridViewChangeButton.Visible = $false
            if ($EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -in "LocalAddress", "RemoteAddress" -and $EditFirewallRulesDataGridView.CurrentCell.Value -notin "Any", "DefaultGateway", "DHCP", "DNS", "Internet", "Intranet", "LocalSubnet")
            {
                $EditFirewallRulesDataGridViewNsLookupButton.Visible = $true
            }
        }
        else
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $false
            $EditFirewallRulesDataGridViewAddButton.Visible = $false
            $EditFirewallRulesDataGridViewNsLookupButton.Visible = $false
            $EditFirewallRulesDataGridViewChangeButton.Visible = $true
        }
        if ($EditFirewallRulesDataGridView.SelectedCells.Count -lt 2)
        {
            Set-Variable -Name "SelectedColumnIndex" -Value $EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -Scope 1
        }
        elseif ($EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -ne $SelectedColumnIndex)
        {
            $EditFirewallRulesDataGridView.ClearSelection()
            $EditFirewallRulesDataGridView.CurrentCell.Selected = $true
            Set-Variable -Name "SelectedColumnIndex" -Value $EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -Scope 1
        }
    })
    $EditFirewallRulesDataGridView.Add_DoubleClick(
    {
        $MousePosition = $EditFirewallRulesDataGridView.PointToClient([System.Windows.Forms.Control]::MousePosition)
        if ($EditFirewallRulesDataGridViewChangeButton.Visible -eq $true -and $EditFirewallRulesDataGridView.HitTest($MousePosition.X,$MousePosition.Y).Type -eq "Cell")
        {
            $EditFirewallRulesDataGridViewChangeButton.PerformClick()
        }
    })
    $EditFirewallRulesDataGridView.Add_SizeChanged(
    {
        $EditFirewallRulesDataGridView.Size = $EditFirewallRulesDataGridView.PreferredSize
        $EditFirewallRulesDataGridViewButtonPanel.Location = @{
            X = 0
            Y = $EditFirewallRulesDataGridView.Bottom
        }
        $EditFirewallRulesDataGridViewButtonPanel.Width = $EditFirewallRulesDataGridView.width
    })
    Set-Variable -Name "SelectedColumnIndex" -Value 0 -Scope 2
    $EditFirewallRulesDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn" -Property @{
       AutoSizeMode = "AllCellsExceptHeader"
    }))
    $EditFirewallRulesDataGridView.Columns[0].DefaultCellStyle.Alignment = "TopLeft"
    $ColumnIndex = 1
    $EmptyWindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule"
    ColumnHeaderContextMenuStrip -DataGridView $EditFirewallRulesDataGridView
    foreach ($PropertyName in ($EmptyWindowsFirewallRule.PsObject.Properties).name)
    {
        if ($PropertyName -ne "PolicyStore" -and $PropertyName -ne "Name")
        {
            if ($PropertyName -in "DisplayName", "Description", "Group", "Enabled", "Direction", "Action", "Protocol", "Program", "Package", "Service")
            {
                $EditFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{
                    ReadOnly = $true
                }))
                $EditFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $EditFirewallRulesDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
            }
            else
            {
                $EditFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{
                    FlatStyle = "Popup"
                }))
                $EditFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
            }
            $EditFirewallRulesDataGridView.Columns[$ColumnIndex].DefaultCellStyle.Alignment = "TopLeft"
            $EditFirewallRulesDataGridView.Columns[$ColumnIndex].HeaderCell.ContextMenuStrip = $ColumnHeaderContextMenuStrip
            $ColumnIndex ++
        }
    }
    Set-Variable -Name "DataGridView" -Value $DataGridView -Scope 2
    $EditFirewallRulesDataGridView.Columns["DisplayName"].Frozen = $true
    $EditFirewallRulesDataGridView.Columns["DisplayName"].Width = 150
    $EditFirewallRulesDataGridView.Columns["Group"].Width = 55
    $EditFirewallRulesDataGridView.Columns["Enabled"].Width = 55
    $EditFirewallRulesDataGridView.Columns["Direction"].Width = 55
    $EditFirewallRulesDataGridView.Columns["Action"].Width = 55
    $EditFirewallRulesDataGridView.Columns["Protocol"].Width = 55
    Set-Variable -Name "EditFirewallRulesDataGridViewButtonPanel" -Value (New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $EditFirewallRulesDataGridView.Width
        Height = 22
        Dock = "None"
        BackColor = "WhiteSmoke"
        Location = @{
            X = 0
            Y = $EditFirewallRulesDataGridView.Bottom
        }
    }) -Scope 2
    Set-Variable -Name "EditFirewallRulesDataGridViewRemoveButton" -Value (New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[28]
        Anchor = "Right"
    }) -Scope 2
    $EditFirewallRulesDataGridViewRemoveButton.Left = $EditFirewallRulesDataGridViewButtonPanel.Width - $EditFirewallRulesDataGridViewRemoveButton.Width - 16
    $EditFirewallRulesDataGridViewRemoveButton.Add_Click(
    { # Most of this should move to the RemoveResource function with a test to see if the selected cell is a ComboBox.
        $SelectItemsToRemoveListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
            AutoSize = $true
            BackColor = "GhostWhite"
            Dock = "Fill"
            SelectionMode = "MultiExtended"
        }
        $SelectItemsToRemoveListBox.Add_KeyDown(
        {
            SelectAll -Control $SelectItemsToRemoveListBox
            if ($_.KeyData -eq "Delete")
            {
                $_.SuppressKeyPress = $true
                $SelectItemsToRemoveAcceptButton.PerformClick()
            }
        })
        foreach ($SelectedCell in $EditFirewallRulesDataGridView.SelectedCells)
        {
            foreach ($Item in $SelectedCell.Items)
            {
                if ($Item -notin $SelectItemsToRemoveListBox.Items -and $Item -ne "Any")
                {
                    $SelectItemsToRemoveListBox.Items.ADD($Item)
                }
            }
        }
        if ($SelectItemsToRemoveListBox.Items.Count)
        { 
            $SelectItemsToRemoveForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
                AutoSize = $true
                FormBorderStyle = "FixedDialog"
                StartPosition = "CenterParent"
                MinimumSize = @{
                    Width = 200
                    Height = 100
                }
            }
            $SelectItemsToRemoveForm.Add_Closing(
            {
                if ($SelectItemsToRemoveListBox.SelectedItems.Count -eq 0 -and $SelectItemsToRemoveForm.DialogResult -eq "OK")
                {
                    $_.Cancel = $true
                    PopUpMessage -Message $Language[33]
                }
            })
            $SelectItemsToRemoveForm.Add_Shown(
            {
                $SelectItemsToRemoveForm.Focus()

            })
            $SelectItemsToRemoveBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
                Width = $SelectItemsToRemoveForm.Width - 16
                Height = 22
                Dock = "Bottom"
                BackColor = "WhiteSmoke"
            }
             $SelectItemsToRemoveCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
                Text = $Language[26]
                Anchor = "Right"
            }
            $SelectItemsToRemoveCancelButton.Left = $SelectItemsToRemoveBottomButtonPanel.Width - $SelectItemsToRemoveCancelButton.Width - 5
            $SelectItemsToRemoveAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
                Text = "Remove"
                Anchor = "Right"
                DialogResult = "OK"
            }
            $SelectItemsToRemoveAcceptButton.Left = $SelectItemsToRemoveCancelButton.Left - $SelectItemsToRemoveAcceptButton.Width - 5
            $SelectItemsToRemoveForm.CancelButton = $SelectItemsToRemoveCancelButton
            $SelectItemsToRemoveForm.AcceptButton = $SelectItemsToRemoveAcceptButton
            $SelectItemsToRemoveStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
                Dock = "Bottom"
                Text = "Please select one or more resource to remove."
            }
            $SelectItemsToRemoveListBox.Size = $SelectItemsToRemoveListBox.PreferredSize
            $SelectItemsToRemoveBottomButtonPanel.Controls.Add($SelectItemsToRemoveCancelButton)
            $SelectItemsToRemoveBottomButtonPanel.Controls.Add($SelectItemsToRemoveAcceptButton)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveListBox)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveBottomButtonPanel)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveStatusBar)
            if ($SelectItemsToRemoveForm.ShowDialog() -eq "OK")
            {
                RemoveResource -RemoveResourceProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -RemoveResourceDataObjects $EditFirewallRulesDataGridView.SelectedCells -RemoveResourceSelectedItems $SelectItemsToRemoveListBox.SelectedItems
            }
        }
        else
        {
            PopUpMessage -Message "No resources were found that can be removed."
        }
    })
    Set-Variable -Name "EditFirewallRulesDataGridViewAddButton" -Value (New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[29]
        Anchor = "Right"
    }) -Scope 2
    $EditFirewallRulesDataGridViewAddButton.Left = $EditFirewallRulesDataGridViewRemoveButton.Left - $EditFirewallRulesDataGridViewAddButton.Width - 5
    $EditFirewallRulesDataGridViewAddButton.Add_Click(
    {
        AddResource -AddResourceProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -AddResourceValues $EditFirewallRulesDataGridView.SelectedCells
    })
    Set-Variable -Name "EditFirewallRulesDataGridViewNsLookupButton" -Value (New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[30]
        Anchor = "Right"
    }) -Scope 2
    $EditFirewallRulesDataGridViewNsLookupButton.Left = $EditFirewallRulesDataGridViewAddButton.Left - $EditFirewallRulesDataGridViewNsLookupButton.Width - 5
    $EditFirewallRulesDataGridViewNsLookupButton.Add_Click(
    {
        NsLookup -IpAddresses $EditFirewallRulesDataGridView.SelectedCells.Value
    })
    Set-Variable -Name "EditFirewallRulesDataGridViewChangeButton" -Value (New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[31]
        Anchor = "Right"
        Visible = $false
    }) -Scope 2
    $EditFirewallRulesDataGridViewChangeButton.Left = $EditFirewallRulesDataGridViewButtonPanel.Width - $EditFirewallRulesDataGridViewChangeButton.Width - 16
    $EditFirewallRulesDataGridViewChangeButton.Add_Click(
    {
        ChangeValue -ChangeValueProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -ChangeValueDataObjects $EditFirewallRulesDataGridView.SelectedCells
    })
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewRemoveButton)
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewAddButton)
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewNsLookupButton)
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewChangeButton)
    $EditFirewallRulesPanel.Controls.Add($EditFirewallRulesDataGridView)
    $EditFirewallRulesPanel.Controls.Add($EditFirewallRulesDataGridViewButtonPanel)
}

function ResourceSelection ($ResourceSelectionData,$ResourceSelectionStatusBarText,[ValidateSet("None", "One", "MultiSimple", "MultiExtended")]$ResourceSelectionSelectionMode = "MultiExtended")
{ # This is designed to be called from inside a click event, the $SelectedItems object will be placed in the scope of the calling function.  
    $ResourceSelectionForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        AutoSize = $true
        FormBorderStyle = "Sizable"
        MinimumSize = @{
            width = $ResourceSelectionStatusBarText.Length + 16
            Height = 250
        }
        StartPosition = "CenterParent"
        Text = $Language[22]
    }
    $ResourceSelectionBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ResourceSelectionForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ResourceSelectionCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[26]
        Anchor = "Right"
    }
    $ResourceSelectionCancelButton.Left = $ResourceSelectionBottomButtonPanel.Width - $ResourceSelectionCancelButton.Width - 16
    $ResourceSelectionAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        DialogResult = "OK"
        Text = $Language[25]
        Anchor = "Right"
    }
    $ResourceSelectionAcceptButton.Left = $ResourceSelectionCancelButton.Left - $ResourceSelectionAcceptButton.Width - 5
    $ResourceSelectionAcceptButton.Add_Click(
    {
        Set-Variable "SelectedItems" -Value $ResourceSelectionListBox.SelectedItems -Scope 2
        $ResourceSelectionForm.Close()
    })
    $ResourceSelectionForm.CancelButton = $ResourceSelectionCancelButton
    $ResourceSelectionForm.AcceptButton = $ResourceSelectionAcceptButton
    $ResourceSelectionListBox = New-Object "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
        SelectionMode = $ResourceSelectionSelectionMode
    }
    $ResourceSelectionListBox.Add_DoubleClick(
    {
        Set-Variable "SelectedItems" -Value $ResourceSelectionListBox.SelectedItems -Scope 2
        $ResourceSelectionForm.Close()
    })
    if ($ResourceSelectionSelectionMode -eq "MultiExtended")
    {
        $ResourceSelectionListBox.Add_KeyDown(
        {
            SelectAll -Control $ResourceSelectionListBox
        })
    }
    foreach ($ResourceSelection in $ResourceSelectionData)
    { # Loop through data and add to listbox
        [void]$ResourceSelectionListBox.Items.Add($ResourceSelection)
    }
    $ResourceSelectionStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = $ResourceSelectionStatusBarText
    }
    $ResourceSelectionPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ResourceSelectionForm.Width - 16
        Height = $ResourceSelectionForm.Height - 82
    }
    $ResourceSelectionPanel.Controls.Add($ResourceSelectionListBox)
    $ResourceSelectionBottomButtonPanel.Controls.Add($ResourceSelectionCancelButton)
    $ResourceSelectionBottomButtonPanel.Controls.Add($ResourceSelectionAcceptButton)
    $ResourceSelectionForm.Controls.Add($ResourceSelectionPanel) # Added to the form first to set focus on this panel
    $ResourceSelectionForm.Controls.Add($ResourceSelectionBottomButtonPanel)
    $ResourceSelectionForm.Controls.Add($ResourceSelectionStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    return $ResourceSelectionForm.ShowDialog()
}

function CheckForGpoModule
{
    if (-not (Get-Module -ListAvailable -Name "GroupPolicy"))
    {
        PopUpMessage -Message $Language[34]
        return $false
    }
    return $true
}

function NsLookup ($IpAddresses)
{
    foreach ($IpAddress in $IpAddresses)
    {
        $NameHost = (Resolve-DnsName -Name $IpAddress -ErrorAction SilentlyContinue).NameHost
        if ($NameHost)
        {
            PopUpMessage -Message "$IpAddress - $NameHost"
        }
        else
        {
            PopUpMessage -Message "$IpAddress - $($Language[32])"
        }
    }
}

function ColumnHeaderContextMenuStrip ($DataGridView)
{
    Set-Variable -Name "DataGridView" -Value $DataGridView -Scope 1
    Set-Variable -Name "ColumnHeaderContextMenuStrip" -Value (New-Object -TypeName "System.Windows.Forms.ContextMenuStrip") -Scope 1
    [void]$ColumnHeaderContextMenuStrip.Items.Add($Language[47])
    [void]$ColumnHeaderContextMenuStrip.Items.Add($Language[48])
    [void]$ColumnHeaderContextMenuStrip.Items.Add($Language[49])
    $ColumnHeaderContextMenuStrip.Add_Opening(
    {
        Set-Variable -Name "MousePosition" -Value ($DataGridView.PointToClient([System.Windows.Forms.Control]::MousePosition)) -Scope 1
    })
    $ColumnHeaderContextMenuStrip.Add_ItemClicked(
    {
        $ClickedColumnHeaderIndex = $DataGridView.HitTest($MousePosition.X,$MousePosition.Y).ColumnIndex
        switch (($_.ClickedItem).Text)
        {
            $Language[47]
            {
               $DataGridView.Columns[$ClickedColumnHeaderIndex].Visible = $false 
            }
            $Language[48]
            {
                if ($DataGridView.Columns[$ClickedColumnHeaderIndex].Frozen)
                {
                    $DataGridView.Columns[0].Frozen = $false
                    $DataGridView.Columns["DisplayName"].Frozen = $true
                }
                else
                {
                    $DataGridView.Columns[$ClickedColumnHeaderIndex].Frozen = $true
                }
            }
            $Language[49]
            {
                foreach ($Column in $DataGridView.Columns)
                {
                    if ($Column.Name -notin "SourcePort", "ProcessId")
                    {
                        $Column.Visible = $true
                    }
                }
                $DataGridView.Columns[0].Frozen = $false
                $DataGridView.Columns["DisplayName"].Frozen = $true
            }
        }
        $DataGridView.Size = $DataGridView.PreferredSize
    })
}

function FindAllPoliciesWithFirewallRulesPage
{
    $ToolPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Find all policies with firewall rules"
    } 
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
            $FindAllPoliciesWithFirewallRulesGpoListBox.Hide()
            GroupPoliciesWithExistingFirewallRules -GroupPoliciesWithExistingFirewallRulesStatusBar $FindAllPoliciesWithFirewallRulesStatusBar
            $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($FindAllPoliciesWithFirewallRules in $Script:GroupPoliciesWithExistingFirewallRules)
        { # Loop through GPOs and add to listbox 
            [void]$FindAllPoliciesWithFirewallRulesGpoListBox.Items.Add($FindAllPoliciesWithFirewallRules)
        }
        $FindAllPoliciesWithFirewallRulesStatusBar.Text = "$($FindAllPoliciesWithFirewallRulesGpoListBox.Items.Count) group policies with firewall rules were found."
        $DefaultPageCancelButton.Left = $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $FindAllPoliciesWithFirewallRulesSaveAsButton.Left = $DefaultPageCancelButton.Left - $FindAllPoliciesWithFirewallRulesSaveAsButton.Width - 5 
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesSaveAsButton)
        $FindAllPoliciesWithFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $FindAllPoliciesWithFirewallRulesBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $FindAllPoliciesWithFirewallRulesSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $FindAllPoliciesWithFirewallRulesSaveFileDialog.Filter = "Text Files (*.txt)|*.txt|All files (*.*)|*.*"
    $FindAllPoliciesWithFirewallRulesSaveAsButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Save As"
        Anchor = "Right"
    }
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Add_Click(
    {
        if ($FindAllPoliciesWithFirewallRulesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $FindAllPoliciesWithFirewallRulesGpoListBox.Items| Out-File -FilePath $FindAllPoliciesWithFirewallRulesSaveFileDialog.FileName
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $FindAllPoliciesWithFirewallRulesGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
        SelectionMode = "None"
    }
    $FindAllPoliciesWithFirewallRulesStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Scanning policies."
    }
    $FindAllPoliciesWithFirewallRulesPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $FindAllPoliciesWithFirewallRulesPanel.Controls.Add($FindAllPoliciesWithFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function UpdateDomainResourcesPage
{
    $ToolPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Update domain resources"
    }
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $UpdateDomainResourcesBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $DefaultPageCancelButton.Left = $UpdateDomainResourcesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
    $UpdateDomainResourcesSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $UpdateDomainResourcesSaveFileDialog.Filter = "XML Files (*.xml)|*.xml|All files (*.*)|*.*"
    $UpdateDomainResourcesExportButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Export"
        Anchor = "Right"
    }
    $UpdateDomainResourcesExportButton.Left = $DefaultPageCancelButton.Left - $UpdateDomainResourcesExportButton.Width - 5
    $UpdateDomainResourcesExportButton.Add_Click(
    {
        if ($UpdateDomainResourcesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ResourcesArray = @()
            foreach ($Resource in $ResourcesAndProxyPorts)
            {
                $ResourcesArray += Get-Variable -Name $Resource -Scope "Script"

            }
            Export-Clixml -InputObject $ResourcesArray -Path $UpdateDomainResourcesSaveFileDialog.FileName -Force
        }
    })
    $UpdateDomainResourcesOpenFileDialog =  New-Object -TypeName "System.Windows.Forms.OpenFileDialog"
    $UpdateDomainResourcesOpenFileDialog.Filter = "XML Files (*.xml)|*.xml|All files (*.*)|*.*"
    $UpdateDomainResourcesImportButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Import"
        Anchor = "Right"
    }
    $UpdateDomainResourcesImportButton.Left = $UpdateDomainResourcesExportButton.Left - $UpdateDomainResourcesImportButton.Width - 5
    $UpdateDomainResourcesImportButton.Add_Click(
    {
        if ($UpdateDomainResourcesOpenFileDialog.ShowDialog() -eq "OK")
        {
            $ResourcesArray = Import-Clixml -Path $UpdateDomainResourcesOpenFileDialog.FileName
            foreach ($Resource in $ResourcesArray)
            {
                Set-Variable -Name $Resource.Name -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope "Script"
                Set-Variable -Name $Resource.Name -Value $Resource.Value -Scope "Script"
            }
            $UpdateDomainResourcesResourcesListBox.SetSelected(0, $true)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $UpdateDomainResourcesResourcesListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        Anchor = "Top,Left"
        Location = @{
            X = 13
            Y = 13
        }
        BorderStyle = "Fixed3D"
        Size = @{
            Width = 212
            Height = 250
        }
    }
    $UpdateDomainResourcesResourcesListBox.Add_MouseHover(
    {
        $MouseHoverIndex = $UpdateDomainResourcesResourcesListBox.IndexFromPoint($UpdateDomainResourcesResourcesListBox.PointToClient([System.Windows.Forms.Control]::MousePosition))
        $UpdateDomainResourcesToolTip.Active = $false
        $UpdateDomainResourcesToolTip.AutoPopDelay = [math]::Sqrt(($UpdateDomainResourcesToolTips[$MouseHoverIndex]).Length) * $ToolTipAutoPopDelayMultiplier
        $UpdateDomainResourcesToolTip.SetToolTip($UpdateDomainResourcesResourcesListBox, $UpdateDomainResourcesToolTips[$MouseHoverIndex])
        $UpdateDomainResourcesToolTip.Active = $true
    })
    $UpdateDomainResourcesResourcesListBox.Add_SelectedValueChanged(
    {
        $UpdateDomainResourcesValuesListBox.DataSource = (Get-Variable -Name $UpdateDomainResourcesResourcesListBox.SelectedItem).Value
    })
    $UpdateDomainResourcesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $UpdateDomainResourcesResourcesListBox.DataSource = $Script:ResourcesAndProxyPorts
    $UpdateDomainResourcesValuesContextMenuStrip = New-Object -TypeName "System.Windows.Forms.ContextMenuStrip"
    $UpdateDomainResourcesValuesContextMenuStrip.Items.Add("Remove")
    $UpdateDomainResourcesValuesContextMenuStrip.Add_ItemClicked(
    {
        $UpdateDomainResourcesRemoveButton.PerformClick()
    })
    $UpdateDomainResourcesValuesListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        Anchor = "Top,Left,Right"
        Location = @{
            X = ($UpdateDomainResourcesResourcesListBox.Location.X + $UpdateDomainResourcesResourcesListBox.Width + 13)
            Y = 13
        }
        BorderStyle = "Fixed3D"
        Size = @{
            Width = ($ToolPageForm.Width - 269)
            Height = $UpdateDomainResourcesResourcesListBox.Height - 35
        }
        SelectionMode = "MultiExtended"
        ContextMenuStrip = $UpdateDomainResourcesValuesContextMenuStrip
    }
    $UpdateDomainResourcesValuesListBox.Add_KeyDown(
    {
        SelectAll -Control $UpdateDomainResourcesValuesListBox
    })
    $UpdateDomainResourcesRemoveButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Remove"
        Anchor = "Top,Right"
        Location = @{
            X = $ToolPageForm.Width - $UpdateDomainResourcesRemoveButton.Width - 105
            Y = $UpdateDomainResourcesValuesListBox.Location.Y + $UpdateDomainResourcesValuesListBox.Height + 5
        }
    }
    $UpdateDomainResourcesRemoveButton.Add_Click(
    {
        RemoveResource -RemoveResourceProperty $UpdateDomainResourcesResourcesListBox.SelectedItem -RemoveResourceDataObjects $UpdateDomainResourcesValuesListBox -RemoveResourceSelectedItems $UpdateDomainResourcesValuesListBox.SelectedItems
    })
    $UpdateDomainResourcesAddButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Add"
        Anchor = "Top,Right"
        Location = @{
            Y = $UpdateDomainResourcesRemoveButton.Location.Y
        }
    }
    $UpdateDomainResourcesAddButton.Left = $UpdateDomainResourcesRemoveButton.Left - $UpdateDomainResourcesAddButton.Width - 5
    $UpdateDomainResourcesAddButton.Add_Click(
    {
        AddResource -AddResourceProperty $UpdateDomainResourcesResourcesListBox.SelectedValue -AddResourceValues $UpdateDomainResourcesValuesListBox
    })
    $UpdateDomainResourcesStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Please select a resource to update."
    }
    $UpdateDomainResourcesPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($UpdateDomainResourcesExportButton)
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($UpdateDomainResourcesImportButton)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesResourcesListBox)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesValuesListBox)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesRemoveButton)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesAddButton)
    $ToolPageForm.Controls.Add($UpdateDomainResourcesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($UpdateDomainResourcesBottomButtonPanel)
    $ToolPageForm.Controls.Add($UpdateDomainResourcesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function EditExistingFirewallRulesPage
{   
    $ToolPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        KeyPreview = $true
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Edit existing firewall rules"
    }
    $ToolPageForm.Add_Closing(
    {
        if ($EditFirewallRulesPanel.Parent)
        {
            if ((CancelAccept -Message $Language[19] -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "Cancel")
            {
                $_.Cancel = $true
            }
        }
    })
    $ToolPageForm.Add_KeyUp(
    {
        if ($_.KeyCode -eq "Back" -and -not $EditExistingFirewallRulesGpoListBox.Parent)
        {
            $EditExistingFirewallRulesBackButton.PerformClick()
        }
    })
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            if ((CancelAccept -Message "Do you want to search for group policies`r`nwith existing firewall rules or select`r`nfrom a list of all group policies?" -CancelButtonText "Search" -AcceptButtonText "Select") -eq "CANCEL")
            {
                $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                    Anchor = "Left"
                }
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
                $EditExistingFirewallRulesGpoListBox.Hide()
                GroupPoliciesWithExistingFirewallRules -GroupPoliciesWithExistingFirewallRulesStatusBar $EditExistingFirewallRulesStatusBar
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($ProgressBar)
                $EditExistingFirewallRulesGroupPolicies = $Script:GroupPoliciesWithExistingFirewallRules
            }
            else
            {
                $EditExistingFirewallRulesGroupPolicies = (Get-GPO -All).DisplayName| Sort-Object
            }
        }
        else
        {
            $EditExistingFirewallRulesGroupPolicies = $Script:GroupPoliciesWithExistingFirewallRules
        }
        foreach ($EditExistingFirewallRulesGroupPolicy in $EditExistingFirewallRulesGroupPolicies)
        { # Loop through GPOs and add to listbox 
            [void]$EditExistingFirewallRulesGpoListBox.Items.Add($EditExistingFirewallRulesGroupPolicy)
        }
        $EditExistingFirewallRulesGpoListBox.SetSelected(0, $true)
        $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
        $DefaultPageCancelButton.Left = $EditExistingFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $EditExistingFirewallRulesAcceptButton.Left = $DefaultPageCancelButton.Left - $EditExistingFirewallRulesAcceptButton.Width - 5
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesAcceptButton)
        $EditExistingFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $EditExistingFirewallRulesBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $EditExistingFirewallRulesAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[25]
        Anchor = "Right"
    }
    $EditExistingFirewallRulesAcceptButtonClick =
    { # This is created as a script outside the click event because it's also used as a double click event, if the double click event calls the click event that would create an additional scope and object data is lost
        if ($EditExistingFirewallRulesGpoListBox.Parent)
        {
            $EditExistingFirewallRulesStatusBar.Text = "Building rule collection."
            $EditExistingFirewallRulesRulesListBox.Items.Clear()
            $GpoSession = Open-NetGPO -PolicyStore "$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)"
            Set-Variable -Name "EditExistingFirewallRulesRulesArray" -Value @() -Scope 1
            if (Get-NetFirewallRule -GPOSession $GpoSession| Select-Object -First 1)
            {
                foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -GPOSession $GpoSession| Sort-Object -Property "DisplayName"))
                {
                    Set-Variable -Name "EditExistingFirewallRulesRulesArray" -Value ($EditExistingFirewallRulesRulesArray + $EditExistingFirewallRulesRule.Name) -Scope 1
                    $EditExistingFirewallRulesRulesListBox.Items.Add($EditExistingFirewallRulesRule.DisplayName)
                }
                $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."
                $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesBackButton)
                $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesGpoListBox)
                $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
                $EditExistingFirewallRulesRulesListBox.SetSelected(0, $true)
                $EditExistingFirewallRulesRulesListBox.Focus()
            }
            else
            {
                PopUpMessage -Message "$($EditExistingFirewallRulesGpoListBox.SelectedItem)`r`ndoes not contain any firewall rules."
                $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
            }
            Remove-Variable -Name "GpoSession" -Force
        }
        elseif ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            if (($EditExistingFirewallRulesRulesListBox.SelectedIndices).Count -ne 0)
            {
                if (-not $Mappings)
                {
                    $EditExistingFirewallRulesStatusBar.Text =  $Language[51]
                    $UserSids = @()
                    foreach ($PsChildName in ((Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-*').PsChildName))
                    {
                        $UserSids += $PsChildName
                    }
                    New-PSDrive -Name "HKU" -PSProvider Registry -Root "HKEY_USERS"
                    Set-Variable -name "Mappings" -Value @{} -Scope 1
                    foreach ($UserSid in $UserSids)
                    { # Get the Appx package family name to SID mappings from the registry on the local machine
                        if (Get-ChildItem -Path "HKU:\$($UserSid)_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\" -ErrorAction SilentlyContinue)
                        {
                            $Root = (Get-ChildItem -Path "HKU:\$($UserSid)_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\")
                            foreach ($Name in $Root.Name)
                            {
                                if ((Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker -and -not $Mappings.((Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker))
                                {
                                    Set-Variable -Name "Mappings" -Value ($Mappings += @{(Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker = (Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").PSChildName}) -Scope 1
                                }
                            }
                        }
                    }
                }
                if (-not $Services)
                {
                    $EditExistingFirewallRulesStatusBar.Text =  $Language[56]
                    Set-Variable -Name "Services" -Value (Get-CimInstance -ClassName "Win32_Service") -Scope 1
                }
                $GpoSession = Open-NetGPO -PolicyStore ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")
                Set-Variable -Name "WindowsFirewallRules" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1
                Set-Variable -Name "WindowsFirewallRulesClone" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1
                foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -GPOSession $GpoSession -Name $EditExistingFirewallRulesRulesArray[$EditExistingFirewallRulesRulesListBox.SelectedIndices]))
                {
                    $EditExistingFirewallRulesStatusBar.Text = "Importing rule $($EditExistingFirewallRulesRule.Name)."
                    $WindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule" -Property @{
                        PolicyStore = ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")
                        Name = $EditExistingFirewallRulesRule.Name
                        DisplayName = $EditExistingFirewallRulesRule.DisplayName
                        Description = $EditExistingFirewallRulesRule.Description
                        Group = $EditExistingFirewallRulesRule.Group
                        Enabled = $EditExistingFirewallRulesRule.Enabled
                        Profile = @($EditExistingFirewallRulesRule.Profile) -split (", ")
                        Direction = $EditExistingFirewallRulesRule.Direction
                        Action = $EditExistingFirewallRulesRule.Action
                        LocalAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).LocalAddress)
                        RemoteAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).RemoteAddress)
                        Protocol = ($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).Protocol
                        LocalPort = @((($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).LocalPort).Replace("RPC", "135"))
                        RemotePort = @((($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).RemotePort).Replace("RPC", "135").Replace("IPHTTPS", "443"))
                        Program = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program
                    }
                    if (($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package -eq "*")
                    {
                        $WindowsFirewallRule.Package = (($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package).Replace("*", $Language[53])
                    }
                    elseif (($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package)
                    {
                        $WindowsFirewallRule.Package = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package
                        $WindowsFirewallRule.Package = $WindowsFirewallRule.Package.Replace($($WindowsFirewallRule.Package), $($Mappings.Keys| Where-Object -FilterScript {
                            $Mappings[$_] -eq $WindowsFirewallRule.Package
                        }))
                    }
                    if (($EditExistingFirewallRulesRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service -in $Language[52], "*")
                    {
                        $WindowsFirewallRule.Service = (($EditExistingFirewallRulesRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service).Replace("*", $Language[54])
                    }
                    else
                    {
                        $WindowsFirewallRule.Service = ($EditExistingFirewallRulesRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service
                        $WindowsFirewallRule.Service = ($Services).Where({$_.Name -eq $WindowsFirewallRule.Service}).DisplayName
                    }
                    Set-Variable -Name "WindowsFirewallRules" -Value ([System.Collections.ArrayList]$WindowsFirewallRules += $WindowsFirewallRule) -Scope 1
                    Set-Variable -Name "WindowsFirewallRulesClone" -Value ([System.Collections.ArrayList]$WindowsFirewallRulesClone += $WindowsFirewallRule.Clone()) -Scope 1
                }
                Remove-Variable -Name "GpoSession" -Force
                $EditExistingFirewallRulesStatusBar.Text = "$($WindowsFirewallRules.Count) rule(s) imported, edit rules and then select one or more rules to create the commands."
                EditFirewallRules
                $EditFirewallRulesDataGridView.DataSource = $WindowsFirewallRules
                $EditExistingFirewallRulesAcceptButton.Text = "Create"
                $EditExistingFirewallRulesPanel.Controls.Add($EditFirewallRulesPanel)
                $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
                UpdateDataSourceForComboBoxCell -ArrayList $WindowsFirewallRules -DataGridView $EditFirewallRulesDataGridView # This needs to run after the gridview control has been added so that the rows exist
            }
            else
            {
                PopUpMessage -Message "Please select one or more rules to edit."
            }
        }
        elseif ($EditFirewallRulesPanel.Parent)
        {
            [int[]]$SelectedIndices = @()
            for ($i = 0; $i -lt $EditFirewallRulesDataGridView.Rows.Count; $i++)
            {
                if ($($EditFirewallRulesDataGridView.Rows[$i].Cells[0].Value) -eq $true)
                {
                    $SelectedIndices += $i
                }
            }
            if ($SelectedIndices.Count)
            {
                BuildCommands -ExistingRules $true
            }
            else
            {
                PopUpMessage -Message "Please select one or more rules."
            }
        }
    }
    $EditExistingFirewallRulesAcceptButton.Add_Click($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesBackButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[24]
        Anchor = "Right"
    }
    $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
    $EditExistingFirewallRulesBackButton.Add_Click(
    {
        if ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
            $EditExistingFirewallRulesGpoListBox.Focus()
        }
        elseif ($EditFirewallRulesDataGridView.Parent)
        {
            if ((CancelAccept -Message $Language[19] -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "OK")
            {
                $EditExistingFirewallRulesStatusBar.Text = "$($WindowsFirewallRules.Count) rule(s) imported, select one or more rules to edit."
                $EditExistingFirewallRulesAcceptButton.Text = $Language[25]
                $EditExistingFirewallRulesPanel.Controls.Remove($EditFirewallRulesPanel)
                $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
                $EditExistingFirewallRulesRulesListBox.Focus()
            }
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $EditExistingFirewallRulesAcceptButton
    $EditExistingFirewallRulesGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
    }
    $EditExistingFirewallRulesGpoListBox.Add_DoubleClick($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesRulesListBox = New-Object "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
        SelectionMode = "MultiExtended"
    }
    $EditExistingFirewallRulesRulesListBox.Add_DoubleClick($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesRulesListBox.Add_KeyDown(
    {
        SelectAll -Control $EditExistingFirewallRulesRulesListBox
    })
    $EditExistingFirewallRulesStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
    }
    $EditExistingFirewallRulesPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function ScanComputerForBlockedConnectionsPage
{
    class NetworkConnection
    {
        [int] $ProcessId
        [string] $DisplayName = ""
        [string] $Application
        [string] $Direction
        [string] $SourceAddress
        [int] $SourcePort
        [string] $DestAddress
        [int] $DestPort
        [string] $Protocol
        [System.Collections.ArrayList] $Service = @()
        [string] $Notes = ""
    }
    $ToolPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        KeyPreview = $true
        Location = @{
            X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125
            Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55
        }
        StartPosition = "Manual"
        Width = 250
        Height = 110
        Text = "Scan computer for blocked connections"
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
    }
    $ToolPageForm.Add_Closing(
    {
        if ($EditFirewallRulesPanel.Parent)
        {
            if ((CancelAccept -Message $Language[19] -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "Cancel")
            {
                $_.Cancel = $true
            }
        }
    })
    $ToolPageForm.Add_KeyUp(
    {
        if ($_.KeyCode -eq "Back" -and -not $ScanComputerForBlockedConnectionsTextBox.Parent)
        {
            $ScanComputerForBlockedConnectionsBackButton.PerformClick()
        }
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $ScanComputerForBlockedConnectionsBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ScanComputerForBlockedConnectionsCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[26]
        Anchor = "Right"
    } # This is not the default cancel button because the form size is different to the tool form?
    $ScanComputerForBlockedConnectionsCancelButton.Left = $ScanComputerForBlockedConnectionsBottomButtonPanel.Width - $ScanComputerForBlockedConnectionsCancelButton.Width - 5
    $ScanComputerForBlockedConnectionsAcceptButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Scan"
        Anchor = "Right"
    }
    $ScanComputerForBlockedConnectionsAcceptButton.Left = $ScanComputerForBlockedConnectionsCancelButton.Left - $ScanComputerForBlockedConnectionsAcceptButton.Width - 5
    $ScanComputerForBlockedConnectionsAcceptButton.Add_Click(
    {
        if ($ScanComputerForBlockedConnectionsTextBox.Parent)
        {
            [String]$Computer = $ScanComputerForBlockedConnectionsTextBox.Text
            try
            {
                try
                {
                    if ([ipaddress]$Computer)
                    {
                        [ipaddress]$IpAddresses = $Computer
                    }
                }
                catch [Management.Automation.PSInvalidCastException]
                {
                    $ScanComputerForBlockedConnectionsStatusBar.Text =  "Resolving IP addresses."
                    [ipaddress[]]$IpAddresses = AttemptResolveDnsName $Computer
                    if ($null -eq $IpAddresses)
                    {
                        throw "DNS name does not exist"
                    }
                }
                foreach ($IpAddress in $IpAddresses) # Because Test-NetConnection does the IP addresses one after another, uses Ping and doesn't provide feedback during the test I've opted to use asynchronous TCP jobs and monitor for the state of those. This also allows me to abandon the jobs if the tests are taking too long.
                {
                    $JobNumber += 1
                    if ($IpAddress.AddressFamily -eq "InterNetworkV6")
                    {
                        $TcpClient = New-Object -TypeName "System.Net.Sockets.TcpClient"("InterNetworkV6")
                    }
                    else
                    {
                        $TcpClient = New-Object -TypeName "System.Net.Sockets.TcpClient"("InterNetwork")
                    }
                    Set-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber") -Value ($TcpClient.ConnectAsync($IpAddress,135))
                    [array]$NetworkConnectivityJobs += Get-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber")
                }
                $WaitTime = (Get-Date).AddSeconds(10)
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Trying $(($NetworkConnectivityJobs).Count) IP address(es)."
                do
                {
                    $NetworkConnectivityJobRanToCompletion = $false
                    $JobsWaitingForActivation = $false
                    foreach ($NetworkConnectivityJob in $NetworkConnectivityJobs)
                    {
                        if ($NetworkConnectivityJob.Value.Status -eq "RanToCompletion")
                        {
                            $NetworkConnectivityJobRanToCompletion = $true
                        }
                        if ($NetworkConnectivityJob.Value.Status -eq "WaitingForActivation")
                        {
                            $JobsWaitingForActivation = $true
                        }
                    }
                    if ($NetworkConnectivityJobRanToCompletion -eq $false)
                    {
                        if ($JobsWaitingForActivation -eq $false)
                            {
                            if ((CancelAccept -Message "All network connectivity jobs have failed,`r`ndo you want to display diagnostic information?" -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "OK")
                            {
                                foreach ($NetworkConnectivityJob in $NetworkConnectivityJobs)
                                {
                                    [array]$DiagnosticResults += $NetworkConnectivityJob.Value.Exception.InnerException
                                }
                                PopUpMessage -Message $DiagnosticResults
                            }
                            throw "Connectivity test failed."   
                        }
                        if ((Get-Date) -gt $WaitTime)
                        {
                            if ((CancelAccept -Message "Network connectivity tests are taking longer than expected,`r`nthis function requires TCP ports 135,5985 and 49152-65535.`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
                            {
                                throw "Connectivity test aborted, scanning cancelled."
                            }
                            $WaitTime = (Get-Date).AddSeconds(10)
                        }
                        Start-Sleep -Milliseconds 500
                    }
                }
                Until ($NetworkConnectivityJobRanToCompletion -eq $true)
                $ComputerCimSession = New-CimSession -ComputerName $Computer -ErrorAction Stop
                $ComputerPsSession = New-PSSession -ComputerName $Computer -ErrorAction Stop
                Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    if(-not (AuditPol /Get /Subcategory:"Filtering Platform Connection").Where({$_ -like "*Filtering Platform Connection*Failure"}))
                    {
                        throw "Failure auditing is not enabled."
                    }
                }
                [datetime]$NetworkStateChange = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    (Get-WinEvent -FilterHashtable @{
                        LogName = "Microsoft-Windows-NetworkProfile/Operational"
                        ID = 4004
                    } -MaxEvents 1 -ErrorAction Stop).TimeCreated.AddSeconds("1")
                }
                $5157MaxEvents = 750
                Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $EventsScript = {
                        $Events = (Get-WinEvent -FilterHashtable @{
                            LogName = "Security"
                            ID = 5157
                            StartTime = $args[0]
                        } -MaxEvents $args[1] -ErrorAction Stop|
                        Select-Object @{
                            Name = "ProcessID"
                            Expression =
                            {
                                $_.Properties[0].Value
                            }
                        }, 
                        @{
                            Name = "Application"
                            Expression =
                            {
                                $_.Properties[1].Value
                            }
                        }, 
                        @{
                            Name = "Direction"
                            Expression =
                            {
                                $_.Properties[2].Value
                            }
                        }, 
                        @{
                            Name = "SourceAddress"
                            Expression =
                            {
                                $_.Properties[3].Value
                            }
                        }, 
                        @{
                            Name = "SourcePort"
                            Expression =
                            {
                                $_.Properties[4].Value
                            }
                        }, 
                        @{
                            Name = "DestAddress"
                            Expression =
                            {
                                $_.Properties[5].Value
                            }
                        }, 
                        @{
                            Name = "DestPort"
                            Expression =
                            {
                                $_.Properties[6].Value
                            }
                        }, 
                        @{
                            Name = "Protocol"
                            Expression =
                            {
                                $_.Properties[7].Value
                            }
                        })
                        return $Events
                    }
                }
                if ((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Invoke-Command*"}))
                {
                    if ((CancelAccept -Message "A $((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Invoke-Command*"}).State) job has been found for this computer.`r`nDo you wants to connect to that job or start a new scan?" -CancelButtonText "New" -AcceptButtonText "Connect") -eq "Cancel")
                    {
                        (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Invoke-Command*"})| Remove-Job
                        $EventsJob = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                            Invoke-Command -ScriptBlock $EventsScript -ArgumentList $args[0], $args[1]
                        } -AsJob -ArgumentList $NetworkStateChange, $5157MaxEvents
                    }
                    else
                    {
                        $EventsJob = (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Invoke-Command*"})
                    }
                }
                else
                {
                    $EventsJob = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                        Invoke-Command -ScriptBlock $EventsScript -ArgumentList $args[0], $args[1]
                    } -AsJob -ArgumentList $NetworkStateChange, $5157MaxEvents
                }
                $WaitTime = (Get-Date).AddSeconds(60)
                do
                {
                    $IndexNumber ++
                    $CharacterArray = ("--  ").ToCharArray()
                    $ScanComputerForBlockedConnectionsStatusBar.Text = "Scanning $Computer, please wait. $([string]($CharacterArray[-$IndexNumber..($CharacterArray.Count - $IndexNumber)]))"
                    if ($IndexNumber -eq $CharacterArray.Count)
                    {
                        $IndexNumber = 0
                    }
                    if ((Get-Date) -gt $WaitTime)
                    {
                        if ((CancelAccept -Message "$Computer`r`nscanning is taking longer than expected. If you`r`nabort waiting for this scan to complete the scan`r`nwill continue in the background and you can`r`ntry to get the results by starting a scan on`r`n$Computer`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
                        {
                            throw "Waiting for scan job to complete aborted."
                        }
                        $WaitTime = (Get-Date).AddSeconds(60)
                    }
                    start-sleep -Milliseconds 500
                }
                while ($EventsJob.State -eq "Running")
                $Events = $EventsJob| Receive-Job -Keep -ErrorAction SilentlyContinue
                if ($EventsJob.State -eq "Failed")
                {
                    if ($error[0].Exception.Message -eq "No events were found that match the specified selection criteria.")
                    {
                        throw "No events were found that match the specified selection criteria."
                    }
                    else
                    {
                        throw
                    }
                }
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - services."
                Set-Variable -Name "Services" -Value (Get-CimInstance -CimSession $ComputerCimSession -ClassName "Win32_Service") -Scope 1
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - drive letters."
                [System.Collections.ArrayList]$DriveLetters = @((Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Volume"| Where-Object {$_.DriveType -eq 3 -and $_.DriveLetter -ne $null}).DriveLetter)
                if ($DriveLetters.Count -eq 1)
                {
                    $SingleDriveLetter = $DriveLetters
                }
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - environment variables."
                $ProgramData = (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $env:ProgramData
                }).Replace("\", "\\")
                $ProgramFiles = (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $env:ProgramFiles
                }).Replace("\", "\\")
                $ProgramFilesX86 = (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    ${env:ProgramFiles(x86)}
                }).Replace("\", "\\")
                $SystemRoot = (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $env:SystemRoot
                }).Replace("\", "\\")
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - packages."
                Set-Variable -Name "Packages" -Value (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $Packages = @{}
                    foreach ($Package in (Get-AppxPackage -AllUsers))
                    {
                        $InstallLocation = $Package.InstallLocation -replace $args[0], "%ProgramData%" -replace $args[1], "%ProgramFiles%" -replace $args[2], "%ProgramFiles% (x86)" -replace $args[3], "%SystemRoot%"
                        if ($InstallLocation -and -not $Packages."$($InstallLocation)")
                        {
                            $Packages += @{$InstallLocation = $Package.PackageFamilyName}
                        }
                    }
                    return $Packages
                } -ArgumentList $ProgramData, $ProgramFiles, $ProgramFilesX86, $SystemRoot) -Scope 1
                (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $UserSids = @()
                    foreach ($PsChildName in ((Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-*').PsChildName))
                    {
                        $UserSids += $PsChildName
                    }
                })
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - package mappings."
                Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    New-PSDrive -Name "HKU" -PSProvider Registry -Root "HKEY_USERS"
                    }
                Set-Variable -Name "Mappings" -Value (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    $Mappings = @{}
                    foreach ($UserSid in $UserSids)
                    { # Get the App package family name to SID mappings from the registry on the scanned machine
                        if (Get-ChildItem -Path "HKU:\$($UserSid)_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\" -ErrorAction SilentlyContinue)
                        {
                            $Root = (Get-ChildItem -Path "HKU:\$($UserSid)_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\")
                            foreach ($Name in $Root.Name)
                            {
                                if ((Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker -and -not $Mappings."$((Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker)")
                                {
                                    $Mappings += @{(Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").Moniker = (Get-ItemProperty -path "HKU:\$Name" -Name "Moniker").PSChildName}
                                }
                            }
                        }
                    }
                    return $Mappings
                }) -Scope 1
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting details - domain subnets."
                [array]$AdHarvest = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest\" -Name "LastFetchContents").LastFetchContents.Split(", ")
                } # Not currently used
                [NetworkConnection[]]$NetworkConnections = @()
                $EventCount = 1
                $EventTotal = $Events.Count
                foreach ($Event in $Events)
                {
                    $ScanComputerForBlockedConnectionsStatusBar.Text = "Adding $EventCount of $EventTotal."
                    $EventCount ++
                    $NetworkConnection = New-Object -TypeName "NetworkConnection"
                    $NetworkConnection.ProcessID = $Event.ProcessID
                    $NetworkConnection.Application = $Event.Application
                    $NetworkConnection.Direction = $Event.Direction.Replace("%%14592", "Inbound").Replace("%%14593", "Outbound")
                    $NetworkConnection.SourceAddress = $Event.SourceAddress
                    $NetworkConnection.SourcePort = $Event.SourcePort
                    $NetworkConnection.DestAddress = $Event.DestAddress
                    $NetworkConnection.DestPort = $Event.DestPort
                    $NetworkConnection.Protocol = $Event.Protocol
                    $NetworkConnections += $NetworkConnection
                }
                $ScanComputerForBlockedConnectionsStatusBar.Text = $Language[13]
                Set-Variable -Name "FilteredNetworkConnections" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1
                Set-Variable -Name "FilteredNetworkConnections" -Value ([System.Collections.ArrayList]$FilteredNetworkConnections += ($NetworkConnections| Select-Object -Property * -ExcludeProperty "SourcePort" -Unique)) -Scope 1
                if ($SingleDriveLetter)
                {
                    foreach ($FilteredNetworkConnection in $FilteredNetworkConnections.Where({$_.Application -like "\device\*"}))
                    {
                        $FilteredNetworkConnection.Application
                        $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$SingleDriveLetter
                    }
                }
                else
                { # This will search for applications on the target computer, other methods to achieve this use commands that will not run in constrained mode and as this runs in a remote session this script's signature is invalid
                    $HarddiskVolumes = @{}
                    foreach ($FilteredNetworkConnection in $FilteredNetworkConnections.Where({$_.Application -like "\device\*"}))
                    {
                        $ApplicationCount = @()
                        $HardDiskVolume = $FilteredNetworkConnection.Application.Split("\")[2]
                        if ($HarddiskVolumes.$HardDiskVolume)
                        {
                            $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$HarddiskVolumes.$HardDiskVolume
                        }
                        else
                        {
                            foreach ($DriveLetter in $DriveLetters)
                            {
                                if (Invoke-Command -Session $ComputerPsSession -ScriptBlock {Test-Path -Path $args[0]} -ArgumentList ($FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$DriveLetter))
                                {
                                    $ApplicationCount += $DriveLetter
                                }
                            }
                            if ($ApplicationCount.Count -eq 1)
                            {
                                $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$ApplicationCount[0]
                                $HarddiskVolumes += @{$HardDiskVolume = $ApplicationCount[0]}
                                $DriveLetters.Remove($ApplicationCount[0])
                            }
                            else
                            {
                                $MultiplePaths = $true
                            }
                        }
                    }
                    if ($MultiplePaths)
                    { # If an application had multiple options the correct harddisk volume may have been found by a later application scan so we can run 1 last check
                        foreach ($FilteredNetworkConnection in $FilteredNetworkConnections.Where({$_.Application -like "\device\*"}))
                        {
                            $HardDiskVolume = $FilteredNetworkConnection.Application.Split("\")[2]
                            if ($HarddiskVolumes.$HardDiskVolume)
                            {
                                $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$HarddiskVolumes.$HardDiskVolume
                            }
                            else
                            {
                                foreach ($DriveLetter in $DriveLetters)
                                {
                                    if (Invoke-Command -Session $ComputerPsSession -ScriptBlock {Test-Path -Path $args[0]} -ArgumentList ($FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$DriveLetter))
                                    {
                                        $ApplicationCount += $DriveLetter
                                    }
                                }
                                if ($ApplicationCount.Count -eq 1)
                                {
                                    $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace "\\device\\harddiskvolume\d+",$ApplicationCount[0]
                                    $HarddiskVolumes += @{$HardDiskVolume = $ApplicationCount[0]}
                                    $DriveLetters.Remove($ApplicationCount[0])
                                }
                            }
                        }
                    }
                }
                $ApplicationFileDescription = @{}
                $ConnectionCount = $FilteredNetworkConnections.Count
                foreach ($FilteredNetworkConnection in $FilteredNetworkConnections)
                {
                    $Count ++
                    $ScanComputerForBlockedConnectionsStatusBar.Text = "$($Language[17]) $Count/$ConnectionCount"
                    $FilteredNetworkConnection.Service = @("Any")
                    if (($Services.Where({$_.ProcessId -eq $FilteredNetworkConnection.ProcessID})).Name)
                    {
                        $FilteredNetworkConnection.Service = @(($Services.Where({$_.ProcessId -eq $FilteredNetworkConnection.ProcessID})).DisplayName)
                    }
                    $FilteredNetworkConnection.Protocol = $FilteredNetworkConnection.Protocol -replace "^1$", "ICMPv4" -replace "^2$", "IGMP" -replace "^47$", "GRE" -replace "^6$", "TCP" -replace "^17$", "UDP" -replace "^58$", "ICMPv6"
                    If ($FilteredNetworkConnection.Application -ne "System" -and $FilteredNetworkConnection.Application -notlike "\device\*")
                    {
                        if ($FilteredNetworkConnection.Application -eq "$($SystemRoot.Replace("\\", "\"))\System32\svchost.exe")
                        {
                            $FilteredNetworkConnection.DisplayName = "SVCHOST $(($Services.Where({$_.ProcessId -eq $FilteredNetworkConnection.ProcessID})).DisplayName) (" + $FilteredNetworkConnection.Protocol + "-" + ($FilteredNetworkConnection.Direction).Replace("Outbound", "Out").Replace("Inbound", "In") + ")"
                        }
                        elseif ($ApplicationFileDescription.($FilteredNetworkConnection.Application))
                        { # If this application has already been scanned and the details are in the hash table, use that data
                            $FilteredNetworkConnection.DisplayName = "$($ApplicationFileDescription.($FilteredNetworkConnection.Application)) (" + $FilteredNetworkConnection.Protocol + "-" + ($FilteredNetworkConnection.Direction).Replace("Outbound", "Out").Replace("Inbound", "In") + ")"
                        }
                        else
                        {
                            $ApplicationFileDescription.($FilteredNetworkConnection.Application) = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-Item $args[0] -ErrorAction SilentlyContinue).VersionInfo.FileDescription} -ArgumentList $FilteredNetworkConnection.Application
                            if (-not $ApplicationFileDescription.($FilteredNetworkConnection.Application))
                            { # If the application does not exist at the time of the scan use the event record data to build the display name
                                $Executable = $FilteredNetworkConnection.Application.Split("\")| Select-Object -Last 1
                                $ApplicationFileDescription.($FilteredNetworkConnection.Application) = $Executable.Substring(0, 1).ToUpper() + $Executable.Substring(1, ($Executable.Length -1))
                            }
                            $FilteredNetworkConnection.DisplayName = "$($ApplicationFileDescription.($FilteredNetworkConnection.Application)) (" + $FilteredNetworkConnection.Protocol + "-" + ($FilteredNetworkConnection.Direction).Replace("Outbound", "Out").Replace("Inbound", "In") + ")"
                        }
                        $FilteredNetworkConnection.Application = $FilteredNetworkConnection.Application -replace $ProgramData, "%ProgramData%" -replace $ProgramFiles, "%ProgramFiles%" -replace $ProgramFilesX86, "%ProgramFiles% (x86)" -replace $SystemRoot, "%SystemRoot%"
                        if ($PortData."$($FilteredNetworkConnection.DestPort)-$($FilteredNetworkConnection.Protocol)")
                        {
                            $FilteredNetworkConnection.Notes = "$($FilteredNetworkConnection.DestPort) - " + $PortData."$($FilteredNetworkConnection.DestPort)-$($FilteredNetworkConnection.Protocol)"[1]
                        }
                    }
                    else
                    {
                        if ($PortData."$($FilteredNetworkConnection.DestPort)-$($FilteredNetworkConnection.Protocol)")
                        {
                            $FilteredNetworkConnection.DisplayName = $PortData."$($FilteredNetworkConnection.DestPort)-$($FilteredNetworkConnection.Protocol)"[0] + " (" + $FilteredNetworkConnection.Protocol + "-" + ($FilteredNetworkConnection.Direction).Replace("Outbound", "Out").Replace("Inbound", "In") + ")"
                            $FilteredNetworkConnection.Notes = "$($FilteredNetworkConnection.DestPort) - " + $PortData."$($FilteredNetworkConnection.DestPort)-$($FilteredNetworkConnection.Protocol)"[1]
                        }
                        else
                        {
                            $FilteredNetworkConnection.DisplayName = "Port " + $FilteredNetworkConnection.DestPort + " (" + $FilteredNetworkConnection.Protocol + "-" + ($FilteredNetworkConnection.Direction).Replace("Outbound", "Out").Replace("Inbound", "In") + ")"
                        }
                    }
                }
                $ScanComputerForBlockedConnectionsDataGridView.DataSource = $FilteredNetworkConnections
                $ScanComputerForBlockedConnectionsDataGridView.Columns["ProcessId"].Visible = $false
                $ScanComputerForBlockedConnectionsDataGridView.Columns["SourcePort"].Visible = $false
                $ScanComputerForBlockedConnectionsStatusBar.Text = $Language[18]
                $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsTextBox)
                $ToolPageForm.FormBorderStyle = "Sizable"
                $ToolPageForm.Location = $ToolSelectionPageForm.Location # Need to look closer at this.
                $ToolPageForm.Size = $ToolSelectionPageForm.Size
                $ToolPageForm.MinimumSize = $ToolSelectionPageForm.MinimumSize
                $ToolPageForm.WindowState = $ToolSelectionPageForm.WindowState
                $ToolPageForm.MaximizeBox = $true
                $ToolPageForm.MinimizeBox = $true
                $ToolPageForm.ControlBox = $true
                $ScanComputerForBlockedConnectionsAcceptButton.Text = "Create"
                $ScanComputerForBlockedConnectionsBackButton.Left = $ScanComputerForBlockedConnectionsAcceptButton.Left - $ScanComputerForBlockedConnectionsBackButton.Width - 5
                $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsBackButton)
                $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridView)
                $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridViewButtonPanel)
                $ScanComputerForBlockedConnectionsDataGridView.Focus()
                UpdateDataSourceForComboBoxCell -ArrayList $FilteredNetworkConnections -DataGridView $ScanComputerForBlockedConnectionsDataGridView
                foreach ($FilteredNetworkConnectionApplication in (($FilteredNetworkConnections.Application).Where({$_ -ne "System"})| Sort-Object -Unique))
                { # Check the file security to check if standard user accounts have delete, fullControl, modify, takeOwnership which can be exploited by users or malware
                    if (Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                        $Acl = Get-Acl -Path $args[0] -ErrorAction SilentlyContinue
                        if($Acl.Owner -notin $args[1], $args[2], $args[3], $args[4], $args[5])
                        {
                            return $true
                        }
                        else
                        {
                            foreach ($Access in $Acl.Access)
                            {
                                if ($Access.IdentityReference -notin $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $args[7])
                                {
                                    foreach ($FileSystemRight in ($Access.FileSystemRights -split ", "))
                                    {
                                        if ($FileSystemRight -in "Delete", "FullControl", "Modify", "TakeOwnership")
                                        {
                                            return $true
                                        }
                                    }
                                }
                            }
                        }
                    } -ArgumentList ($FilteredNetworkConnectionApplication -replace "%ProgramData%", $ProgramData  -replace "%ProgramFiles%", $ProgramFiles  -replace "%ProgramFiles% (x86)", $ProgramFilesX86 -replace "%SystemRoot%", $SystemRoot), $Language[39], $Language[40], $Language[41], $Language[42], $Language[43], $Language[44], $Language[45])
                    {
                        foreach ($ScanComputerForBlockedConnectionsDataGridViewRow in $ScanComputerForBlockedConnectionsDataGridView.Rows)
                        {
                            if ($ScanComputerForBlockedConnectionsDataGridViewRow.Cells[$ScanComputerForBlockedConnectionsDataGridView.Columns["Application"].Index].Value -eq $FilteredNetworkConnectionApplication)
                            {
                                $ScanComputerForBlockedConnectionsDataGridViewRow.Cells[$ScanComputerForBlockedConnectionsDataGridView.Columns["Application"].Index].Style.Backcolor = "Yellow"
                                $ScanComputerForBlockedConnectionsDataGridViewRow.Cells[$ScanComputerForBlockedConnectionsDataGridView.Columns["Application"].Index].ToolTipText = $Language[46]
                            }
                        }
                    }
                }
            }
            catch [System.Management.Automation.RuntimeException]
            {
                if ($error[0].Exception.Message -in "Connectivity test aborted, scanning cancelled.", "Waiting for scan job to complete aborted.", "DNS name does not exist")
                {
                }
                elseif ($error[0].Exception.Message -eq "Connectivity test failed.")
                {
                    PopUpMessage -Message "Connectivity test failed, is`r`n$Computer`r`navailable on the network and are`r`nTCP ports 135,5985 and 49152-65535`r`nopen from this computer."
                }
                elseif ($error[0].Exception.Message -eq "No events were found that match the specified selection criteria.")
                {
                    PopUpMessage -Message "No matching events were found since the last network`r`nstate change on $(($NetworkStateChange.AddSeconds(-1)).ToString()), event ID 4004 in`r`nlog 'Microsoft-Windows-NetworkProfile/Operational'"
                }
                elseif ($error[0].Exception.Message -eq "Failure auditing is not enabled.")
                {
                    PopUpMessage -Message $Language[15]
                }
                else
                {
                    PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)System.Management.Automation.RuntimeException"
                }
            }
            catch
            {
                PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)"
            }
            if ($ScanComputerForBlockedConnectionsTextBox.Parent)
            { # The datagridview control was not added so the status text is reset.
                $ScanComputerForBlockedConnectionsStatusBar.Text = $Language[16]
            }
            Remove-CimSession -CimSession $ComputerCimSession -ErrorAction SilentlyContinue
            Remove-PSSession -Session $ComputerPsSession
        }
        elseif ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
            [int[]]$SelectedIndices = @()
            for ($i = 0; $i -lt $ScanComputerForBlockedConnectionsDataGridView.Rows.Count; $i++)
            {
                if ($($ScanComputerForBlockedConnectionsDataGridView.Rows[$i].Cells[0].Value) -eq $true)
                {
                    $SelectedIndices += $i
                }
            }
            if ($SelectedIndices.Count)
            {
            Set-Variable -Name "WindowsFirewallRules" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1
            foreach ($ScanComputerForBlockedConnectionsRule in $FilteredNetworkConnections[$SelectedIndices])
            {
                $WindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule" -Property @{
                    PolicyStore = ""
                    Name = "{" + (New-Guid) + "}"
                    DisplayName = $ScanComputerForBlockedConnectionsRule.DisplayName
                    Description = ""
                    Group = ""
                    Enabled = $true
                    Profile = @("Domain")
                    Direction = $ScanComputerForBlockedConnectionsRule.Direction
                    Action = "Allow"
                    Protocol = $ScanComputerForBlockedConnectionsRule.Protocol
                    Program = $ScanComputerForBlockedConnectionsRule.Application
                }
                if ($ScanComputerForBlockedConnectionsRule.Direction -eq "Inbound")
                {
                    $WindowsFirewallRule.LocalAddress = @("Any")
                    $WindowsFirewallRule.RemoteAddress = @($ScanComputerForBlockedConnectionsRule.SourceAddress)
                    $WindowsFirewallRule.LocalPort = @($ScanComputerForBlockedConnectionsRule.DestPort)
                    $WindowsFirewallRule.RemotePort = @("Any")
                }
                else
                {
                    $WindowsFirewallRule.LocalAddress = @("Any")
                    $WindowsFirewallRule.RemoteAddress = @($ScanComputerForBlockedConnectionsRule.DestAddress)
                    $WindowsFirewallRule.LocalPort = @("Any")
                    $WindowsFirewallRule.RemotePort = @($ScanComputerForBlockedConnectionsRule.DestPort)
                }
                if ($Packages.((($ScanComputerForBlockedConnectionsRule.Application).Split("\")| Select-Object -SkipLast 1) -join "\"))
                {
                    $WindowsFirewallRule.Package = $Packages.((($ScanComputerForBlockedConnectionsRule.Application).Split("\")| Select-Object -SkipLast 1) -join "\")
                }
                if ($ScanComputerForBlockedConnectionsRule.Service.Count -gt 1)
                {
                    ResourceSelection -ResourceSelectionData $ScanComputerForBlockedConnectionsRule.Service -ResourceSelectionStatusBarText "$($Language[27]) $($ScanComputerForBlockedConnectionsRule.DisplayName)." -ResourceSelectionSelectionMode "One"
                    $WindowsFirewallRule.Service = $SelectedItems
                }
                else
                {
                    $WindowsFirewallRule.Service = $ScanComputerForBlockedConnectionsRule.Service
                }
                Set-Variable -Name "WindowsFirewallRules" -Value ([System.Collections.ArrayList]($WindowsFirewallRules + $WindowsFirewallRule)) -Scope 1
            }
            $ScanComputerForBlockedConnectionsStatusBar.Text = "$($WindowsFirewallRules.Count) rule(s) imported, edit rules and then select one or more rules to create the commands."
            EditFirewallRules
            $EditFirewallRulesDataGridView.DataSource = $WindowsFirewallRules
            $ScanComputerForBlockedConnectionsPanel.Controls.Add($EditFirewallRulesPanel)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridViewButtonPanel)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridView)
            UpdateDataSourceForComboBoxCell -ArrayList $WindowsFirewallRules -DataGridView $EditFirewallRulesDataGridView # This needs to run after the gridview control has been added so that the rows exist
            }
            else
            {
                PopUpMessage -Message $Language[18]
            }
        }
        elseif ($EditFirewallRulesPanel.Parent)
        {
            [int[]]$SelectedIndices = @()
            for ($i = 0; $i -lt $EditFirewallRulesDataGridView.Rows.Count; $i++)
            {
                if ($($EditFirewallRulesDataGridView.Rows[$i].Cells[0].Value) -eq $true)
                {
                    $SelectedIndices += $i
                }
            }
            if ($SelectedIndices.Count)
            {
                BuildCommands
            }
            else
            {
                PopUpMessage -Message "Please select one or more rules."
            }
        }
    })
    $ScanComputerForBlockedConnectionsBackButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[24]
        Anchor = "Right"
    }
    $ScanComputerForBlockedConnectionsBackButton.Left = $ScanComputerForBlockedConnectionsAcceptButton.Left - $ScanComputerForBlockedConnectionsBackButton.Width - 5
    $ScanComputerForBlockedConnectionsBackButton.Add_Click(
    {
        if ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
            $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Remove($ScanComputerForBlockedConnectionsBackButton)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridViewButtonPanel)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridView)
            $ToolPageForm.FormBorderStyle = "FixedDialog"
            $ToolPageForm.Location = @{
                X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125
                Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55
            }
            $ToolPageForm.MinimumSize = @{
                Width = 0
                Height = 0
            }
            $ToolPageForm.Size = @{
                Width = 250
                Height = 110
            }
            $ToolPageForm.WindowState = "Normal"
            $ToolPageForm.MaximizeBox = $false
            $ToolPageForm.MinimizeBox = $false
            $ToolPageForm.ControlBox = $false
            $ScanComputerForBlockedConnectionsAcceptButton.Text = "Scan"
            $ScanComputerForBlockedConnectionsStatusBar.Text = $Language[16]
            $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
            $ScanComputerForBlockedConnectionsTextBox.focus()
        }
        elseif ($EditFirewallRulesPanel.Parent)
        {
            if ((CancelAccept -Message $Language[19] -CancelButtonText $Language[21] -AcceptButtonText $Language[20]) -eq "OK")
            {
                $ScanComputerForBlockedConnectionsStatusBar.Text = $Language[18]
                $DataGridView = $ScanComputerForBlockedConnectionsDataGridView
                $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridView)
                $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridViewButtonPanel)
                $ScanComputerForBlockedConnectionsPanel.Controls.Remove($EditFirewallRulesPanel)
                UpdateDataSourceForComboBoxCell -ArrayList $FilteredNetworkConnections -DataGridView $ScanComputerForBlockedConnectionsDataGridView
            }
        }
    })
    $ToolPageForm.CancelButton = $ScanComputerForBlockedConnectionsCancelButton
    $ToolPageForm.AcceptButton = $ScanComputerForBlockedConnectionsAcceptButton
    $ScanComputerForBlockedConnectionsDataGridView = New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{
        AutoSize = $true
        BackGroundColor = "WhiteSmoke"
        Dock = "None"
        AutoGenerateColumns = $false
        ColumnHeadersHeightSizeMode = 'AutoSize'
        MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
        RowHeadersVisible = $false
    }
    $ScanComputerForBlockedConnectionsDataGridView.Add_CurrentCellChanged(
    {
        if ($ScanComputerForBlockedConnectionsDataGridView.CurrentCell.OwningColumn.Name -in "SourceAddress", "DestAddress")
        {
                $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton.Visible = $true
        }
        else
        {
            $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton.Visible = $false
        }
    })
    $ScanComputerForBlockedConnectionsDataGridView.Add_SizeChanged(
    {
        $ScanComputerForBlockedConnectionsDataGridView.Size = $ScanComputerForBlockedConnectionsDataGridView.PreferredSize
        $ScanComputerForBlockedConnectionsDataGridViewButtonPanel.Location = @{
            X = 0
            Y = $ScanComputerForBlockedConnectionsDataGridView.Bottom
        }
        $ScanComputerForBlockedConnectionsDataGridViewButtonPanel.Width = $ScanComputerForBlockedConnectionsDataGridView.width
    })
    $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn" -Property @{
        AutoSizeMode = "AllCellsExceptHeader"
    }))
    $ScanComputerForBlockedConnectionsDataGridView.Columns[0].DefaultCellStyle.Alignment = "TopLeft"
    $ColumnIndex = 1
    $EmptyNetworkConnection = New-Object -TypeName "NetworkConnection"
    ColumnHeaderContextMenuStrip -DataGridView $ScanComputerForBlockedConnectionsDataGridView
    foreach ($PropertyName in ($EmptyNetworkConnection.PsObject.Properties).name)
    {
        if ($PropertyName -in "ProcessId", "DisplayName", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol", "Notes")
        {
            $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{
                ReadOnly = $true
            }))
            $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
            $ScanComputerForBlockedConnectionsDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
        }
        else
        {
            $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{
                FlatStyle = "Popup"
            }))
            $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
        }
        $ScanComputerForBlockedConnectionsDataGridView.Columns["$PropertyName"].DefaultCellStyle.Alignment = "TopLeft"
        $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].HeaderCell.ContextMenuStrip = $ColumnHeaderContextMenuStrip
        $ColumnIndex ++
    }
    $ScanComputerForBlockedConnectionsDataGridView.Columns["DisplayName"].Frozen = $true
    $ScanComputerForBlockedConnectionsDataGridView.Columns["DisplayName"].Width = 150
    $ScanComputerForBlockedConnectionsDataGridView.Columns["Direction"].Width = 55
    $ScanComputerForBlockedConnectionsDataGridView.Columns["SourcePort"].Width = 55
    $ScanComputerForBlockedConnectionsDataGridView.Columns["DestPort"].Width = 55
    $ScanComputerForBlockedConnectionsDataGridView.Columns["Protocol"].Width = 55
    $ScanComputerForBlockedConnectionsDataGridView.Columns["Notes"].DefaultCellStyle.Padding = @{
        Left=0
        Top=2
        Right=0
        Bottom=2
    }
    $ScanComputerForBlockedConnectionsDataGridView.Columns["Notes"].DefaultCellStyle.WrapMode = "True"
    $ScanComputerForBlockedConnectionsDataGridView.Columns["Notes"].Width = 300
    $ScanComputerForBlockedConnectionsDataGridViewButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ScanComputerForBlockedConnectionsDataGridView.Width
        Height = 22
        Dock = "None"
        BackColor = "WhiteSmoke"
        Location = @{
            X = 0
            Y = $ScanComputerForBlockedConnectionsDataGridView.Bottom
        }
    }
    $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[30]
        Anchor = "Right"
    }
    $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton.Left = $ScanComputerForBlockedConnectionsDataGridViewButtonPanel.Width - $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton.Width - 16
    $ScanComputerForBlockedConnectionsDataGridViewNsLookupButton.Add_Click(
    {
        NsLookup -IpAddresses $ScanComputerForBlockedConnectionsDataGridView.SelectedCells.Value
    })
    $ScanComputerForBlockedConnectionsTextBox = New-Object -TypeName "System.Windows.Forms.TextBox" -Property @{
        width = $ToolPageForm.Width - 36
        Location = @{
            X = 10
            Y= 5
        }
        Text = "LocalHost"
    }
    $ScanComputerForBlockedConnectionsStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = $Language[16]
    }
    $ScanComputerForBlockedConnectionsPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Dock = "Fill"
        BackColor = "WhiteSmoke"
    }
    $ScanComputerForBlockedConnectionsPanel.Add_SizeChanged(
    {
        $ScanComputerForBlockedConnectionsDataGridViewButtonPanel.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = 22
        }
        $ScanComputerForBlockedConnectionsDataGridView.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
    })
    $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
    $ScanComputerForBlockedConnectionsDataGridViewButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridViewNsLookupButton)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsCancelButton)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsAcceptButton)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsStatusBar)
    [void]$ToolPageForm.ShowDialog()
}

function ExportExistingRulesToPowerShellCommandsPage
{
    $ToolPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Export existing rules to PowerShell commands"
    }
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            GroupPoliciesWithExistingFirewallRules -GroupPoliciesWithExistingFirewallRulesStatusBar $ExportExistingRulesToPowerShellCommandsStatusBar
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($GroupPolicy in $Script:GroupPoliciesWithExistingFirewallRules)
        { # Loop through GPOs and add to listbox 
            [void]$ExportExistingRulesToPowerShellCommandsGpoListBox.Items.Add($GroupPolicy)
        }
        $ExportExistingRulesToPowerShellCommandsGpoListBox.SetSelected(0, $true)
        $DefaultPageCancelButton.Left = $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
        $ExportExistingRulesToPowerShellCommandsSaveAsButton.Left = $DefaultPageCancelButton.Left - $ExportExistingRulesToPowerShellCommandsSaveAsButton.Width - 5 
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsSaveAsButton)
        $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $ExportExistingRulesToPowerShellCommandsBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog.Filter = "PowerShell Files (*.ps1)|*.ps1|All files (*.*)|*.*"
    $ExportExistingRulesToPowerShellCommandsSaveAsButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = "Save As"
        Anchor = "Right"
    }
    $ExportExistingRulesToPowerShellCommandsSaveAsButtonClick =
    { # This is created as a script outside the click event because it's also used as a double click event, if the double click event calls the click event that would create an additional scope and object data is lost
        if ($ExportExistingRulesToPowerShellCommandsSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $GPOSession = Open-NetGPO -PolicyStore ("$DomainName\$($ExportExistingRulesToPowerShellCommandsGpoListBox.SelectedItem)")
            [array]$FirewallRules = Get-NetFirewallRule -GPOSession $GPOSession
            $RuleProgress = 1
            foreach ($FirewallRule in $FirewallRules)
            { # This function does not check for the properties InterfaceAlias, InterfaceType and Security. These may be added in a future build.
                $ProgressBar.Value = ($RuleProgress*($OneHundredPercent/$FirewallRules.Count))
                $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Exporting rule $($FirewallRule.DisplayName)" 
                $RuleProgress ++
                $Command = @"
New-NetFirewallRule -GPOSession `$GPOSession
"@
                $Value = ($FirewallRule.Name  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                $Command += @"
 -Name "$Value"
"@
                $Value = ($FirewallRule.DisplayName  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                $Command += @"
 -DisplayName "$Value"
"@
                $Value = ($FirewallRule.Description  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                if ($Value -ne $null)
                {
                    $Command += @"
 -Description "$Value"
"@
                }
                $Value = ($FirewallRule.Group  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                if ($Value -ne $null)
                {
                    $Command += @"
 -Group "$Value"
"@
                }
                $Value = $FirewallRule.Enabled
                if ($Value -ne "True")
                {
                    $Command += @"
 -Enabled "$Value"
"@
                }
                $Value = $FirewallRule.Profile
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Profile "$Value"
"@
                }
                $Value = $FirewallRule.Platform
                if($Value -ne $null)
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -Platform "$Value"
"@
                }
                $Value = $FirewallRule.Direction
                if ($Value -ne "Inbound")
                {
                    $Command += @"
 -Direction "$Value"
"@
                }
                $Value = $FirewallRule.Action
                if ($Value -ne "Allow")
                {
                    $Command += @"
 -Action "$Value"
"@
                }
                $Value = $FirewallRule.EdgeTraversalPolicy
                if ($Value -ne "Block")
                {
                    $Command += @"
 -EdgeTraversalPolicy "$Value"
"@
                }
                $Value = $FirewallRule.LooseSourceMapping
                if ($Value -ne $false)
                {
                    $Command += @"
 -LooseSourceMapping "$true"
"@
                }
                $Value = $FirewallRule.LocalOnlyMapping
                if ($Value -ne $false)
                {
                    $Command += @"
 -LocalOnlyMapping "$true"
"@
                }
                $Value = $FirewallRule.Owner
                if ($Value -ne $null)
                {
                    $Command += @"
 -Owner "$Value"
"@
                }  
                $Value = ($FirewallRule| Get-NetFirewallAddressFilter -GPOSession $GPOSession).RemoteAddress
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -RemoteAddress "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallAddressFilter -GPOSession $GPOSession).LocalAddress
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -LocalAddress "$Value"
"@
                }
                $Value = (($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Program "$Value"
"@
                } 
                $Value = (($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                if ($Value -ne $null)
                {
                    $Command += @"
 -Package "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).Protocol
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Protocol "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).LocalPort
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -LocalPort "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).RemotePort
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -RemotePort "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).IcmpType
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '", "'
                    $Command += @"
 -IcmpType "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).DynamicTarget
                if ($Value -ne "Any")
                {
                    $Command += @"
 -DynamicTarget "$Value"
"@
                }         
                $Value = (($FirewallRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service  -replace '`', '``' -replace "'", "``'" -replace '"', '`"').Replace('$', '`$')
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Service "$Value"
"@
                }
                [string[]]$Commands += $Command
            }
            $Commands| Out-File $ExportExistingRulesToPowerShellCommandsSaveFileDialog.FileName
            Remove-Variable -Name "GPOSession" -Force
            $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
    }
    $ExportExistingRulesToPowerShellCommandsSaveAsButton.Add_Click($ExportExistingRulesToPowerShellCommandsSaveAsButtonClick)
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $ExportExistingRulesToPowerShellCommandsSaveAsButton
    $ExportExistingRulesToPowerShellCommandsGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
    }
    $ExportExistingRulesToPowerShellCommandsGpoListBox.Add_DoubleClick($ExportExistingRulesToPowerShellCommandsSaveAsButtonClick)
    $ExportExistingRulesToPowerShellCommandsStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Select a policy to export."
    }
    $ExportExistingRulesToPowerShellCommandsPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $ExportExistingRulesToPowerShellCommandsPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsGpoListBox)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function MainThread
{
    $DomainName = $env:USERDNSDOMAIN
    $OneHundredPercent = 100
    $FontSizeDivisor = 45
    $MarginDivisor = 20
    $PaddingDivisor = 125
    $ToolTipAutoPopDelayMultiplier = 800
    $DropDownWidthMultiplier = 6
    $ToolSelectionPageForm = New-Object -TypeName "System.Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        StartPosition = "CenterScreen"
        Width = 1024
        Height = 512
        MinimumSize = @{
            Width = 310
            Height = 200
        }
        Text = $Language[0]
    }
    $ToolSelectionPageBottomButtonPanel = New-Object -TypeName "System.Windows.Forms.Panel" -Property @{
        Width = $ToolSelectionPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ToolSelectionPageCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[12]
        Anchor = "Right"
    }
    $ToolSelectionPageCancelButton.Left = $ToolSelectionPageBottomButtonPanel.Width - $ToolSelectionPageCancelButton.Width - 16
    $ToolSelectionPageForm.CancelButton = $ToolSelectionPageCancelButton
    $DefaultPageCancelButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Text = $Language[12]
        Anchor = "Right"
    }
    $DefaultPageCancelButton.Add_Click(
    {
        $ToolSelectionPageForm.Size = $ToolPageForm.Size
        $ToolSelectionPageForm.Location = $ToolPageForm.Location
    })
    $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
    [int]$FontSize = $SquareRootOfFormSize / $FontSizeDivisor
    [int]$Margin = $SquareRootOfFormSize / $MarginDivisor
    [int]$Padding = $SquareRootOfFormSize / $PaddingDivisor
    $ToolButtonPanel = New-Object -TypeName "System.Windows.Forms.FlowLayoutPanel" -Property @{
        BackColor = "WhiteSmoke"
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolSelectionPageForm.Width - 16
        Height = $ToolSelectionPageForm.Height - 82
        FlowDirection = "LeftToRight"
    }
    $ToolButtonPanel.Add_SizeChanged(
    {
        $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
        [int]$FontSize = $SquareRootOfFormSize / $FontSizeDivisor
        [int]$Margin = $SquareRootOfFormSize / $MarginDivisor
        [int]$Padding = $SquareRootOfFormSize / $PaddingDivisor
        $BoldButtonFont = New-Object -TypeName "System.Drawing.Font"("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold)
        $ExportExistingRulesToPowerShellCommandsButton.Font = $BoldButtonFont
        $ExportExistingRulesToPowerShellCommandsButton.Margin = $Margin
        $ExportExistingRulesToPowerShellCommandsButton.Padding = $Padding
        $FindAllPoliciesWithFirewallRulesButton.Font = $BoldButtonFont
        $FindAllPoliciesWithFirewallRulesButton.Margin = $Margin
        $FindAllPoliciesWithFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $UpdateDomainResourcesButton.Font = $BoldButtonFont
        $UpdateDomainResourcesButton.Margin = $Margin
        $UpdateDomainResourcesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $EditExistingFirewallRulesButton.Font = $BoldButtonFont
        $EditExistingFirewallRulesButton.Margin = $Margin
        $EditExistingFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $ScanComputerForBlockedConnectionsButton.Font = $BoldButtonFont
        $ScanComputerForBlockedConnectionsButton.Margin = $Margin
        $ScanComputerForBlockedConnectionsButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
    })
    $BoldButtonFont = New-Object -TypeName "System.Drawing.Font"("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold) 
    $ExportExistingRulesToPowerShellCommandsButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Margin = $Margin
        Padding = $Padding
        Width = 270
        Height = 84
        AutoSize = $true
        AutoSizeMode = "GrowAndShrink"
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $ExportExistingRulesToPowerShellCommandsButton.Text = $Language[1] # As this button contains the most text all other buttons will inherit it's size
    $ExportExistingRulesToPowerShellCommandsButton.Add_SizeChanged(
    {
        $FindAllPoliciesWithFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $UpdateDomainResourcesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $EditExistingFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $ScanComputerForBlockedConnectionsButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
    })
    $ExportExistingRulesToPowerShellCommandsButton.Add_Click(
    {
        if (CheckForGpoModule)
        {
            $ToolSelectionPageForm.Hide()
            ExportExistingRulesToPowerShellCommandsPage
            $ToolSelectionPageForm.Show()
        }  
    })
    $ExportExistingRulesToPowerShellCommandsToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $ExportExistingRulesToPowerShellCommandsToolTip.AutoPopDelay = [math]::Sqrt(($Language[2]).Length) * $ToolTipAutoPopDelayMultiplier
    $ExportExistingRulesToPowerShellCommandsToolTip.SetToolTip($ExportExistingRulesToPowerShellCommandsButton, $Language[2])
    $FindAllPoliciesWithFirewallRulesButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $FindAllPoliciesWithFirewallRulesButton.Text = $Language[3]
    $FindAllPoliciesWithFirewallRulesButton.Add_Click(
    {
        if (CheckForGpoModule)
        {
            $ToolSelectionPageForm.Hide()
            FindAllPoliciesWithFirewallRulesPage
            $ToolSelectionPageForm.Show()
        } 
    })
    $FindAllPoliciesWithFirewallRulesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $FindAllPoliciesWithFirewallRulesToolTip.AutoPopDelay = [math]::Sqrt(($Language[4]).Length) * $ToolTipAutoPopDelayMultiplier
    $FindAllPoliciesWithFirewallRulesToolTip.SetToolTip($FindAllPoliciesWithFirewallRulesButton, $Language[4])
    $UpdateDomainResourcesButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $UpdateDomainResourcesButton.Text = $Language[5]
    $UpdateDomainResourcesButton.Add_Click(
    {
        if ($null -eq $DomainControllers)
        {
            DefaultDomainResources -DefaultDomainResourcesStatusBar $ToolSelectionPageStatusBar
        }
        $ToolSelectionPageForm.Hide()
        UpdateDomainResourcesPage
        $ToolSelectionPageForm.Show()   
    })
    $UpdateDomainResourcesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $UpdateDomainResourcesToolTip.SetToolTip($UpdateDomainResourcesButton, $Language[6])
    $UpdateDomainResourcesToolTip.AutoPopDelay = [math]::Sqrt(($UpdateDomainResourcesToolTip.GetToolTip).Length) * $ToolTipAutoPopDelayMultiplier
    $EditExistingFirewallRulesButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $EditExistingFirewallRulesButton.Text = $Language[7]
    $EditExistingFirewallRulesButton.Add_Click(
    {
        if (CheckForGpoModule)
        {
            $ToolSelectionPageForm.Hide()
            EditExistingFirewallRulesPage
            $ToolSelectionPageForm.Show()
        }  
    })
    $EditExistingFirewallRulesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $EditExistingFirewallRulesToolTip.AutoPopDelay = [math]::Sqrt(($Language[8]).Length) * $ToolTipAutoPopDelayMultiplier
    $EditExistingFirewallRulesToolTip.SetToolTip($EditExistingFirewallRulesButton, $Language[8])
    $ScanComputerForBlockedConnectionsButton = New-Object -TypeName "System.Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $ScanComputerForBlockedConnectionsButton.Text = $Language[9]
    $ScanComputerForBlockedConnectionsButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        ScanComputerForBlockedConnectionsPage
        $ToolSelectionPageForm.Show()   
    })
    $ScanComputerForBlockedConnectionsToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $ScanComputerForBlockedConnectionsToolTip.AutoPopDelay = [math]::Sqrt(($Language[10]).Length) * $ToolTipAutoPopDelayMultiplier
    $ScanComputerForBlockedConnectionsToolTip.SetToolTip($ScanComputerForBlockedConnectionsButton, $Language[10])
    $ToolSelectionPageStatusBar = New-Object -TypeName "System.Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = $Language[11]
    }
    $ToolSelectionPageBottomButtonPanel.Controls.Add($ToolSelectionPageCancelButton)
    $ToolButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsButton)
    $ToolButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($UpdateDomainResourcesButton)
    $ToolButtonPanel.Controls.Add($EditExistingFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsButton)
    $ToolSelectionPageForm.Controls.Add($ToolButtonPanel) 
    $ToolSelectionPageForm.Controls.Add($ToolSelectionPageBottomButtonPanel) 
    $ToolSelectionPageForm.Controls.Add($ToolSelectionPageStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolSelectionPageForm.ShowDialog()
}

$EnglishPortData = @{
"0-ICMPv4" = "Echo request", "Ping, can be used to exfiltrate data and should not be used to the Internet"
"0-ICMPv6" = "Echo request", "Ping, can be used to exfiltrate data and should not be used to the Internet"
"22-TCP" = "SSH", "Can be used by malware to connect to command and control servers.`r`nShould only be allowed to trusted addresses.`r`nCommonly used to tunnel other traffic and bypass firewalls."
"67-UDP" = "DHCP request", "Clients broadcast DHCP requests, inbound requests only need to be allowed on DHCP servers."
"80-TCP" = "HTTP", "Unsecured web service, consider using secure HTTPS.`r`nCan be used by malware to connect to command and control servers.`r`nShould only be allowed to trusted addresses."
"443-TCP" = "HTTPS", "Can be used by malware to connect to command and control servers.`r`nShould only be allowed to trusted addresses.`r`nCommonly used to tunnel other traffic and bypass firewalls."
"445-TCP" = "SMB", "File sharing, can be used to exfiltrate data and should not be used to the Internet.`r`nClients should only accept inbound connections from tier management resources.`r`nCan be used by malware compromise computers across the network."
}

$English = @( # `n and `r`n are used for new lines
"Windows firewall tool selection"
"Export existing`n rules to`nPowerShell commands"
"Use this tool to query a domain for policies`nthat have existing firewall rules and then`nexport a policy to a PowerShell script.`n"
"Find all policies with firewall rules"
"Use this tool to query a domain for policies`nthat have existing firewall rules, this list`ncan then be saved to a text file as reference.`n"
"  Update domain resources"
"Use this tool to update domain resources that can be used`nto create or update firewall rules in group policy objects.`nNames can be used and will be translated into IP addresses`nwhich can be applied to multiple rules.`n"
"Edit existing firewall rules"
"Use this tool to edit existing firewall rules, domain resources can be`nselected and DNS will be used to resolve all IP addresses to be used.`nMultiple rules can be edited at once and saved to a PowerShell`nscript or saved back to the domain.`nBeta 1."
"Scan computer for blocked connections"
"Use this tool to scan a computer for blocked network`nconnections and to create new firewall rules that can be`nsaved to a PowerShell script or saved to a group policy object.`nBeta 1."
"Please select a tool to launch."
"Exit"
"Removing duplicate entries."
"This script invokes a GUI and cannot be run over a remote session or on PowerShell Core editions."
"Filtering platform connection auditing is not enabled.`r`nThis can be enabled using the command;`r`nAuditpol /Set /Subcategory:`"Filtering Platform Packet Drop`" /Failure:Enable`r`nOr via group policy at the location;`"Computer Configuration\Policies\Windows Settings\`r`nSecurity Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\`r`nAudit Filtering Platform Connection"
"Enter a computer name or IP address to scan."
"Updating blocked connection"
"Please select one or more rules to create."
"Are you sure, any unsaved`r`nchanges will be lost?"
"Yes"
"No"
"Resource selection"
"Please select a GPO to update."
"Back"
"Select"
"Exit"
"Select the service to be used for"
"Remove"
"Add"
"NsLookup"
"Change"
"Host name not found."
"Nothing selected."
"Group policy module not found.`r`nThis tool is not available without this module.`r`Please install the RSAT tools on clients or add`r`nthe group policy management feature on servers."
"Scanning policy"
"Updating resource"
" could not be resolved,check connectivity to`r`nthe DNS infrastructure and ensure there is a valid host record."
" is an invalid proxy port."
"BUILTIN\Administrators"
"NT AUTHORITY\SYSTEM"
"NT AUTHORITY\LOCAL SERVICE"
"NT AUTHORITY\NETWORK SERVICE"
"NT SERVICE\TrustedInstaller"
"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"
"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES"
"This security on this could not be determined or the file appears to grant delete rights to non privileged accounts, please review.`r`nMalware or a malicious user could overwrite this application and gain access to the network resources allowed to this application.`r`nConsider moving this application to a location where standard users do not have delete rights."
"Hide"
"Freeze/Unfreeze"
"Restore defaults"
"Please select a package."
"Collecting package mappings."
"Any"
"Packages only"
"Services only"
"Please select a service."
"Collecting services."
"Error processing command;`r`n"
"`r`nThe rule has been created/modified by a newer version`r`nof the OS and cannot be updated from this machine.`r`nPlease use this tool on a more recent OS."
"Command processing completed."
)

$EnglishUpdateDomainResourcesToolTips = @(
"Backup servers"
"Clustered nodes and management IP addresses"
"CRL servers"
"DirectAccess servers`r`nThis is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint."
"DNS servers`r`nSpecify these if you do not have DNS on each domain controller or you have additional DNS servers."
"Domain controllers"
"External VPN endpoints`r`nThis is the externally resolvable IPSec hostname or address."
"File servers"
"Key management servers"
"Microsoft subnets"
"Proxy server ports"
"Proxy servers"
"Server role administration servers`r`nThese are trusted machines used by tier administrators permitted to administer a server role."
"SQL servers"
"Tier X management servers`r`nThese are used in tier X firewall baselines to define which computers can manage the device at a particular tier."
"Trusted DHCP subnets`r`nThis is client enterprise subnets and includes subnets issued by the VPN server, `"Predefined set of computers`" cannot be used here."
"Web servers"
"WPAD and PAC file servers"
)

switch -Wildcard ((Get-UICulture).Name)
{
    default
    {
        $Language = $English
        $PortData = $EnglishPortData
        $UpdateDomainResourcesToolTips = $EnglishUpdateDomainResourcesToolTips
    }
}

if ((Get-Host).Name -eq "ServerRemoteHost" -or $PSVersionTable.PSEdition -eq "Core")
{
    Write-Warning -Message $Language[14]
    break
}

Add-Type -Assembly "System.Windows.Forms"
[System.Windows.Forms.Application]::EnableVisualStyles()

MainThread
