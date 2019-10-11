function Hide-Console {
    # https://stackoverflow.com/questions/40617800/opening-powershell-script-and-hide-command-prompt-but-not-the-gui
    # .NET methods for hiding/showing the console in the background
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0) # 0 = hide
}

Function New-GuiHeading {
    param(
        [Parameter(Mandatory)][string]$name
    )
    $string = Get-Content "$moduleRoot\xaml\heading.xaml"
    $string = $string.Replace('INSERT_SECTION_HEADING',(Get-XamlSafeString $name) )
    $string = $string.Replace('INSERT_ROW',$row)
    $script:row++

    return $string
}

Function New-GuiRow {
    param(
        [Parameter(Mandatory)][PSCustomObject]$item
    )
    $string = Get-Content "$moduleRoot\xaml\item.xaml"
    $string = $string.Replace('INSERT_BACKGROUND_COLOR',$buttonBackgroundColor)
    $string = $string.Replace('INSERT_FOREGROUND_COLOR',$buttonForegroundColor)
    $string = $string.Replace('INSERT_BUTTON_TEXT',(Get-XamlSafeString $item.Name) )
    # Description is optional
    if ($item.Description) {
        # TODO: Window MinWidth is too high if no items have Description
        $string = $string.Replace('INSERT_DESCRIPTION',(Get-XamlSafeString $item.Description) )
    }
    else {
        $string = $string.Replace('INSERT_DESCRIPTION','')
    }
    $string = $string.Replace('INSERT_BUTTON_NAME',$item.Reference)
    $string = $string.Replace('INSERT_ROW',$row)
    $script:row++

    return $string
}

Function Get-XamlSafeString {
    param(
        [Parameter(Mandatory)][string]$string
    )
    # https://docs.microsoft.com/en-us/dotnet/framework/wpf/advanced/how-to-use-special-characters-in-xaml
    # Order matters: &amp first
    $string = $string.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    # Preserves line breaks. A bit hacky. Bad idea?
    # https://stackoverflow.com/questions/183406/newline-in-string-attribute
    $string = $string.Replace('&lt;LineBreak /&gt;','<LineBreak />')

    return $string
}

Function New-GuiForm {
    # Based on: https://foxdeploy.com/2015/05/14/part-iii-using-advanced-gui-elements-in-powershell/
    param (
        [Parameter(Mandatory)][array]$inputXml # XML has not been converted to object yet
    )
    # Process raw XML
    $inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*','<Window'

    # Read XAML
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]$xaml = $inputXML
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    try {
        $form = [Windows.Markup.XamlReader]::Load($reader)
    }
    catch {
        Write-Warning "Unable to parse XML!
Ensure that there are NO SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them).
Note that this module does not currently work with PowerShell 7-preview and the VS Code integrated console."
        throw
    }

    #region Load XAML objects in PowerShell
    $xaml.SelectNodes("//*[@Name]") | ForEach-Object {
        try {
            # TODO: could put these in a hashtable instead
            Set-Variable -Name "WPF_$($_.Name)" -Value $Form.FindName($_.Name) -ErrorAction Stop -Scope script
        }
        catch {
            throw
        }
    }

    return $form
}

Function Start-Script {
    param(
        [Parameter(Mandatory)][string]$buttonName
    )
    # Get relevant CSV row
    $csvMatch = $csvData | Where-Object {$_.Reference -eq $buttonName}

    # TODO: check that target file exist?

    # Begin constructing arguments
    $arguments = '-ExecutionPolicy Bypass '
    if ($noExit) {
        # TODO: could be a per-script setting
        $arguments += '-NoExit -NoLogo '
    }
    $command = $csvMatch.Command
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

    switch ($csvMatch.Method) {
        # TODO: section could be more compact
        # TODO: arguments do not currently work
        powershell_file {
            $arguments += "-File `"$command`""
            Start-Process -FilePath "powershell.exe" -ArgumentList $arguments
        }
        powershell_inline {
            $arguments = "-EncodedCommand `"$encodedCommand`""
            Start-Process -FilePath "powershell.exe" -ArgumentList $arguments
        }
        pwsh_file {
            $arguments += "-File `"$command`""
            Start-Process -FilePath "pwsh.exe" -ArgumentList $arguments
        }
        pwsh_inline {
            $arguments = "-EncodedCommand `"$encodedCommand`""
            Start-Process -FilePath "pwsh.exe" -ArgumentList $arguments
        }
        cmd {
            Start-Process -FilePath $command
        }
    }
}