Function Show-ScriptMenuGui {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory)]$csvPath,
        [string]$windowTitle = 'PowerShell Script Menu',
        [string]$buttonForegroundColor = 'White',
        [string]$buttonBackgroundColor = '#366EE8',
        [string]$iconPath,
        [switch]$hideConsole,
        [switch]$noExit
    )

    if ($hideConsole) {
        # TODO: This will also hide errors. Should be done later?
        Hide-Console | Out-Null
    }

    $csvData = Import-CSV $csvPath
    # TODO: validate CSV input

    # Add unique Reference to each item
    # Used as x:Name of button and to look up action on click
    $i = 0
    $csvData | ForEach-Object {
        $_ | Add-Member -Name Reference -MemberType NoteProperty -Value "button$i"
        $i++
    }

    # Begin constructing XAML
    $xaml = @()
    $xaml += Get-Content "$moduleRoot\xaml\start.xaml"
    $xaml = $xaml.Replace('INSERT_WINDOW_TITLE',$windowTitle)
    if ($iconPath) {
        # TODO: change taskbar icon?
        $iconPath = (Resolve-Path $iconPath).Path
        $xaml = $xaml.Replace('INSERT_ICON_PATH',$iconPath)
    }
    else {
        $xaml = $xaml.Replace('Icon="INSERT_ICON_PATH" ','')
    }

    # Row counter
    $script:row = 0
    # Add CSV data to XAML
    # Not using Group-Object as PS7-preview4 does not preserve original order
    $sections = $csvData.Section | Where-Object {-not [string]::IsNullOrEmpty($_)} | Get-Unique
    # First loop through Sections
    ForEach ($section in $sections) {
        # Section Heading
        $xaml += New-GuiHeading $section
        $csvData | Where-Object {$_.Section -eq $section} | ForEach-Object {
            # Add items
            $xaml += New-GuiRow $_
        }
    }
    # Then process items with blank Section
    $csvData | Where-Object {[string]::IsNullOrEmpty($_.Section)} | ForEach-Object {
        $xaml += New-GuiRow $_
        # TODO: spacing at top of window is untidy with no Sections (minor)
    }

    # Finish constructing XAML
    $xaml += Get-Content "$moduleRoot\xaml\end.xaml"

    # Generate form
    $form = New-GuiForm -inputXml $xaml

    # Add clicks to buttons
    ForEach ($buttonVariable in Get-Variable WPF_button*) {
        $buttonVariable.Value.Add_Click( {
            # Use object in pipeline to identify script to run
            Start-Script $_.Source.Name
        } )
    }

    # Show form
    $Form.ShowDialog() | Out-Null
}