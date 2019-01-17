param(
[string]$computerName,
[string]$currentDir
)

[DSCLocalConfigurationManager()]
Configuration lcmpush 
{	
	Node $computerName
	{
		Settings 
		{
			AllowModuleOverwrite = $True
            ConfigurationMode = 'ApplyAndAutoCorrect'
			RefreshMode = 'Push'	
		}    
	}    
}

lcmpush -OutputPath $currentDir\mofs

