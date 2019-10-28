param(
[string]$computerName,
[string]$currentDir
)

Configuration measuresconfig 
{	
	Node $computerName
	{		

        # BETTER solution to handle registry keys: https://mathieubuisson.github.io/managing-large-numbers-of-registry-settings/
        #M889229-disable-ssl-v3        
        Registry key1Value1
        {
            Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'DisabledByDefault'
            Ensure = 'Present'            
            ValueData = '00000001'
            ValueType = 'Dword'
        }
        	
        Registry key1Value2
        {
            Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'DisabledByDefault'
            Ensure = 'Present'            
            ValueData = '00000000'
            ValueType = 'Dword'
        }
	}
}

measuresconfig -OutputPath $currentDir\mofs



