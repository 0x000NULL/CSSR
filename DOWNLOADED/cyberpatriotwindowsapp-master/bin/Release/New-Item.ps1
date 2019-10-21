function New-Item {
	<#
	.SYNOPSIS
	This function ...

	.DESCRIPTION
	A bit more description

	.PARAMETER FromPipeline
	Shows how to process input from the pipeline, remaining parameters or by named parameter.

	.EXAMPLE
	New-Item 'abc'

	Description of the example.

	#>

	<# Enable -Confirm and -WhatIf. #>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(
			Mandatory = $true,
			Position=0,
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			ValueFromRemainingArguments = $true
			)]
		[ValidateNotNullOrEmpty()]
		[string[]] $FromPipeline
	)

	begin {
	}

	process {
		foreach ( $SingleValue in $FromPipeline ) {
			if ( $pscmdlet.ShouldProcess($SingleValue) ) {
				Write-Output $SingleValue
			}
		}
	}

	end {
	}
}

if ($loadingModule) {
	Export-ModuleMember -Function 'New-Item'
}

