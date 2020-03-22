
param 
(	
	[Parameter()]
	[ValidateSet('Add', 'Generate', 'Remove', 'FullRemove')]
	[string]
	$Action
)
Function New-EventManifest
{
	param (
		# Filepath to event provider DLL location, will be created if not exists
		[Parameter(Mandatory = $true)]
		[string]
		$FilePath,

		# Provider Log Name, ie Company/Security (If eventviewer hierarchy should work, use xx-yy-zz/qq or zz/qq. Format must be zero or 2 dashes)
		[Parameter(Mandatory = $true)]	
		[string]
		$LogName,

		# Path to CSC, default 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
		[Parameter()]
		[string]
		$CSCPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe',

		# Path to SDK, default 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64'
		[Parameter()]
		[string]
		$SDKPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64'
	)

	# Max number of attributes per eventid are 8
	$Sources = @{	
		Autoruns  = @{
			Attributes = 'Time', 'Entry_Location', 'Entry', 'Description', 'Image_Path', 'Version', 'Launch_String', 'sha256'
			EventID    = '10'
			TaskInfo   = 'AUTORUNS'
			Name       = 'autoruns'
		}
		Pipelist  = @{
			Attributes = 'PipeName', 'Instances', 'MaxInstances'
			EventID    = '20'
			TaskInfo   = 'PIPELIST'
			Name       = 'pipelist'
		}
		Certstore = @{
			Attributes = 'Store', 'Subject', 'Issuer', 'SerialNumber', 'Thumbprint', 'Algorithm', 'NotBefore', 'NotAfter'
			EventID    = '30'
			TaskInfo   = 'CERTSTORE'
			Name       = 'certstore'
		}
		Streams   = @{
			Attributes = 'FileName', 'LastWriteTime', 'Stream'
			EventID    = '40'
			TaskInfo   = 'STREAMS'
			Name       = 'streams'
		}
		Modules   = @{
			Attributes = 'FileName', 'UserName', 'PID', 'SHA256', 'BaseAddress', 'EntryPointAddress'
			EventID    = '50'
			TaskInfo   = 'Loaded DLLs'
			Name       = 'modules'
		}
	}


	# Variables

	$ManifestPath = $FilePath -replace '\\$'
	$OutputPath = (Split-Path $script:MyInvocation.MyCommand.Path) + '\OutPut'
	$SDKPath = $SDKPath -replace '\\$'
	$ProviderName = Split-Path $LogName
	$ChannelSymbol = (Split-Path $LogName).Split('-')[-1]
	$Manifestdll = "$ManifestPath\$ProviderName.dll"


	# XML Manifest Creation

	$Templates = $Sources.GetEnumerator().foreach( {
			$eventdata = $($Sources.($_.name).Attributes).foreach( { ('<data name="{0}" inType="win:UnicodeString" outType="xs:string"/>' -f $_) }) -join [System.Environment]::NewLine
			'<template tid="{0}">
			{1}
		</template>' -F $Sources.($_.name).Name, $eventdata		
		})


	$Events = $Sources.GetEnumerator().foreach( {
			$source = $Sources.($_.name).Name
			$ID = $Sources.($_.name).EventID
			$message = '$(string.Custom {1} Events.event.{0}.message)' -f $ID, $ChannelSymbol
			'<event symbol="{0}" value="{1}" version="1" channel="{4}" level="win:Informational" task="Task-{2}" template="{0}" message="{3}" />' -f $source.ToLower(), $ID, $source.ToUpper(), $Message, $LogName
		})

	$StringIDs = $Sources.GetEnumerator().foreach( {
			$source = $Sources.($_.name).Name
			$ID = $Sources.($_.name).EventID
			$Attributes = $Sources.($_.name).Attributes
			$n = 1
			$Value = $(
				foreach ($Val in $attributes)
				{
					$Val + ': %{0}!s!%n' -f $n
					$n++				
				}
			)	
			'<string id="Custom {2} Events.event.{0}.message" value="{1}"></string>' -f $ID, $($Value -join ''), $ChannelSymbol
			'<string id="task.{0}" value="{1}" />' -f $Source.ToUpper(), $Sources.($_.name).TaskInfo
		})

	$Tasks = $Sources.GetEnumerator().foreach( {
			$source = $Sources.($_.name).Name
			$ID = $Sources.($_.name).EventID
			'<task name="Task-{0}" symbol="TASK_{0}" value="{1}" message="$(string.task.{0})" eventGUID="{2}" />' -f $Source.ToUpper(), $ID, "{$(New-Guid)}"
		})
	$Content = @"
<?xml version="1.0" encoding="UTF-8"?>
<instrumentationManifest xsi:schemaLocation="http://schemas.microsoft.com/win/2004/08/events eventman.xsd" 
    xmlns="http://schemas.microsoft.com/win/2004/08/events" 
    xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
    xmlns:xs="http://www.w3.org/2001/XMLSchema" 
    xmlns:trace="http://schemas.microsoft.com/win/2004/08/events/trace">
    <instrumentation>
        <events>
            <provider name="$ProviderName" symbol="$ChannelSymbol" guid="{$(New-Guid)}" resourceFileName="$Manifestdll" messageFileName="$Manifestdll">
                <events>
                    $Events 
                </events>
                <levels/>
				<tasks>
					$Tasks  
				</tasks>
                <opcodes/>
				<channels>
				<channel chid="c1"
					name="$LogName"
					type="Operational"
					symbol="$ChannelSymbol"					
					enabled="true"
					/>                    
                </channels>
                <templates>			
                    $Templates
                </templates>
            </provider>
        </events>
    </instrumentation>
    <localization>
        <resources culture="en-US">
            <stringTable>
				<string id="level.Informational" value="Information"></string>
                <string id="channel.System" value="System"></string>
				<string id="Publisher.EventMessage" value="%1;%n&#xA;%2;%n"></string>		
					$StringIDs
            </stringTable>
        </resources>
    </localization>
</instrumentationManifest> 
"@

	try
	{		
		# Compile Custom Event Provider. Requires SDK		
		If (!(Test-Path -Path $OutputPath))
		{
			New-Item -ItemType Directory -Path $OutputPath -ErrorAction Stop
		}	
		Push-Location -Path $OutputPath
		Remove-Item -Path "$OutputPath\*"
		Set-Content -Value $content -Path "$OutputPath\$ProviderName.man" -Encoding ASCII		
		$null = & $SDKPath\mc.exe "$OutputPath\$ProviderName.man"
		$null = & $SDKPath\mc.exe -css Namespace "$OutputPath\$ProviderName.man" 
		$null = & $SDKPath\rc.exe "$OutputPath\$ProviderName.rc" 
		$null = & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /win32res:"$OutputPath\$ProviderName.res" /unsafe /target:library /out:"$OutputPath\$ProviderName.dll" 
		Get-ChildItem -Path $OutputPath | Where-Object name -NotMatch ".dll$|.man$" | Remove-Item
		Pop-Location
	}
	catch
	{
		$Error[0].Exception.Message 
		"Line " + $Error[0].InvocationInfo.ScriptLineNumber
	}
}
Function Add-CustomEventProvider
{
	param 
	(
		# Filepath to event provider DLL location, will be created if not exists
		[Parameter(Mandatory = $true)]
		[ValidateScript( {
				if ( -Not (($_ | Test-Path -PathType Leaf) -and ($_ -Match 'man$') ) )
				{
					throw "File or folder does not exist"
				}
				return $true
			})]
		[System.IO.FileInfo]
		$ManifestFilePath
	)
	try
	{
		$DestinationPath = Split-Path -Path $(([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.resourceFileName)	
		$LogName = $([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.channels.channel.name  
		$DestinationManifest = $(([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.resourceFileName) -replace '.dll', '.man'		
		If (!(Test-Path -Path $DestinationPath))
		{
			$null = New-Item -ItemType Directory -Path $DestinationPath -ErrorAction Stop
		}
		If ($DestinationManifest -and (Test-Path -Path $DestinationManifest))
		{		
			$null = & C:\Windows\System32\wevtutil.exe um $DestinationManifest
		}
		Get-ChildItem -Path $DestinationPath | Where-Object name -Match "man$|dll$" | Remove-Item -ErrorAction Stop
		Get-ChildItem -Path $(((Get-ChildItem -Path $ManifestFilePath).Directory)[0]) | Where-Object name -Match "man$|dll$" | Copy-Item -Destination $DestinationPath -ErrorAction Stop
		$null = & C:\Windows\System32\wevtutil.exe im $DestinationManifest
		$null = & C:\Windows\System32\wevtutil.exe sl $LogName /ca:O:BAG:SYD:"(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)"
		$LogName = $([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.channels.channel.name 
		try
		{
			$null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
			Write-Verbose "$Logname was added"			
		}
		catch
		{			
			Write-Verbose "$Logname could not be added"	
			throw "$Logname could not be added"
		}		
	}
	catch
	{
		throw $Error[0].Exception.Message + " at line " + $Error[0].InvocationInfo.ScriptLineNumber
	}
	
}
Function Remove-CustomEventProvider
{
	param 
	(
		# Filepath to event provider DLL location, will be created if not exists
		[Parameter(Mandatory = $true)]
		[ValidateScript( {
				if ( -Not (($_ | Test-Path -PathType Leaf) -and ($_ -Match 'man$') ) )
				{
					throw "File or folder does not exist"
				}
				return $true
			})]
		[System.IO.FileInfo]
		$ManifestFilePath,

		[Parameter()]
		[switch]
		$RemoveDirectory
	)
	try
	{
		$ErrorActionPreference = 'Stop'
		$DestinationPath = Split-Path -Path $(([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.resourceFileName)
		$DestinationManifest = $(([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.resourceFileName) -replace '.dll', '.man'
		$Destinationdll = $(([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.resourceFileName) 		
		if ($DestinationPath -and (Test-Path $DestinationPath))
		{
			$DestinationManifest = Get-ChildItem -Path $DestinationPath | Where-Object name -Match "man$" | Select-Object -ExpandProperty Fullname	
			if ($DestinationManifest -and (Test-Path -Path $DestinationManifest))
			{
				$null = & C:\Windows\System32\wevtutil.exe um $DestinationManifest
				Get-ChildItem -Path $DestinationManifest | Remove-Item -ErrorAction Stop -Confirm:$false
			}
			if ($Destinationdll -and (Test-Path -Path $Destinationdll))
			{
				Get-ChildItem -Path $Destinationdll | Remove-Item -ErrorAction Stop -Confirm:$false
			}
			if ($RemoveDirectory)
			{
				Remove-Item -Path $DestinationPath -ErrorAction Stop -Confirm:$false -Recurse -Force	
			}
		}				
		$LogName = $([xml](Get-Content $ManifestFilePath)).instrumentationManifest.instrumentation.events.provider.channels.channel.name 
		try
		{
			Get-WinEvent -ListLog $LogName -ErrorAction Stop		
		}
		catch
		{			
			Write-Verbose "$Logname Removed"			
		}		
	}
	catch
	{		
		throw $Error[0].Exception.Message + "at line " + $Error[0].InvocationInfo.ScriptLineNumber
	}	
}

$Logname = "CustomSec/Security"
$DestinationPath = 'C:\Program Files\CustomSecurityProvider'
$ManifestFilePath = (Get-ChildItem -path ((Split-Path $script:MyInvocation.MyCommand.Path) + '\output\*.man')).FullName
$SDKPath = ((Split-Path $script:MyInvocation.MyCommand.Path) + '\SDK')
$CSCPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

switch ($Action)
{
	'Add'
	{
		Add-CustomEventProvider -ManifestFilePath $ManifestFilePath
	}	
	'Generate'
	{
		New-EventManifest -FilePath $DestinationPath -LogName $Logname -SDKPath $SDKPath -CSCPath $CSCPath
	}
	'Remove'
	{
		Remove-CustomEventProvider -ManifestFilePath $ManifestFilePath
	}
	'FullRemove'
	{
		Remove-CustomEventProvider -ManifestFilePath $ManifestFilePath -RemoveDirectory
	}
	Default
	{
	}
}




