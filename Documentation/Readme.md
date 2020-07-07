# Security Information Collection

## Overview

This project consists of two parts.

* **Custom Event Provider**  
    -CreateProvider.ps1 creates an event manifest and dll and uses C:\Windows\System32\wevtutil.exe to install the provider  

* **Collection Script**  
    -SecInfo.ps1 collects information using powershell, autoruns and pipelist from sysinternals and logs the result to the custom event log previously created

<br>

***

## Custom Event Provider

### Purpose and Function

This project purpose is to create an event provider that will be used for collecting security information from endpoints.  
The  log is created with custom name attributes which enables seamless integration with Elastic Common Schema.  
The script will create a manifest file and compile a dll that will be installed using c:\windows\system32\wevtutil.exe.

### Requirements

* Windows SDK
* .Net

```powershell
#Download SDK
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkID=2033908 -OutFile "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe"
#Install SDK RS5
Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe" -ArgumentList "/features OptionId.DesktopCPPx64 /quiet"
```

### Function Parameters

-**DestinationPath**  
Filepath to event provider dll location, will be created if not exists

-**LogName**  
Provider Log Name, ie Company/Security (If eventviewer hierarchy should work, use xx-yy-zz/qq or zz/qq. Format must be zero or 2 dashes)

-**CSCPath**  
Path to CSC, default 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

-**SDKPath**  
Path to SDK, default 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64'

### Event Types

In order to create a manifest that supports custom attributes you must specify sources. This will create different event types with corresponding attributes.

```powershell
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
```

### Script Parameters

The script can generate, add or remove a provider.

-**Generate**  
Creates the manifest and dll and saves them in output folder

-**Add**  
Install the provider using the previously generated files

-**Remove**  
Removes the provider and deletes the dll and manifest

-**FullRemove**  
Removes the provider and deletes the dll and manifest as well as the folder  

# Installation

Use the script CreateProvider.ps1 or manually install it using wevtutil.exe  

## Using CreateProvider.ps1

Generate Provider  

```powershell
.\CreateProvider.ps1 -Action Generate -Verbose
```

Add Provider  

```powershell
.\CreateProvider.ps1 -Action Add -Verbose
```

Remove Provider  

```powershell
.\CreateProvider.ps1 -Action Remove -Verbose
```

Remove Provider and folder

```powershell
.\CreateProvider.ps1 -Action FullRemove -Verbose
```

## Manually using Wevtutil.exe

* Create dll and manifest file or use the provided files
* Copy them to the correct path according to the manifest file (If using the provided, the path should be "C:\Program Files\CustomSecurityProvider\CustomSec.dll")
* Install the provider using C:\Windows\System32\wevtutil.exe
* Modify log permissions

```console
C:\Windows\System32\wevtutil.exe im "C:\Program Files\CustomSecurityProvider\CustomSec.man"
C:\Windows\System32\wevtutil.exe sl "CustomSec/Security" /ca:O:BAG:SYD:"(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)"
```

This will create a custom event log located in CustomSec/Security
<p><img src="eventprovider.png" alt="Image description"></p>

## Uninstalling Custom Event Provider

```console
C:\Windows\System32\wevtutil.exe um "C:\Program Files\CustomSecurityProvider\CustomSec.man"
```

***

## Collection Script

### Description

Collect various information and creates logs in custom event provider

### Dependencies

autorunsc.exe  
pipelist.exe

### Syntax

Logging must be done using the exact attributes created in the provider in the correct order

```powershell
$Pipelist = (& $pipelistpath -accepteula -nobanner) | Select-Object -Skip 2 | ForEach-Object { $_ -replace "\s\s+", ";" } | ConvertFrom-Csv -Delimiter ';' -Header "PipeName", "Instances", "MaxInstances"  
$ProviderName = "CustomSec"
Write-CustomLog -ProviderName $ProviderName -Objects $Pipelist -ID 20
```
