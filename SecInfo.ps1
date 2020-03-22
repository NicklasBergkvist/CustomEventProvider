Function Write-CustomLog
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [object[]]
        $Objects,
        [Parameter()]
        [int]
        $ID,
        [Parameter()]
        [string]
        $ProviderName        
    )
    foreach ($object in $objects)
    {
        New-WinEvent -ProviderName $Providername -Id $ID -Payload @(
            foreach ($Prop in $object.psobject.properties)
            {
                if ($prop.value)
                {
                    (([string]$prop.Value.ToString()).foreach( { [int[]][char[]]$_ | Where-Object { $_ -gt 31 } }) | ForEach-Object { [char]$_ }) -join ''
                }
                else
                {
                    'n/a'
                }
            }
        )
    }
}
Function Get-LoadedDLL
{
    $Processes = Get-Process -IncludeUserName
    $Files = $Processes | Select-Object -expand modules -ErrorAction SilentlyContinue | Sort-Object filename -Unique | Select-Object -ExpandProperty Filename
    $HashFileHash = $Files.ForEach( { @{$_ = (Get-FileHash -Algorithm SHA256 -Path $_).hash } })
    $HashSigCheck = $Files.ForEach( { @{$_ = Get-AuthenticodeSignature -FilePath $_ } })
    $(ForEach ($process in $Processes)
        {  
            foreach ($Module in $process.modules)
            {
                if ($HashSigCheck.$($Module.Filename).Status -notmatch 'Valid')
                {
                    [pscustomobject]@{
                        pid               = $process.id
                        filename          = $Module.Filename
                        sha256            = $HashFileHash.$($Module.Filename)
                        SigCheck          = $HashSigCheck.$($Module.Filename).Status
                        BaseAddress       = $Module.BaseAddress
                        EntryPointAddress = $Module.EntryPointAddress
                        UserName          = $process.UserName                                        
                    }
                }
            } 
        }) | Group-Object filename | ForEach-Object {
        [pscustomobject]@{
            filename          = $_.name
            UserName          = ($_.group.UserName | Select-Object -Unique) -join ','
            pid               = $_.group.pid -join ','           
            sha256            = $_.group.sha256 | Select-Object -First 1
            BaseAddress       = ($_.group.BaseAddress | Select-Object -Unique) -join ',' 
            EntryPointAddress = ($_.group.EntryPointAddress | Select-Object -Unique) -join ',' 
        }
    }
}
$autorunspath = (Get-ChildItem -path ((Split-Path $script:MyInvocation.MyCommand.Path) + '\bin\autorunsc.exe')).FullName
$pipelistpath = (Get-ChildItem -path ((Split-Path $script:MyInvocation.MyCommand.Path) + '\bin\pipelist.exe')).FullName
if (Test-Path -Path $autorunspath)
{
    $autoruns = & $autorunspath -accepteula -nobanner -a * -c -h -m -s | ConvertFrom-Csv | Select-Object 'Time', @{n = "Entry_Location"; e = { $_.'Entry Location' } }, 'Entry', 'Description', @{n = "Image_Path"; e = { $_.'Image Path' } }, 'Version', @{n = "Launch_String"; e = { $_.'Launch String' } }, @{n = "SHA256"; e = { $_.'SHA-256' } }        
}
else
{
    $autoruns = @('', '', '', 'autorunsc.exe not found', '', '', '', '')
}
if (Test-Path -Path $pipelistpath)
{
    $Pipelist = (& $pipelistpath -accepteula -nobanner) | Select-Object -Skip 2 | ForEach-Object { $_ -replace "\s\s+", ";" } | ConvertFrom-Csv -Delimiter ';' -Header "PipeName", "Instances", "MaxInstances"    
}
else
{    
    $Pipelist = @('pipelist.exe not found', '', '')
}

$Certstore = Get-ChildItem Cert:\ -Recurse | Where-Object {!$_.PSIsContainer} | Select-Object @{n = "Store"; e = {$_.PSParentPath -replace ".+::"}}, "Subject", "Issuer", "SerialNumber", "Thumbprint", @{n = "Algorithm"; e = {$_.SignatureAlgorithm.FriendlyName}}, NotBefore, NotAfter
$streams = Get-ChildItem 'C:\' -recurse -ErrorAction SilentlyContinue | Get-Item -stream * -ErrorAction SilentlyContinue | Where-Object stream -NotMatch '\:\$DATA$|Zone.Identifier' | Select-Object filename, @{'n' = 'LastWriteTime'; "e" = { (Get-ChildItem $_.filename | Select-Object -ExpandProperty LastWriteTime).tostring() } }, stream 
$LoadedDLLs = Get-LoadedDll
$ProviderName = "CustomSec"
Write-CustomLog -ProviderName $ProviderName -Objects $autoruns -ID 10
Write-CustomLog -ProviderName $ProviderName -Objects $Pipelist -ID 20
Write-CustomLog -ProviderName $ProviderName -Objects $Certstore -ID 30
Write-CustomLog -ProviderName $ProviderName -Objects $streams -ID 40
Write-CustomLog -ProviderName $ProviderName -Objects $LoadedDLLs -ID 50
