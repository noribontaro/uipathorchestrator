#######################
#
# Main install script
#
#######################


$orchestratorVersion = Get-content C:\temp_param\ocver.ps1 -TotalCount 1
$orchestratorFolder = "${env:ProgramFiles(x86)}\Uipath\Orchestrator"
$passphrase = "Passw0rd!"
$orchestratorHostname
$databaseServerName = Get-content C:\temp_param\rds.ps1 -TotalCount 1
$databaseName = "UiPath"
$databaseUserName = "uipathdbuser"
$databaseUserPassword = Get-content C:\temp_param\rdspass.ps1 -TotalCount 1
$databaseAuthenticationMode = "SQL"
$appPoolIdentityType = "APPPOOLIDENTITY"
$appPoolIdentityUser
$appPoolIdentityUserPassword
$redisServerHost
$nuGetStoragePath
$orchestratorAdminUsername = "admin"
$orchestratorAdminPassword = Get-content C:\temp_param\oc.ps1 -TotalCount 1
$orchestratorTennant = "Default"
$orchestratorLicenseCode
$useElasticsearch = Get-content C:\temp_param\usees.ps1 -TotalCount 1
$esDomainName = Get-content C:\temp_param\es.ps1 -TotalCount 1
$esReqAuth = ""


###Create Database
Invoke-Sqlcmd -ServerInstance "$databaseServerName" -Username "$databaseUserName" -Password "$databaseUserPassword" "CREATE DATABASE $databaseName COLLATE Latin1_General_CI_AS"


#Enable TLS12
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"
# Script Version
$sScriptVersion = "1.0"
# Debug mode; $true - enabled ; $false - disabled
$sDebug = $true
# Log File Info
$sLogPath = "C:\temp\log"
$sLogName = "Install-Orchestrator.ps1.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

function Main {
    try {
        Start-Transcript -Path "$sLogPath\Install-UipathOrchestrator-Transcript.ps1.txt" -Append

        # Setup temp dir in %appdata%\Local\Temp
        $tempDirectory = (Join-Path 'C:\temp\' "UiPath-$(Get-Date -f "yyyyMMddhhmmssfff")")
        New-Item -ItemType Directory -Path $tempDirectory -Force

        $source = @()
        $source += "https://download.uipath.com/versions/$orchestratorVersion/UiPathOrchestrator.msi"
        $source += "https://download.microsoft.com/download/C/9/E/C9E8180D-4E51-40A6-A9BF-776990D8BCA9/rewrite_amd64.msi"
        $source += "https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
        $tries = 5
        while ($tries -ge 1) {
            try {
                foreach ($item in $source) {

                    $package = $item.Substring($item.LastIndexOf("/") + 1)

                    Download-File -url "$item " -outputFile "$tempDirectory\$package"

                    # Start-BitsTransfer -Source $item -Destination "$tempDirectory" -ErrorAction Stop

                }
                break
            }
            catch {
                $tries--
                Write-Verbose "Exception:"
                Write-Verbose "$_"
                if ($tries -lt 1) {
                    throw $_
                }
                else {
                    Write-Verbose
                    Log-Write -LogPath $sLogFile -LineValue "Failed download. Retrying again in 5 seconds"
                    Start-Sleep 5
                }
            }
        }
    }
    catch {

        Log-Error -LogPath $sLogFile -ErrorDesc "$($_.exception.message) on $(Get-Date)" -ExitGracefully $True

    }

    if (!$orchestratorHostname) { $orchestratorHostname = $env:COMPUTERNAME }

    $features = @(
        'IIS-DefaultDocument',
        'IIS-HttpErrors',
        'IIS-StaticContent',
        'IIS-RequestFiltering',
        'IIS-URLAuthorization',
        'IIS-WindowsAuthentication',
        'IIS-NetFxExtensibility45',
        'IIS-ASPNET45',
        'IIS-ISAPIExtensions',
        'IIS-ISAPIFilter',
        'IIS-WebSockets',
        'IIS-ManagementConsole',
        'IIS-ManagementScriptingTools',
        'ClientForNFS-Infrastructure'
    )
    Install-UiPathOrchestratorFeatures -features $features

    $checkFeature = Get-WindowsFeature "IIS-DirectoryBrowsing"
    if ( $checkFeature.Installed -eq $true) {
        Disable-WindowsOptionalFeature -FeatureName IIS-DirectoryBrowsing -Remove -NoRestart -Online
        Log-Write -LogPath $sLogPath -LineValue "Feature IIS-DirectoryBrowsing is removed" 
    }

    #install URLrewrite
    Install-UrlRewrite -urlRWpath "$tempDirectory\rewrite_amd64.msi"

    # install .Net 4.7.2
    # & "$tempDirectory\NDP472-KB4054530-x86-x64-AllOS-ENU.exe" /q /norestart
    # Wait-Process -Name "NDP472-KB4054530-x86-x64-AllOS-ENU"

    # ((Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/public-hostname -UseBasicParsing).RawContent -split "`n")[-1]

    $cert = New-SelfSignedCertificate -DnsName "$env:COMPUTERNAME", "$orchestratorHostname" -CertStoreLocation cert:\LocalMachine\My -FriendlyName "Orchestrator Self-Signed certificate" -KeySpec Signature -HashAlgorithm SHA256 -KeyExportPolicy Exportable  -NotAfter (Get-Date).AddYears(20)

    $thumbprint = $cert.Thumbprint

    Export-Certificate -Cert cert:\localmachine\my\$thumbprint -FilePath "$($tempDirectory)\OrchPublicKey.cer" -force

    Import-Certificate -FilePath "$($tempDirectory)\OrchPublicKey.cer" -CertStoreLocation "cert:\LocalMachine\Root"

    #install Orchestrator

    $getEncryptionKey = Generate-Key -passphrase $passphrase

    $msiFeatures = @("OrchestratorFeature")
    $msiProperties = @{ }
    $msiProperties += @{
        "ORCHESTRATORFOLDER"          = "`"$($orchestratorFolder)`"";
        "DB_SERVER_NAME"              = "$($databaseServerName)";
        "DB_DATABASE_NAME"            = "$($databaseName)";
        "HOSTADMIN_PASSWORD"          = "$($orchestratorAdminPassword)";
        "DEFAULTTENANTADMIN_PASSWORD" = "$($orchestratorAdminPassword)";
        "APP_ENCRYPTION_KEY"          = "$($getEncryptionKey.encryptionKey)";
        "APP_NUGET_ACTIVITIES_KEY"    = "$($getEncryptionKey.nugetKey)";
        "APP_NUGET_PACKAGES_KEY"      = "$($getEncryptionKey.nugetKey)";
        "APP_MACHINE_DECRYPTION_KEY"  = "$($getEncryptionKey.DecryptionKey)";
        "APP_MACHINE_VALIDATION_KEY"  = "$($getEncryptionKey.Validationkey)";
        "TELEMETRY_ENABLED"           = "0";
    }
    if ($appPoolIdentityType -eq "USER") {

        $msiProperties += @{
            "APPPOOL_IDENTITY_TYPE" = "USER";
            "APPPOOL_USER_NAME"     = "$($appPoolIdentityUser)";
            "APPPOOL_PASSWORD"      = "$($appPoolIdentityUserPassword)";
        }
    }
    else {
        $msiProperties += @{"APPPOOL_IDENTITY_TYPE" = "APPPOOLIDENTITY"; }
    }

    if ($databaseAuthenticationMode -eq "SQL") {
        $msiProperties += @{
            "DB_AUTHENTICATION_MODE" = "SQL";
            "DB_USER_NAME"           = "$($databaseUserName)";
            "DB_PASSWORD"            = "$($databaseUserPassword)";
        }
    }
    else {
        $msiProperties += @{"DB_AUTHENTICATION_MODE" = "WINDOWS"; }
    }
    
    if ($useElasticsearch -eq "True") {
        $msiProperties += @{"ELASTIC_URL" = "$($esDomainName)"; }
    }
    else {
        Write-Host "nothing to do for ES"
    }

    Install-UiPathOrchestratorEnterprise -msiPath "$($tempDirectory)\UiPathOrchestrator.msi" -logPath "$($sLogPath)\Install-UiPathOrchestrator.log" -msiFeatures $msiFeatures -msiProperties $msiProperties

    #Remove the default Binding
    Remove-WebBinding -Name "Default Web Site" -BindingInformation "*:80:"

    #add public DNS to bindings
    New-WebBinding -Name "UiPath*" -IPAddress "*" -Protocol http
    New-WebBinding -Name "UiPath*" -IPAddress "*" -Protocol https

    #stopping default website
    Set-ItemProperty "IIS:\Sites\Default Web Site" serverAutoStart False
    Stop-Website 'Default Web Site'

    #disable https to http for AWS ELB
    Set-WebConfigurationProperty '/system.webserver/rewrite/rules/rule[@name="Redirect HTTP to HTTPS"]' -Name enabled -Value false -PSPath "IIS:\sites\UiPath Orchestrator"

    #test Orchestrator URL
    try {
        TestOrchestratorConnection -orchestratorURL "https://$orchestratorHostname"
        TestOrchestratorConnection -orchestratorURL "http://$orchestratorHostname"
    }
    catch {
        Log-Error -LogPath $sLogFile -ErrorDesc "$($_.exception.message) at testing Orchestrator URL" -ExitGracefully $False
    }

    if ($redisServerHost) {
        $LBkey = @("LoadBalancer.Enabled" , "LoadBalancer.UseRedis", "LoadBalancer.Redis.ConnectionString", "NuGet.Packages.ApiKey", "NuGet.Activities.ApiKey")

        $LBvalue = @("true", "true", "$($redisServerHost)", "$($getEncryptionKey.nugetKey)", "$($getEncryptionKey.nugetKey)")

        for ($i = 0; $i -lt $LBkey.count; $i++) {

            Set-AppSettings -path "$orchestratorFolder" -key $LBkey[$i] -value $LBvalue[$i]

        }

        SetMachineKey -webconfigPath "$orchestratorFolder\web.config" -validationKey $getEncryptionKey.Validationkey -decryptionKey $getEncryptionKey.DecryptionKey -validation "SHA1" -decryption "AES"

        Restart-WebSitesSite -Name "UiPath*"

    }

     #set storage path
    if ($nuGetStoragePath) {
       
        if ($orchestratorVersion -lt "19.4.1") {

            $LBkey = @("NuGet.Packages.Path", "NuGet.Activities.Path" )

            $LBvalue = @("\\$($nuGetStoragePath)", "\\$($nuGetStoragePath)\Activities")

            for ($i = 0; $i -lt $LBkey.count; $i++) {

                Set-AppSettings -path "$orchestratorFolder" -key $LBkey[$i] -value $LBvalue[$i]

            }

        }
        else {
            $LBkey = "Storage.Location"
            $LBvalue = "RootPath=\\$($nuGetStoragePath)"
            Set-AppSettings -path "$orchestratorFolder" -key $LBkey -value $LBvalue
        }

    }

    # Remove temp directory
    Log-Write -LogPath $sLogFile -LineValue "Removing temp directory $($tempDirectory)"
    Remove-Item $tempDirectory -Recurse -Force | Out-Null


    #Set Deployment Key
    #Login to Orchestrator via API
    $dataLogin = @{
        tenancyName            = $orchestratorTennant
        usernameOrEmailAddress = $orchestratorAdminUsername
        password               = $orchestratorAdminPassword
    } | ConvertTo-Json

    $orchUrl_login = "localhost/account/login"

    #Get the login session used for all requests
    $orchWebResponse = Invoke-RestMethod -Uri $orchUrl_login  -Method Post -Body $dataLogin -ContentType "application/json" -UseBasicParsing -Session websession

    #Get Orchestrator Deployment Keys & Settings
    $getNugetKey = 'localhost/odata/Settings'
    $getNugetKeyResponse = Invoke-RestMethod -Uri $getNugetKey -Method GET -ContentType "application/json" -UseBasicParsing -WebSession $websession

    $nugetNameKeys = @("NuGet.Packages.ApiKey", "NuGet.Activities.ApiKey")
    $nugetValueKey = $($getEncryptionKey.nugetKey)

    foreach ($nugetNameKey in $nugetNameKeys) {

        $getOldNugetKey = $getNugetKeyResponse.value | Where-Object { $_.Name -eq $nugetNameKey } | Select-Object -ExpandProperty value

        $insertNugetPackagesKey = @{
            Value = $nugetValueKey
            Name  = $nugetNameKey
        } | ConvertTo-Json

        if ($getOldNugetKey -ne $nugetValueKey) {

            $orchUrlSettings = "localhost/odata/Settings('$nugetNameKey')"
            $orchWebSettingsResponse = Invoke-RestMethod -Method PUT -Uri $orchUrlSettings -Body $insertNugetPackagesKey -ContentType "application/json" -UseBasicParsing -WebSession $websession

        }
    }

    if ($orchestratorLicenseCode) {

        Try {
      
            #Check if Orchestrator is already licensed
            $getLicenseURL = "localhost/odata/Settings/UiPath.Server.Configuration.OData.GetLicense()"
            $getOrchestratorLicense = Invoke-RestMethod -Uri $getLicenseURL -Method GET -ContentType "application/json" -UseBasicParsing -WebSession $websession

            if ( $getOrchestratorLicense.IsExpired -eq $true) {
                # Create boundary
                $boundary = [System.Guid]::NewGuid().ToString()	

                # Create linefeed characters
                $LF = "`r`n"

                # Create the body lines
                $bodyLines = (
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"OrchestratorLicense`"; filename=`"OrchestratorLicense.txt`"",
                    "Content-Type: application/octet-stream$LF",
                    $orchestratorLicenseCode,
                    "--$boundary--"
                ) -join $LF

                $licenseURL = "localhost/odata/Settings/UiPath.Server.Configuration.OData.UploadLicense"
                $uploadLicense = Invoke-RestMethod -Uri $licenseURL -Method POST -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -WebSession $websession

                Log-Write -LogPath $sLogFile -LineValue "Licensing Orchestrator..."

            }
        }
        Catch {
            Log-Error -LogPath $sLogFile -ErrorDesc "The following error occurred: $($_.exception.message)" -ExitGracefully $False
        }
      
    }

}


function Invoke-MSIExec {

    param (
        [Parameter(Mandatory = $true)]
        [string] $msiPath,
      
        [Parameter(Mandatory = $true)]
        [string] $logPath,

        [string[]] $features,

        [System.Collections.Hashtable] $properties
    )

    if (!(Test-Path $msiPath)) {
        throw "No .msi file found at path '$msiPath'"
    }

    $msiExecArgs = "/i `"$msiPath`" /q /l*vx `"$logPath`" "

    if ($features) {
        $msiExecArgs += "ADDLOCAL=`"$($features -join ',')`" "
    }

    if ($properties) {
        $msiExecArgs += (($properties.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " ")
    }

    $process = Start-Process "msiexec" -ArgumentList $msiExecArgs -Wait -PassThru

    return $process
}


function Install-UiPathOrchestratorEnterprise {

    param (
        [Parameter(Mandatory = $true)]
        [string] $msiPath,

        [string] $installationFolder,

        [string] $licenseCode,

        [string] $logPath,

        [string[]] $msiFeatures,

        [System.Collections.Hashtable] $msiProperties
    )

    if (!$msiProperties) {
        $msiProperties = @{ }
    }

    if ($licenseCode) {
        $msiProperties["CODE"] = $licenseCode;
    }

    if ($installationFolder) {
        $msiProperties["APPLICATIONFOLDER"] = "`"$installationFolder`"";
    }

    if (!$logPath) {
        $logPath = Join-Path $script:tempDirectory "install.log"
    }

    Log-Write -LogPath $sLogFile -LineValue "Installing UiPath"

    $process = Invoke-MSIExec -msiPath $msiPath -logPath $logPath -features $msiFeatures -properties $msiProperties

    Log-Write -LogPath $sLogFile -LineValue "Installing Features $($msiFeatures)"
 

    return @{
        LogPath        = $logPath;
        MSIExecProcess = $process;
    }
}


function Install-UrlRewrite {
  
    param(

        [Parameter(Mandatory = $true)]
        [string]
        $urlRWpath

    )

    # Do nothing if URL Rewrite module is already installed
    $rewriteDllPath = Join-Path $Env:SystemRoot 'System32\inetsrv\rewrite.dll'

    if (Test-Path -Path $rewriteDllPath) {
        Log-Write -LogPath $sLogFile -LineValue  "IIS URL Rewrite 2.0 Module is already installed"

        return
    }

    $installer = $urlRWpath

    $exitCode = 0
    $argumentList = "/i `"$installer`" /q /norestart"

    Log-Write -LogPath $sLogFile -LineValue  "Installing IIS URL Rewrite 2.0 Module"

    $exitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList $argumentList -Wait -Passthru).ExitCode

    if ($exitCode -ne 0 -and $exitCode -ne 1641 -and $exitCode -ne 3010) {
        Log-Error -LogPath $sLogFile -ErrorDesc "Failed to install IIS URL Rewrite 2.0 Module (Exit code: $exitCode)" -ExitGracefully $False
    }
    else {
        Log-Write -LogPath $sLogFile -LineValue  "IIS URL Rewrite 2.0 Module successfully installed"
    }
}


function Generate-Key {

    param(

        [Parameter(Mandatory = $true)]
        [string]
        $passphrase
    
    )
    function KeyGenFromBuffer([int] $KeyLength, [byte[]] $Buffer) {

        (1..$KeyLength | ForEach-Object { '{0:X2}' -f $Buffer[$_] }) -join ''

    }

    # Register CryptoProviders
    $hashProvider = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $encrypter = New-Object System.Security.Cryptography.AesCryptoServiceProvider

    $encrypter.Key = $hashProvider.ComputeHash([System.Text.ASCIIEncoding]::UTF8.GetBytes($passphrase))

    $encryptionKey = [System.Convert]::ToBase64String($encrypter.Key)

    # NugetKey from passphrase
    $nugethashProvider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider

    $nugetGUID = $nugethashProvider.ComputeHash([System.Text.ASCIIEncoding]::UTF8.GetBytes($passphrase))

    $nugetkey = [System.guid]::New($nugetGUID)

    $BufferKeyPrimary = [system.Text.Encoding]::UTF8.GetBytes($encrypter.Key)
    $BufferKeySecondary = [system.Text.Encoding]::UTF8.GetBytes($BufferKeyPrimary)

    $decryptionKey = KeyGenFromBuffer -Buffer $BufferKeyPrimary -KeyLength 32

    $validationKey = KeyGenFromBuffer -Buffer $BufferKeySecondary -KeyLength 64

    $hashProvider.Dispose()
    $encrypter.Dispose()

    New-Object -TypeName PSObject -Property @{
        Validationkey = $validationkey
        DecryptionKey = $decryptionKey
        encryptionKey = $encryptionKey
        nugetKey      = $nugetkey.Guid
    }

}


function SetMachineKey {

    param(

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $webconfigPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $validationKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $decryptionKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $validation,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $decryption

    )

    $currentDate = (get-date).tostring("mm_dd_yyyy-hh_mm_s") # month_day_year - hours_mins_seconds

    $machineConfig = $webconfigPath

    if (Test-Path $machineConfig) {
        $xml = [xml](get-content $machineConfig)
        $xml.Save($machineConfig + "_$currentDate")
        $root = $xml.get_DocumentElement()
        $system_web = $root."system.web"
        if ($system_web.machineKey -eq $nul) {
            $machineKey = $xml.CreateElement("machineKey")
            $a = $system_web.AppendChild($machineKey)
        }
        $system_web.SelectSingleNode("machineKey").SetAttribute("validationKey", "$validationKey")
        $system_web.SelectSingleNode("machineKey").SetAttribute("decryptionKey", "$decryptionKey")
        $system_web.SelectSingleNode("machineKey").SetAttribute("validation", "$validation")
        $system_web.SelectSingleNode("machineKey").SetAttribute("decryption", "$decryption")
        $a = $xml.Save($machineConfig)
    }
    else { 
        Write-Error -Message "Error: Webconfig does not exist in '$webconfigPath'"
        Log-Error -LogPath $sLogFile -ErrorDesc "Error: Webconfig does not exist '$webconfigPath'" -ExitGracefully $True
    }
}


function Set-AppSettings {
    param (
        # web.config path
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $path,

        # Key to add/update
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $key,

        # Value
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $value
    )


    # Make a backup copy before editing
    $ConfigBackup = "$path\web.config.$(Get-Date -Format yyyyMMdd_hhmmsstt).backup"
    try { Copy-Item -Path "$path\web.config" -Destination $ConfigBackup -Force -EA 1 } catch { throw }
    Write-Verbose "Backed up '$path\web.config' to '$ConfigBackup'"
    Log-Write -LogPath $sLogFile -LineValue "Backed up '$path\web.config' to '$ConfigBackup'"


    $webconfig = Join-Path $path "web.config"
    [bool] $found = $false

    if (Test-Path $webconfig) {
        $xml = [xml](get-content $webconfig);
        $root = $xml.get_DocumentElement();

        foreach ($item in $root.appSettings.add) {
            if ($item.key -eq $key) {
                $item.value = $value;
                $found = $true;
            }
        }

        if (-not $found) {
            $newElement = $xml.CreateElement("add");
            $nameAtt1 = $xml.CreateAttribute("key")
            $nameAtt1.psbase.value = $key;
            $newElement.SetAttributeNode($nameAtt1);

            $nameAtt2 = $xml.CreateAttribute("value");
            $nameAtt2.psbase.value = $value;
            $newElement.SetAttributeNode($nameAtt2);

            $xml.configuration["appSettings"].AppendChild($newElement);
        }

        $xml.Save($webconfig)
    }
    else {
        Write-Error -Message "Error: File not found '$webconfig'"
        Log-Error -LogPath $sLogFile -ErrorDesc "Error: File not found '$webconfig'" -ExitGracefully $True
    }
}


function TestOrchestratorConnection {
    param (
        [string]
        $orchestratorURL
    )
    # First we create the request.
    $HTTP_Request = [System.Net.WebRequest]::Create("$orchestratorURL")

    # We then get a response from the site.
    $HTTP_Response = $HTTP_Request.GetResponse()

    # We then get the HTTP code as an integer.
    $HTTP_Status = [int]$HTTP_Response.StatusCode

    if ($HTTP_Status -eq 200) {
        Log-Write -LogPath $sLogFile -LineValue "Orchestrator Site is OK!"
    }
    else {
        Log-Write -LogPath $sLogFile -LineValue "The Orchestrator Site may be down, please check!"
    }

    # Finally, we clean up the http request by closing it.
    $HTTP_Response.Close()

}


function Install-UiPathOrchestratorFeatures {
    param (

        [Parameter(Mandatory = $true)]
        [string[]] $features

    )

    foreach ($feature in $features) {

        try {
            Log-Write -LogPath $sLogFile -LineValue "Installing feature $feature"
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -all -NoRestart
        }
        catch {
            Log-Error -LogPath $sLogFile -ErrorDesc "$($_.exception.message) on installing $($feature)" -ExitGracefully $True
        }

    }

}



function Download-File {

    param (
        [Parameter(Mandatory = $true)]
        [string]$url,

        [Parameter(Mandatory = $true)]
        [string] $outputFile
    )

    Write-Verbose "Downloading file from $url to local path $outputFile"

    Try {
        $webClient = New-Object System.Net.WebClient
    }
    Catch {
        Log-Error -LogPath $sLogFile -ErrorDesc "The following error occurred: $_" -ExitGracefully $True
    }
    Try {
        $webClient.DownloadFile($url, $outputFile)
    }
    Catch {
        Log-Error -LogPath $sLogFile -ErrorDesc "The following error occurred: $_" -ExitGracefully $True
    }
}


function Log-Start {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$ScriptVersion
    )

    Process {
        $sFullPath = $LogPath + "\" + $LogName

        # Check if file exists and delete if it does
        if ((Test-Path -Path $sFullPath)) {
            Remove-Item -Path $sFullPath -Force
        }

        # Create file and start logging
        New-Item -Path $LogPath -Value $LogName -ItemType File

        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value ""
        Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
        Add-Content -Path $sFullPath -Value ""
        Add-Content -Path $sFullPath -Value "Running with debug mode [$sDebug]."
        Add-Content -Path $sFullPath -Value ""
        Add-Content -Path $sFullPath -Value "***************************************************************************************************"
        Add-Content -Path $sFullPath -Value ""

        # Write to screen for debug mode
        Write-Debug "***************************************************************************************************"
        Write-Debug "Started processing at [$([DateTime]::Now)]."
        Write-Debug "***************************************************************************************************"
        Write-Debug ""
        Write-Debug "Running script version [$ScriptVersion]."
        Write-Debug ""
        Write-Debug "Running with debug mode [$sDebug]."
        Write-Debug ""
        Write-Debug "***************************************************************************************************"
        Write-Debug ""
    }

}



function Log-Write {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$LineValue
    )

    Process {
        Add-Content -Path $LogPath -Value $LineValue

        # Write to screen for debug mode
        Write-Debug $LineValue
    }
}


function Log-Error {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$ErrorDesc,

        [Parameter(Mandatory = $true)]
        [boolean]$ExitGracefully
    )

    Process {
        Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."

        # Write to screen for debug mode
        Write-Debug "Error: An error has occurred [$ErrorDesc]."

        # If $ExitGracefully = True then run Log-Finish and exit script
        if ($ExitGracefully -eq $True) {
            Log-Finish -LogPath $LogPath
            Break
        }
    }
}


function Log-Finish {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [string]$NoExit
    )

    Process {
        Add-Content -Path $LogPath -Value ""
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
        Add-Content -Path $LogPath -Value "***************************************************************************************************"
        Add-Content -Path $LogPath -Value ""

        # Write to screen for debug mode
        Write-Debug ""
        Write-Debug "***************************************************************************************************"
        Write-Debug "Finished processing at [$([DateTime]::Now)]."
        Write-Debug "***************************************************************************************************"
        Write-Debug ""

        # Exit calling script if NoExit has not been specified or is set to False
        if (!($NoExit) -or ($NoExit -eq $False)) {
            Exit
        }
    }
}


Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
Main
Log-Finish -LogPath $sLogFile
