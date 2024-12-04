<#

    	.NOTES
	============================================================================================================
	Copyright (c) Microsoft Corporation. All rights reserved.
	File:		Upgrade-Gen1ToTL.ps1
	Purpose:	Gen1 to Trusted launch upgrade
	Pre-Reqs:	Windows PowerShell version 7.2+ and Azure PowerShell Module version 12.2+ 
	Version: 	3.0.1
	============================================================================================================

	DISCLAIMER
	============================================================================================================
	This script is not supported under any Microsoft standard support program or service.

	This script is provided AS IS without warranty of any kind.
	Microsoft further disclaims all implied warranties including, without limitation, any
	implied warranties of merchantability or of fitness for a particular purpose.

	The entire risk arising out of the use or performance of the script
	and documentation remains with you. In no event shall Microsoft, its authors,
	or anyone else involved in the creation, production, or delivery of the
	script be liable for any damages whatsoever (including, without limitation,
	damages for loss of business profits, business interruption, loss of business
	information, or other pecuniary loss) arising out of the use of or inability
	to use the sample scripts or documentation, even if Microsoft has been
	advised of the possibility of such damages.
    ============================================================================================================

    .SYNOPSIS
    Upgrades Azure VM from Gen1 to Trusted Launch Configuration with OS State preserved.
    Script Version - 3.0.1

    .DESCRIPTION
        PREREQUISITES:
            1. Az.Compute, Az.Accounts PowerShell Module
            2. Current Gen 1 VM is running.
            3. VM Contributor rights on resource group.
            4. If backup is enabled, Gen1 VM backup is configured with Enhanced policy.
                1. Existing backup can be migrated to Enhanced policy using preview https://aka.ms/formBackupPolicyMigration.
            5. ASR is not enabled for Gen1 VM. ASR currently does not supports Trusted launch VMs.
            6. Azure IaaS VM Agent should be installed and healthy.
            7. For Linux VM only, On-board to Gen1 to Trusted launch VM private preview at https://aka.ms/Gen1ToTLUpgrade.

        STEPS:
            1. Create csv with VMName, ResourceGroupName, EnableSecureBoot parameters.
            2. Execute PowerShell script which will:
                1. Check if current VM Size is compatible with Trusted launch.
                2. Execute MBR to GPT OS Disk boot partition conversion.
                3. De-allocate or Stop VM.
                4. Update VM to Gen2-Trusted launch.
                5. Start VM.
            3. Validate health of workload and virtual machine.

    .PARAMETER subscriptionId
    Subscription ID for Gen1 VM.

    .PARAMETER tenantDomain
    Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

    .PARAMETER csvLocation
    Local file path location of csv containing vmName, vmResourceGroupName, enableSecureBoot details.

    .PARAMETER batchSize
    (Optional) Number of machines which should be processed in parallel. Default set to 5.

    .PARAMETER useCloudshell
    (Optional) Use cloud shell in Azure Portal for script execution.

    .PARAMETER vmName
    (Csv input parameter) Resource Name of Gen1 VM to be upgraded

    .PARAMETER vmResourceGroupName
    (Csv input parameter) Resource Group for Gen1 VM.

    .PARAMETER enableSecureBoot
    (Csv input parameter) If target Trusted Launch VM should be deployed with Secure Boot enabled (TRUE) or disabled (FALSE). This option should be disabled if VM is hosting custom or unsigned boot drivers which cannot be attested.

    .EXAMPLE
        .\Upgrade-Gen1ToTL.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.onmicrosoft.com -csvLocation "C:\Temp\sampleCsv.csv"
        
        Upgrade all VMs provided in csv from Gen1 to Trusted launch with specific parameter values.

    .LINK
        https://aka.ms/TrustedLaunch

    .LINK
        https://aka.ms/TrustedLaunchUpgrade
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Azure Subscription Id or Guid")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory=$false, HelpMessage = "The cloud environment where the VM exists.")]
    [ValidateSet("AzureCloud","AzureChinaCloud","AzureUSGovernment")]
    [string]$environment='AzureCloud',
    [Parameter(Mandatory = $true, HelpMessage = "Location of csv containing Gen1 VM(s) details - vmName, vmResourceGroupName, EnableSecureBoot.")]
    [string][ValidateNotNullOrEmpty()]$csvLocation,
    [Parameter(Mandatory = $false, HelpMessage = "Number of machines which should be processed in parallel. Default set to 5.")]
    [int][ValidateNotNullOrEmpty()]$batchSize,
    [Parameter(Mandatory = $false, HelpMessage = "Use cloud shell in Azure Portal for script execution.")]
    [switch]$useCloudshell
)

#region - Validate Pre-Requisites
try {
    New-Variable -Name 'ERRORLEVEL' -Value 0 -Scope Script -Force
    
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -gt 7 -or ($PSVersion.Major -eq 7 -and $PSVersion.Minor -ge 2)) {
        $messagetxt = "[Common] INFO: PowerShell version is greater than 7.2"
        Write-Output $messageTxt
    } else {
        $messagetxt = "[Common] ERROR: PowerShell version is not greater than 7.2 and does not meets requirements."
        Write-Error $messagetxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }

    if ($useCloudshell) {
        $workingDirectory = [system.string]::concat((Get-Location).Path, "/Gen1-TrustedLaunch-Upgrade")
    } else {
        if ((Test-Path $env:UserProfile -ErrorAction SilentlyContinue) -eq $true) {
            $workingDirectory = "$env:UserProfile\Gen1-TrustedLaunch-Upgrade"
        } else {
            $messageTxt = "[Common] INFO: User profile directory not found. Defaulting to script execution location."
            Write-Output $messagetxt
            $workingDirectory = [system.string]::concat((Get-Location).Path, "\Gen1-TrustedLaunch-Upgrade")
        }
    }
    if ((Test-Path $workingDirectory) -eq $true) {
        $messageTxt = "[Common] INFO: Working Directory Already Setup $workingDirectory"
        Write-Output $messageTxt
    }
    else {
        $messageTxt = "[Common] INFO: Setting up working dir $workingDirectory"
        Write-Output $messageTxt
        New-Item -ItemType Directory -Path (Split-Path $workingDirectory -Parent) -Name (Split-Path $workingDirectory -Leaf) -ErrorAction 'Stop' | Out-Null
    }

    If ($useSignedScript -and !($outputStorageAccountName)) {
        $messagetxt = "[Common] ERROR: Output storage account name is required if useSignedScript is set."
        Write-Error $messageTxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }

    $azPsModule = @(@{
            ModuleName = 'Az.Accounts'
            Version    = [version]"2.8.0"
        },
        @{
            ModuleName = 'Az.Compute'
            Version    = [version]"6.0.0"
        },
        @{
            ModuleName = 'Az.Storage'
            Version    = [version]"5.8.0"
        })

    foreach ($azModule in $azPsModule) {
        $module = Get-Module -ListAvailable -Name $azModule.ModuleName

        # Check if the module is available
        if ($module) {
            # Check if the module version is greater than or equal to the minimum version
            if ($module.Version -ge $azModule.Version) {
                $messagetxt = "[Common] INFO: Module $($azModule.ModuleName) with minimum version $($azModule.Version) is available."
                Write-Output $messageTxt
            }
            else {
                $messagetxt = "[Common] WARN: Module $($azModule.ModuleName)  is available, but its version is lower than the minimum version $($azModule.Version). Upgrading module on local machine."
                Write-warning $messageTxt
                Update-Module $($azModule.ModuleName) -ErrorAction 'Stop' -Confirm:$false -Force
            }
        }
        else {
            $messagetxt = "[Common] WARN: Module $($azModule.ModuleName) is not available, proceeding with $($azModule.ModuleName) install."
            Write-warning $messageTxt
            Install-Module -Name $($azModule.ModuleName) -Repository PSGallery -Force -Confirm:$false -ErrorAction 'Stop'
        }
    }
}
catch [system.exception] {
    $messageTxt = '[Common] ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
    Write-Output $messageTxt
    $ERRORLEVEL = -1
}
#endregion

#region - Connect Azure Subscription
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "[Common] INFO: Connecting to Subscription $subscriptionId under $tenantDomain"
        Write-Output $messageTxt
        Update-AzConfig -EnableLoginByWam $false -ErrorAction 'Stop'
        #region - Enable-AzAccount()
        if ($useCloudshell) {
            Set-AzContext -SubscriptionId $subscriptionId -tenant $tenantDomain -ErrorAction 'Stop'
        } else {
            $azureProfile = "$workingDirectory\AzureProfile-$subscriptionId.json"
            $paramTestPath = @{
                Path        = $($azureProfile)
                ErrorAction = 'Stop'
            }
            if (Test-Path @paramTestPath) {
                $messageTxt = "[Common] INFO: Clearing previously cached Azure profile JSON"
                Write-Output $messageTxt
                Remove-Item -Path $azureProfile -Force -Confirm:$false -ErrorAction 'Stop' | Out-Null
            }
            $paramTestPath = @{
                Path        = $workingDirectory
                PathType    = 'Container'
                ErrorAction = 'Stop'
            }
            if (-not (Test-Path @paramTestPath)) {
                $paramNewItem = @{
                    Path        = $workingDirectory
                    ItemType    = 'directory'
                    ErrorAction = 'Stop'
                }
                New-Item @paramNewItem | Out-Null
            }

            $paramConnectAzAccount = @{
                subscriptionId = $subscriptionID
                Tenant         = $tenantDomain
                ErrorAction    = 'Stop'
            }
            if ($environment) {
                $paramConnectAzAccount.Add('Environment', $environment)
            }
            Connect-AzAccount @paramConnectAzAccount

            $paramSaveAzContext = @{
                Path        = $($azureProfile)
                Force       = $true
                ErrorAction = 'Stop'
            }
            Save-AzContext @paramSaveAzContext | Out-Null
        }
        #endregion

        #region - Check for feature registration
        If ((Get-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview").RegistrationState -ne "Registered") {
            $messageTxt = "[Common] WARN: Feature Gen1ToTLMigrationPreview is not registered. Registering now."
            Write-Warning $messagetxt
            Register-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview" -ErrorAction 'Stop'

            do {
                $registrationState = (Get-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview").RegistrationState
                $messagetxt = "[Common] INFO: Registration state: $registrationState"
                Write-Output $messagetxt
                Start-Sleep -Seconds 10
            } while ($registrationState -ne "Registered")
        } else {
            $messagetxt = "[Common] INFO: Feature Gen1ToTLMigrationPreview is already registered."
            Write-Output $messagetxt
        }
        #endregion
    }
    catch [System.Exception] {
        $messageTxt = '[Common] ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }    
}
#endregion

if ($ERRORLEVEL -eq 0) {
    #region - Main script
    if (-not $batchSize) {
        [int]$batchSize = 5
    }

    $importVmArray = Import-Csv $csvLocation -ErrorAction 'Stop'
    foreach ($element in $importVmArray) {
        $element | Add-Member -MemberType NoteProperty -Name 'subscriptionId' -Value $subscriptionId
        $element | Add-Member -MemberType NoteProperty -Name 'tenantDomain' -Value $tenantDomain
        if ($useCloudshell) {
            $element | Add-Member -MemberType NoteProperty -Name 'useCloudShell' -Value $true
        }
        if ($useSignedScript) {
            $element | Add-Member -MemberType NoteProperty -Name 'useSignedScript' -Value $true
            $element | Add-Member -MemberType NoteProperty -Name 'storageAccountName' -Value $outputStorageAccountName
        }
    }

    $importVmArray | ForEach-Object -ThrottleLimit $batchSize -Parallel  {
        #region - Functions
        function Get-ErrorLevel {
            <#
            .SYNOPSIS
                Get ERRORLEVEL variable value
            
            .DESCRIPTION
                Get ERRORLEVEL variable value
            
            .OUTPUTS
                None.
            
            .NOTES	
            #>
            
            #region - Get ERRORLEVEL variable value
            $script:ERRORLEVEL
            #endregion
        }
        function Set-ErrorLevel {
            <#
            .SYNOPSIS
                Set ERRORLEVEL variable value
            
            .DESCRIPTION
                Set ERRORLEVEL variable value
            
            .PARAMETER level
                ERRORLEVEL level [int] parameter.
            
            .OUTPUTS
                $ERRORLEVEL
            
            .NOTES		
            #>
            
            param
            (
                [Parameter(Mandatory = $false)]
                [int]$level = 0
            )
            
            #region - Set Errorlevel
            $script:ERRORLEVEL = $level
            #endregion
        }
        function Write-InitLog {
            param
            (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$logDirectory,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$vmName
            )
            try {
                $logStamp = (Get-Date -Format yy.MM.dd-HH.mm.ss)
                $script:logFile = "$logDirectory\$($vmName)-Gen1-TL-Upgrade-" + $logStamp + '.log'
            } catch [system.exception] {
                $messageTxt = "[$vmName] ERROR: Error Exception Occurred `nWrite-InitLog()  `n$($psitem.Exception.Message)"
                Write-Output $messageTxt
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        function Write-LogEntry {
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                $logMessage,
                [Parameter(Mandatory = $false)]
                [int]$logSeverity = 1,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [String]$logComponent
            )
            try {
                $time = Get-Date -Format 'HH:mm:ss.ffffff'
                $date = Get-Date -Format 'MM-dd-yyyy'
                $message = "<![LOG[$logMessage" + "]LOG]!><time=`"$time`" date=`"$date`" component=`"$logComponent`" context=`"`" type=`"$logSeverity`" thread=`"`" file=`"`">"
                $paramOutFile = @{
                    Append    = $true
                    Encoding  = 'UTF8'
                    FilePath  = $logFile
                    NoClobber = $true
                }
                $message | Out-File @paramOutFile
            } catch [system.exception] {
                $messageTxt = "[$vmName] ERROR: Error Exception Occurred `nWrite-LogEntry()  `n$($psitem.Exception.Message)"
                Write-Output $messageTxt
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        $importVm = $_
        $vmName = $importVm.vmName
        $vmResourceGroupName = $importVm.vmResourceGroupName
        $subscriptionId = $importVm.subscriptionID
        $tenantDomain = $importVm.tenantDomain
        $useCloudshell = $importVm.useCloudShell
        $outputStorageAccountName = $importVm.storageAccountName
        $useSignedScript = $importVm.useSignedScript
        
        if ($importVm.enableSecureBoot) {
            $enableSecureBoot = [system.convert]::ToBoolean($importVm.enableSecureBoot)
        }
        else { $enableSecureBoot = $true }
        [bool]$gen2Vm = $false
        [bool]$tlVm = $false

        #region - Validate Pre-Requisites
        try {
            Set-Errorlevel 0 | Out-Null
            Get-Errorlevel | Out-Null

            if ($useCloudshell) {
                $workingDirectory = [system.string]::concat((Get-Location).Path, "/Gen1-TrustedLaunch-Upgrade")
            } else {
                if ((Test-Path $env:UserProfile -ErrorAction SilentlyContinue) -eq $true) {
                    $workingDirectory = "$env:UserProfile\Gen1-TrustedLaunch-Upgrade"
                } else {
                    $messageTxt = "[$vmName] INFO: User profile directory not found. Defaulting to script execution location."
                    Write-Output $messagetxt
                    $workingDirectory = [system.string]::concat((Get-Location).Path, "\Gen1-TrustedLaunch-Upgrade")
                }
            }

            Write-InitLog -logDirectory $workingDirectory -vmName $vmName
            $messageTxt = "[$vmName] INFO: Script Version: 3.0.1"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"

            $inputParam = @{
                'VM name' = $vmName
                'Resource group name' = $vmResourceGroupName
                'Subscription ID' = $subscriptionId
                'Tenant Domain' = $tenantDomain
                'Use Cloud Shell' = $useCloudshell
                'Use Signed Script' = $useSignedScript
                'Output Storage Account Name' = $outputStorageAccountName
                'Enable Secure Boot' = $enableSecureBoot
            }
            $messageTxt = $inputParam.GetEnumerator() | ForEach-Object {"$($PSItem.Key) = $($PSItem.Value)"}
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
            
            $messageTxt = "[$vmName] INFO: Processing VM $vmName under resource group $vmResourceGroupName with Secure boot $($importVm.enableSecureBoot)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
        }
        catch [system.exception] {
            $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Setup-PreRequisites"
            Set-ErrorLevel -1
            return $ERRORLEVEL
        }
        #endregion

        #region - Connect Azure Subscription
        If ($ERRORLEVEL -eq 0) {
            try {
                $messageTxt = "[$vmName] INFO: Connecting to Subscription $subscriptionId under $tenantDomain"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Connect-AzSubscription"
                #region - Enable-AzAccount()
                If ($useCloudshell -eq $true) {
                    Set-AzContext -SubscriptionId $subscriptionId -tenant $tenantDomain -ErrorAction 'Stop'
                } else {
                    $azureProfile = "$workingDirectory\AzureProfile-$subscriptionId.json"
                    $paramTestPath = @{
                        Path        = $($azureProfile)
                        ErrorAction = 'Stop'
                    }
                    if (Test-Path @paramTestPath) {
                        $paramImportAzContext = @{
                            Path        = $($azureProfile)
                            ErrorAction = 'Stop'
                        }
                        Import-AzContext @paramImportAzContext | Out-Null
                    } else {
                        $paramTestPath = @{
                            Path        = $workingDirectory
                            PathType    = 'Container'
                            ErrorAction = 'Stop'
                        }
                        if (-not (Test-Path @paramTestPath)) {
                            $paramNewItem = @{
                                Path        = $workingDirectory
                                ItemType    = 'directory'
                                ErrorAction = 'Stop'
                            }
                            New-Item @paramNewItem | Out-Null
                        }

                        $paramConnectAzAccount = @{
                            subscriptionId = $subscriptionID
                            Tenant         = $tenantDomain
                            ErrorAction    = 'Stop'
                        }
                        if ($environment) {
                            $paramConnectAzAccount.Add('Environment', $environment)
                        }
                        Connect-AzAccount @paramConnectAzAccount

                        $paramSaveAzContext = @{
                            Path        = $($azureProfile)
                            Force       = $true
                            ErrorAction = 'Stop'
                        }
                        Save-AzContext @paramSaveAzContext | Out-Null
                    }
                }
                #endregion
            }
            catch [System.Exception] {
                $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Connect-AzSubscription"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }    
        }
        #endregion

        #region - Current VM Configuration
        If ($ERRORLEVEL -eq 0) {
            try {
                $messageTxt = "[$vmName] INFO: Mapping existing configuration for $vmName under $vmResourceGroupName"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
        
                $paramGetAzVm = @{
                    ResourceGroupName = $vmResourceGroupName
                    Name              = $vmName
                    ErrorAction       = 'Stop'
                }
                $currentVm = Get-AzVM @paramGetAzVm
        
                $CurrentVMConfig = @{
                    osdisk       = $currentvm.StorageProfile.OsDisk
                    vmsize       = $currentvm.HardwareProfile.VmSize
                    location     = $currentVm.Location
                    securityType = $currentVm.SecurityProfile.SecurityType
                }
                
                $osDiskParam = @{
                    ResourceGroupName = $currentVm.ResourceGroupName
                    Name              = $CurrentVMConfig.osdisk.Name
                    ErrorAction       = 'Stop'
                }
                $currentOsDisk = Get-AzDisk @osDiskParam
        
                $currentOsDiskConfig = @{
                    sku        = $currentOsDisk.sku.Name
                    diskSize   = $currentOsDisk.DiskSizeGB
                    HyperVGen  = $currentOsDisk.HyperVGeneration
                    osType     = $currentOsDisk.OsType
                    encryption = $currentOsDisk.Encryption
                }
        
                if ($currentOsDiskConfig.HyperVGen -eq "V2") {
                    if ($CurrentVMConfig.securityType) {
                        $messagetxt = "[$vmName] INFO: VM $vmName under resource group $vmResourceGroupName is already Trusted launch, no further action required."
                        Write-Output $messagetxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                        [bool]$tlVm = $true
                        [bool]$gen2Vm = $true
                    } else {
                        $messageTxt = "[$vmName] INFO: VM $vmName under resource group $vmResourceGroupName is running as Gen2. MBR2GPT conversion will be skipped."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                        [bool]$gen2Vm = $true
                    }
                }
                $paramGetAzVm = @{
                    ResourceGroupName = $vmResourceGroupName
                    Name              = $vmName
                    Status            = $true
                    ErrorAction       = 'Stop'
                }
                $currentOs = Get-AzVM @paramGetAzVm
                $messageTxt = "[$vmName] INFO: OS Type of Source VM is $($currentOsDiskConfig.osType) and OS Name is $($currentOs.OsName)."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            }
            catch [System.Exception] {
                $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        #region - Validate SKU Support
        If ($ERRORLEVEL -eq 0) {
            try {
                If ($tlVm -eq $false) {
                    $messageTxt = "[$vmName] INFO: Validating VM SKU $($CurrentVMConfig.vmsize) for $vmname is supported for Gen2 & Trusted launch"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-VMSize"
            
                    $gen2Support = $null
                    $tlvmSupport = $null
            
                    $skuDetail = Get-AzComputeResourceSku -Location $($CurrentVMConfig.location) -ErrorAction 'Stop' | `
                        Where-Object { $psitem.Name -eq $($CurrentVMConfig.vmsize) }
            
                    $gen2Support = $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object { $psitem.Name -eq "HyperVGenerations" }
                    $tlvmSupport = $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object { $psitem.Name -eq "TrustedLaunchDisabled" }
            
                    if (($gen2Support.value.Split(",")[-1] -eq "V2") -and !($tlvmSupport)) {
                        $messageTxt = "[$vmName] INFO: VM SKU $($CurrentVMConfig.vmsize) supported for Gen2 & Trusted launch."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-VMSize"
                    } else {
                        $messageTxt = "[$vmName] ERROR: VM SKU $($CurrentVMConfig.vmsize) not supported for Gen2 or Trusted launch. Update VM Size to Gen2-Trusted launch Supported SKU. For more details, https://aka.ms/TrustedLaunch"
                        Write-Error $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Validate-VMSize"
                        Set-ErrorLevel -1
                        return $ERRORLEVEL
                    }
                }
            } catch [system.exception] {
                $messageTxt = "[$vmName] ERROR: Error Exception Occurred `n$($psitem.Exception.Message)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Validate-VMSize"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        #region - MBR to GPT Validation
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($gen2Vm -eq $false) {
                    if ($currentOsDiskConfig.osType -ne "Linux") {
                        if ($currentOs.OsName.Contains("2016")) {
                            $messagetxt = "[$vmName] ERROR: Windows Server 2016 does not supports native MBR to GPT upgrade. Terminating script."
                            Write-Error $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                            Set-ErrorLevel -1
                        } else {
                            $messageTxt = "[$vmName] INFO: Validating MBR to GPT conversion support for $vmname"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"

                            $paramSetAzVMRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                Location          = $CurrentVMConfig.location
                                RunCommandName    = 'managedRuncommand'
                                SourceScript      = "MBR2GPT /validate /allowFullOS"
                                TimeoutInSecond   = 120
                                Erroraction       = 'Stop'
                            }
                            Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
        
                            $paramGetAzVmRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                RunCommandName    = 'managedRuncommand'
                                Expand            = 'InstanceView'
                                ErrorAction       = 'Stop'
                            }
                            $checkCmdOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView

                            if ($checkCmdOutput.Error.Length -gt 0 -or $checkCmdOutput.Output.Length -eq 0) {
                                $messagetxt = "[$vmName] ERROR: MBR to GPT support validation for Windows $vmname failed. Terminating script execution."
                                Write-Error $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"

                                $messageTxt = "[$vmName] INFO: Fetching setupact.log for $vmname"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"

                                $paramSetAzVMRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    Location          = $CurrentVMConfig.location
                                    RunCommandName    = 'managedRuncommand'
                                    SourceScript      = "Get-Content C:\WINDOWS\setupact.log"
                                    TimeoutInSecond   = 120
                                    Erroraction       = 'Stop'
                                }
                                Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
            
                                $paramGetAzVmRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    RunCommandName    = 'managedRuncommand'
                                    Expand            = 'InstanceView'
                                    ErrorAction       = 'Stop'
                                }
                                $setupActOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView

                                $setupFileStamp = (Get-Date -Format yy.MM.dd-HH.mm.ss)
                                if ($useCloudshell) {
                                    $setupActOutFile = [system.string]::concat($workingDirectory, "/", $vmName, "-",$setupFileStamp, "-mbr2gpt-validate-setupact.log")
                                } else {
                                    $setupActOutFile = [system.string]::concat($workingDirectory, "\", $vmName, "-",$setupFileStamp, "-mbr2gpt-validate-setupact.log")
                                }

                                $messageTxt = "[$vmName] INFO: Writing setupact.log to $setupActOutFile"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                $setupActOutput.Output | Out-File -FilePath $setupActOutFile -Force -ErrorAction 'Stop'

                                $messageTxt = "[$vmName] INFO: Fetching setuperr.log for $vmname"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"

                                $paramSetAzVMRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    Location          = $CurrentVMConfig.location
                                    RunCommandName    = 'managedRuncommand'
                                    SourceScript      = "Get-Content C:\Windows\setuperr.log"
                                    TimeoutInSecond   = 120
                                    Erroraction       = 'Stop'
                                }
                                Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
            
                                $paramGetAzVmRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    RunCommandName    = 'managedRuncommand'
                                    Expand            = 'InstanceView'
                                    ErrorAction       = 'Stop'
                                }
                                $setupErrOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView
                                if ($useCloudshell) {
                                    $setupErrOutFile = [system.string]::concat($workingDirectory, "/", $vmName, "-",$setupFileStamp, "-mbr2gpt-validate-setuperr.log")
                                } else {
                                    $setupErrOutFile = [system.string]::concat($workingDirectory, "\", $vmName, "-",$setupFileStamp, "-mbr2gpt-validate-setuperr.log")
                                }

                                $messageTxt = "[$vmName] INFO: Writing setuperr.log to $setupErrOutFile"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                $setupErrOutput.Output | Out-File -FilePath $setupErrOutFile -Force -ErrorAction 'Stop'

                                Set-ErrorLevel -1
                            }  else {
                                $messagetxt = "[$vmName] INFO: MBR to GPT support validation for Windows $vmname completed successfully."
                                Write-Output $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                            }
                        }
                    } else {
                        $checkLinuxCmd = @'
bootDevice=$(echo "/dev/$(lsblk -no pkname $(df /boot | awk 'NR==2 {print $1}'))") && diskType=$(blkid $bootDevice -o value -s PTTYPE) && efiPartition=$(fdisk -l $bootDevice | grep EFI | awk '{print $1}') && biosPartition=$(fdisk -l $bootDevice | grep -i 'BIOS Boot' | awk '{print $1}') && grep -qs '/boot/efi' /etc/fstab && echo 'Boot device: '$bootDevice', disk type: '$diskType', EFI partition: '$efiPartition', BIOS partition: '$biosPartition', /boot/efi present in /etc/fstab'|| echo 'Boot device: '$bootDevice', disk type: '$diskType', EFI partition: '$efiPartition', BIOS partition: '$biosPartition', /boot/efi missing in /etc/fstab'
'@
                        if ($useCloudshell) {
                            $checkCmdFile = [system.string]::concat($workingDirectory, "/gen2LinuxCheckCmd.txt")
                        } else {
                            $checkCmdFile = [system.string]::concat($workingDirectory, "\gen2LinuxCheckCmd.txt")
                        }
                        if (-not (Test-Path $checkCmdFile -ErrorAction 'SilentlyContinue')) {
                            $messageTxt = "[$vmName] INFO: Writing validation script to gen2LinuxCheckCmd.txt"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                            $stream = [System.IO.StreamWriter]::new($checkCmdFile)
                            $stream.WriteLine($checkLinuxCmd)
                            $stream.Close()
                        }

                        $messageTxt = "[$vmName] INFO: Executing validation script for $($vmName)"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"

                        $paramSetAzVMRunCommand = @{
                            ResourceGroupName = $vmResourceGroupName
                            VMName            = $vmName
                            Location          = $CurrentVMConfig.location
                            RunCommandName    = 'managedRuncommand'
                            SourceScript      = (Get-Content $checkCmdFile)
                            TimeoutInSecond   = 120
                            Erroraction       = 'Stop'
                        }
                        Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null

                        $paramGetAzVmRunCommand = @{
                            ResourceGroupName = $vmResourceGroupName
                            VMName            = $vmName
                            RunCommandName    = 'managedRuncommand'
                            Expand            = 'InstanceView'
                            ErrorAction       = 'Stop'
                        }
                        $checkCmdOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView.Output
                        $messageTxt = "[$vmName] INFO: $checkCmdOutput"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"

                        $diskTypeCheck = $false
                        $efiPartitionCheck = $false
                        $bootEfiCheck = $false
                        if ($checkCmdOutput -match "disk type:\s*(\w+),") {
                            $diskType = $matches[1]
                            if ($diskType -eq "gpt") {
                                $diskTypeCheck = $true
                            }
                        }
                        if ($checkCmdOutput -match "EFI partition:\s*([^,]+),") {
                            $efiPartition = $matches[1]
                            if ($efiPartition -ne "") {
                                $efiPartitionCheck = $true
                            }
                        }
                        if ($checkCmdOutput -match "/boot/efi present") {
                            $bootEfiCheck = $true
                        }
                        if ($diskTypeCheck -and $efiPartitionCheck -and $bootEfiCheck) {
                            $messagetxt = "[$vmName] INFO: EFI partition for Linux VM  $vmname validated successfully."
                            Write-Output $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                        } else {
                            $messagetxt = "[$vmName] ERROR: EFI partition for Linux VM $vmname not found. Terminating script execution."
                            Write-Error $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                            Set-ErrorLevel -1
                        }
                    }
                }
            }
            catch [System.Exception] {
                $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        #region - MBR to GPT conversion
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($gen2Vm -eq $false) {
                    if ($currentOsDiskConfig.osType -eq "Linux") {
                        $messageTxt = "[$vmName] INFO: No MBR to GPT conversion required for Linux VM $($vmName)."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "MBR-GPT-Execution"
                    }
                    else {
                        $messageTxt = "[$vmName] INFO: Executing MBR to GPT conversion on $vmname"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"

                        $messageTxt = "[$vmName] INFO: Validating MBR to GPT conversion support for $vmname"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"

                        $paramSetAzVMRunCommand = @{
                            ResourceGroupName = $vmResourceGroupName
                            VMName            = $vmName
                            Location          = $CurrentVMConfig.location
                            RunCommandName    = 'managedRuncommand'
                            SourceScript      = "MBR2GPT /convert /allowFullOS"
                            TimeoutInSecond   = 120
                            Erroraction       = 'Stop'
                        }
                        Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
    
                        $paramGetAzVmRunCommand = @{
                            ResourceGroupName = $vmResourceGroupName
                            VMName            = $vmName
                            RunCommandName    = 'managedRuncommand'
                            Expand            = 'InstanceView'
                            ErrorAction       = 'Stop'
                        }
                        $convertCmdOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView

                        if ($convertCmdOutput.Error.Length -gt 0 -or $convertCmdOutput.Output.Length -eq 0) {
                            $messagetxt = "[$vmName] ERROR: MBR to GPT conversion for Windows $vmname failed. Terminating script execution."
                            Write-Error $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Execution"

                            $messageTxt = "[$vmName] INFO: Fetching setupact.log for $vmname"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"

                            $paramSetAzVMRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                Location          = $CurrentVMConfig.location
                                RunCommandName    = 'managedRuncommand'
                                SourceScript      = "Get-Content C:\WINDOWS\setupact.log"
                                TimeoutInSecond   = 120
                                Erroraction       = 'Stop'
                            }
                            Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
        
                            $paramGetAzVmRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                RunCommandName    = 'managedRuncommand'
                                Expand            = 'InstanceView'
                                ErrorAction       = 'Stop'
                            }
                            $setupActOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView
                            $setupFileStamp = (Get-Date -Format yy.MM.dd-HH.mm.ss)
                            if ($useCloudshell) {
                                $setupActOutFile = [system.string]::concat($workingDirectory, "/", $vmName, "-",$setupFileStamp, "-mbr2gpt-convert-setupact.log")
                            } else {
                                $setupActOutFile = [system.string]::concat($workingDirectory, "\", $vmName, "-",$setupFileStamp, "-mbr2gpt-convert-setupact.log")
                            }

                            $messageTxt = "[$vmName] INFO: Writing setupact.log to $setupActOutFile"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            $setupActOutput.Output | Out-File -FilePath $setupActOutFile -Force -ErrorAction 'Stop'

                            $messageTxt = "[$vmName] INFO: Fetching setuperr.log for $vmname"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"

                            $paramSetAzVMRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                Location          = $CurrentVMConfig.location
                                RunCommandName    = 'managedRuncommand'
                                SourceScript      = "Get-Content C:\WINDOWS\setuperr.log"
                                TimeoutInSecond   = 120
                                Erroraction       = 'Stop'
                            }
                            Set-AzVMRunCommand @paramSetAzVMRunCommand | Out-Null
        
                            $paramGetAzVmRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                RunCommandName    = 'managedRuncommand'
                                Expand            = 'InstanceView'
                                ErrorAction       = 'Stop'
                            }
                            $setupErrOutput = (Get-AzVMRunCommand  @paramGetAzVmRunCommand).InstanceView
                            if ($useCloudshell) {
                                $setupErrOutFile = [system.string]::concat($workingDirectory, "/", $vmName, "-",$setupFileStamp, "-mbr2gpt-convert-setuperr.log")
                            } else {
                                $setupErrOutFile = [system.string]::concat($workingDirectory, "\", $vmName, "-",$setupFileStamp, "-mbr2gpt-convert-setuperr.log")
                            }

                            $messageTxt = "[$vmName] INFO: Writing setuperr.log to $setupErrOutFile"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            $setupErrOutput.Output | Out-File -FilePath $setupErrOutFile -Force -ErrorAction 'Stop'

                            Set-ErrorLevel -1
                        }  else {
                            $messagetxt = "[$vmName] INFO: MBR to GPT conversion for Windows $vmname completed successfully."
                            Write-Output $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                        }
                    }
                }
            }
            catch [System.Exception] {
                $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Execution"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        #region - Upgrade VM to Trusted launch
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($tlvm -eq $false) {
                    $messageTxt = "[$vmName] INFO: De-allocating $vmname"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramStopAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        Name              = $vmName
                        Force             = $true
                        Confirm           = $false
                        ErrorAction       = 'Stop'
                    }
                    Stop-AzVm @paramStopAzVm | Out-Null

                    $messageTxt = "[$vmName] INFO: Updating security type for $vmname to Trusted launch"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramUpdateAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        VM                = $currentVm
                        SecurityType      = 'TrustedLaunch'
                        EnableVtpm        = $true
                        ErrorAction       = 'Stop'
                    }
                    if ($enableSecureBoot -eq $true) {
                        $paramUpdateAzVm.Add('EnableSecureBoot', $true)
                    } 
                    else { $paramUpdateAzVm.Add('EnableSecureBoot', $false) }
                    Update-AzVM @paramUpdateAzVm | Out-Null

                    $messageTxt = "[$vmName] INFO: Starting $vmname"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramStartAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        Name              = $vmName
                        ErrorAction       = 'Stop'
                    }
                    Start-AzVM @paramStartAzVm | Out-Null
                }
            }
            catch [System.Exception] {
                $messageTxt = "[$vmName]" + ' ERROR: Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Upgrade-AzVM"
                Set-ErrorLevel -1
                return $ERRORLEVEL
            }
        }
        #endregion

        #region - closure
        if ($ERRORLEVEL -eq 0) {
            $messageTxt = "[$vmName] INFO: Gen1 to Gen2-Trusted launch upgrade complete for $vmName."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
        }
        #endregion
    }
    #endregion   
}
# SIG # Begin signature block
# MIIoQQYJKoZIhvcNAQcCoIIoMjCCKC4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3EYTq025wflVs
# 3pk2c1iF9hBvuagHYJ7/3UYL9ndTGaCCDYswggYJMIID8aADAgECAhMzAAAD9LjE
# XeFOcLZ+AAAAAAP0MA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwNzE3MjEwMjM1WhcNMjUwOTE1MjEwMjM1WjCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IDNyZCBQYXJ0eSBBcHBsaWNhdGlvbiBDb21wb25lbnQwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv3P8bL08GKolFW7QNDVOF0aM4iqMxVvAW
# VM124/82xbjAraJkKxieMrQa1Fc95LVGgxmJIi5R6QKMz2MO9bnwC7kSkPqoZJil
# 26bRLY6jinjbwPpK3TzbW7z9bXfWw5bPFlt72NVIdXJ3xtHoYa+AOi++CF2Ry7+7
# o1AzvotJwG6lQSiCMKeMt8apqEF1f+QkDFEUv5tezw9748DeHW9orvo4IPzWa7vW
# QgljB08LKSnzTN9/Jot2coWpFv4YuEoJZmR2ofPJMnDUUruDORTXnxwhfvd/wUmI
# SoEysSqobkNV+qFuUmSShYrx8R1zHm7P6G/iRMIKYmSrIYBKUvndAgMBAAGjggFz
# MIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3TBEBBggrBgEFBQcDAzAdBgNVHQ4EFgQU
# Dz4uMjS8YCSZaU0449GJYQ1ufyowRQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNMjMxNTIyKzUwMjUxODAfBgNV
# HSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0Ey
# MDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZF
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQ
# Q0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBABUCAiEn4g8i5T3VCP8160IY4ERdvZi5QZ2pSnBPW1dswVhLxkNTiCTV
# XKDjTQ4EwDBNSZZGJePz4+t86pKhlBON3S7wswf5fCovJLlIiKbw+E4TZeY6xAxd
# +5zV7Q2lsQhPHxiOY0PIGUE0KJfv/DQUulD8DrE0rru7yOO+DJI0muoK0BbHhRfd
# mAJhp2gbYRkarEIkhML9m3gR12mCBb69Vocm4IyOBivUPMjjvQMkERF7cR07k2uP
# 6dmpR8wtof9la0/K0wgiP5XuQUsAqgzhXrljH7dK7nqGrBDjJtrRdYfvVL+Rcz9i
# YZO280g2uNtac5em3HOEsactAL7XKqZ4o7s9sRyp/bTNLLRmhFMB729IL+Hi0YM7
# C8th3HZ5nP+77L46KUGip6QgRIJs+EO0YNW+AwgMxPfKpTx/Ggh8Z85kP7HLDZJk
# ZdPO/3cgVOTO4ax21vO2yMPCdfoGGr2ZLZw4SjEbGuOZJ22iGMV7tBvHk8nWAt3q
# +j/icAq99GA1nIPnw3jK3K9OwGqwA9eiWsO8/bHMm6s50UKIFupMKm6qObosaVBy
# R58rf8Cxumka7hPy1eSJSzQyA4UqYNTWuChsTfqgRLmLomS6yAu7t4r/bM4mGl+2
# Ki+avhQ4COm3jWWd0V6UGIP3T4zaKNs2GWFBIYsb/6XVvvi7pz/JMIIHejCCBWKg
# AwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYw
# NzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGf
# Qhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRg
# JGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NE
# t13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnn
# Db6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+E
# GvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+t
# GSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxh
# H2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AV
# s70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f
# 7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3D
# KI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9Jaw
# vEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1Ud
# DgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRy
# LToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDEx
# XzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDEx
# XzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2Nz
# L3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAA
# bwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUA
# A4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+
# vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4H
# Limb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6
# aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiX
# mE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn
# +N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAq
# ZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5h
# YbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/
# RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXm
# r/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMyk
# XcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGgwwghoIAgEB
# MIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNV
# BAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAP0uMRd4U5w
# tn4AAAAAA/QwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIDTp0KahYgUM0mifo1YcLwSvKz+XGc+LTZg6mqExVe1/MEQGCisGAQQBgjcC
# AQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNy
# b3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQCiaOAC1UpyqNoheCbEKcxqR81O
# EVAJezelJ92Tk/pEfg+B2WG0bDFiOP1oWUiGKnPzH9HnrSHIHG1RHRc3JrLa3lH6
# eXNI/pcGsQJbuQqMEU2T94GXRwgxQfK5vzCllSw315HkDVLeeVO5FAGYPiw3qmJL
# OsSQAO2frldGQdplWkTKO3Xxgd7FiFAcFv7BBzR2n5gOayNynMLDI0pNjP3weFkX
# ICT8CMQlv2DDm91KIVu1D01OVNfsyOwpv2LpMV5FewBbeSxOIYDg+J/cp74ySpgA
# W3wxUpyjmJQf5IwLukNk68mYUpeLHHvFZzTQ/YVy0K6u+ZYg8rEASQdFcLRhoYIX
# lDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIXbTCCF2kCAQMx
# DzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEB
# BgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIAyxaQouhqqohYXDPiJR7IbG
# 5OMkU/j7x79Cfp2KDyGmAgZnPydsZLsYEzIwMjQxMjA0MTYyNTA4LjAzOVowBIAC
# AfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo4RDAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgECAhMzAAAB88UK
# Q64DzB0xAAEAAAHzMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTIzMTIwNjE4NDYwMloXDTI1MDMwNTE4NDYwMlowgcsxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
# c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# Tjo4RDAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAP6fptrhK4H2
# JI7lYyFueCpgBv7Pch/M2lkhZL+yB9eGUtiYaexS2sZfc5VyD7ySsl2LG41Qw7tk
# A6oJmxdSM7PzNyfVpQPkPavY+HNUqMe2K9YaAaPjHnCpZ7VCi/e8zPxYewqx9p0i
# VaN8EydUpWiY7JtDv7aNzhp/OPZclBBKYT2NBGgGiAPCaplqR5icjHQSY665w+vr
# vhPr9hpM+IhiUZ/5dXa7qhAcCQwbnrFg9CKSK1COM1YcAN8GpsERqqmlqy3GlE1z
# iJ3ZLXFVDFxAZeOcCB55Vts9sCgQuFvD7PdV61HC4QUlHNPqFtYSC/P0sxg9JuKg
# cvzD5mJajfG7DdHt8myp7umqyePC+eI/ux8TW61+LuTQ1Bkym+I6z//bf0fp4Dog
# 5W0XzDrqKkTvURitxI2s4aVObm6qr6zI7W51k54ozTFjvbw1wYMWqeO4U9sQSbr5
# 61kp+1T2PEsJLOpc5U7N2oDw7ldrcTjWPezsyVMXhDsFitCZunGqFO9+4iVjAjYD
# N47c6K9x7MnAGPYVCBOJUdpy8xAOBIDsTm/K1qTT4wsGbQBxbgg96vwDiA4YP2hK
# mubIC7UnrAWQGt/ZKOf6J42roXHS1aPwimDe5C9y6DfuNJp0XqrWtQRqg8hqNkIZ
# WT6jnCfqu35zB0nf1ERTjdpYLCfQL5fHAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU
# w2QV9qURUQyMDcCmhTH2oOsNCiQwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAN/E
# HI/80f7v29zeWI7hzudcz9QoVwCbnDrUXFHE/EJdFeWI2NnuwOo0/QPNRMFT21Lk
# OqSpFKIhXXmPurx7p6WDz9wPdu/Sxbgaj0AwviWEDkwGDfDMp2KF8nQT8cipwdfX
# WbC1ulOILayABSHv45mdv1PAkTulsQE8lBTHG4KJLn+vSzZBWKkGaL/wwRbZ4iLi
# Yn68cjkMJoAaihPgDXn/ug2P3PLNEAFNQgI02tLX0p+vIQ3l2HmSo4bhCBxr3Dov
# sIv5K65NmLRJnxmrrmIraFDwgwA5XF7AKkPiVkvo0OxU1LAE1c5SWzE4A7cbTA1P
# 5wG6D8cPjcHsTah1V+zofYRgJnFRLWuBF4Z3a6pDGBDbCsy5NvnKQ76p37ieFp//
# 1I3eB62ia1CfkjOF8KStpPUqdkXxMjfJ7Vnemd6vQKf+nXkfvA3AOQECJn7aLP01
# QR5gt8wab28SsNUENEyMawT8eqpjtBNJO0O9Tv7NnBE8aOJhhQVdP5WCR90eIWkr
# DjZeybQx8vlo5rfUXIIzXv+k9MgpNGIqwMXfvRLAjBkCNXOIP/1CEQUG72miMVQs
# 5m/O4vmJIQkhyqilUDB1s12uhmLYc3yd8OPMlrwIxORB5J9CxCkqvzc6EGYTcwXa
# zPyCp7eWhzTkNbwk29nfbwmmzcskIAu3StA8lic7MIIHcTCCBVmgAwIBAgITMwAA
# ABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAw
# OTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6c
# BwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWN
# E893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8
# OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6O
# U8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6
# BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75x
# qRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrb
# qn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XY
# cz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK
# 12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJR
# XRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnG
# rnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQM
# HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
# IwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0
# dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
# Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEk
# W+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zR
# oZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1
# AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthIS
# EV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4s
# a3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32
# THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMB
# V0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5P
# ndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUx
# UYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi
# 6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6C
# baUFEMFxBmoQtB1VM1izoXBm8qGCA00wggI1AgEBMIH5oYHRpIHOMIHLMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# OEQwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WiIwoBATAHBgUrDgMCGgMVAG76BizYtGFrmkU7v2DcuR/ApGcooIGDMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQAC
# BQDq+sh2MCIYDzIwMjQxMjA0MTIyNDIyWhgPMjAyNDEyMDUxMjI0MjJaMHQwOgYK
# KwYBBAGEWQoEATEsMCowCgIFAOr6yHYCAQAwBwIBAAICBv8wBwIBAAICEw8wCgIF
# AOr8GfYCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEADOtfE7oFKg4+gDu/
# tPyYywgkm35HzTXJdkBevryLr76FOu+ciZsMQ9Tghi1IMMvoeE+IBX5EaLK8qO0E
# kY7pTEAn7guhUyA3/6ViQlgXmRLeBbhVuJNg7h7wvyyv9L5AYXkOFrE3rGUo1fGf
# nf7seE5Y7v6hELF0V3zY6mjVEDCuejhb0QMy3N5Jg5OpsdIA80Hz0WdJgdoyGZtl
# AuoERN573I53gxwjSPKbLiWhMYdWsG5qVKqN6dWQT/xbIFDH3MJPcIDbRiglXgCd
# w6GaWHYjytA8hEsJENDtDeukGWdKmoybhfgqxSWuwYNYIdY9hDPhD4yfnBmAer4Z
# qaNarjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAAB88UKQ64DzB0xAAEAAAHzMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGQXtAz59GoWWNBl
# 25jbA7HvL0/gweRHom8ieFN6zm8mMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgGLzZNIu24bhWSnzAGYmT9P5ECHzjWwb9oM7DGDo7YugwgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfPFCkOuA8wdMQABAAAB8zAi
# BCA6G+nwQLAG2J6I4eXZ6QswwRN2ChwnxgwUgA7QLoP8/jANBgkqhkiG9w0BAQsF
# AASCAgAGOtLybg7num6e3+s7ntU6cADNUhnP+jPRs1akxZtawgZAEla3Ckap4hjI
# kU1tbIsWZD1Qm2rQ2uuqhIMu/YKs3C8URxee9rjTlct11qlgPE0WLZXxeMSho/Eg
# cokpuF3z3BKIZQ+nHlVcjeaIzBvMcjsoWT4Z7xEwqg445mUnwYAFbAnu04Ho1mhj
# 7hDzuM5Sv/WrEUjBw5v4gfWpu42nZX3grEgyzatz0Vjjt58B2SOkj3IBbL3LZY9P
# s3oF8/odLULfN4X0Gt+hewKsr0S7DyifRG0t48w3sa1O6KNoS1iDpTK/G+xk/aR0
# xdisA6Q8J6hZS2aA5vNC7VObQVODlSvGqcMb/tZZZU6bdZ7WKpOMNhZl1kFEgdhX
# RXaXNa63WsUCWqMMcINeGnRfA14AqEbbJsYD/gtMzSmsx3UFFyLf71aGTxsfRDC5
# zpGZfdFImHBWFd+2PI6xwJ1evPy9Ut7EgmtBBOa4FOitbht9kpCkQBymlwx3zjgy
# PLXNwwjRd8aBUL1m+BarcV3eOJ8FiJ8lNfSBq8VY24ka1zzwMl0QbOe0eUzUUsVX
# RA54wqUAEco9KggRERnIWb9g+vytaRnEvD4BBHYihh4noZwgTkTRjGPJEbu5RULI
# lsDbUvWZG1qVyj6ioEa7BVSsq0/P2Hba2Ih8NgnoMB0Q60iuAA==
# SIG # End signature block
