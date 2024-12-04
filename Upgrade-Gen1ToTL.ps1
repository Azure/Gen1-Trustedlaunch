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
                        $messageTxt = "[$vmName] INFO: Writing validation script to gen2LinuxCheckCmd.txt"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                        if ($useCloudshell) {
                            $checkCmdFile = [system.string]::concat($workingDirectory, "/gen2LinuxCheckCmd.txt")
                        } else {
                            $checkCmdFile = [system.string]::concat($workingDirectory, "\gen2LinuxCheckCmd.txt")
                        }
                        $stream = [System.IO.StreamWriter]::new($checkCmdFile)
                        $stream.WriteLine($checkLinuxCmd)
                        $stream.Close()

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