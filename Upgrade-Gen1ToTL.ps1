<#

    	.NOTES
	============================================================================================================
	Copyright (c) Microsoft Corporation. All rights reserved.
	File:		Upgrade-Gen1ToTL.ps1
	Purpose:	Gen1 to Trusted launch upgrade
	Pre-Reqs:	Windows PowerShell version 7.2+ and Azure PowerShell Module version 12.2+ 
	Version: 	3.0.0
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
    Script Version - 3.0.0

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
            $messageTxt = "[$vmName] INFO: Script Version: 3.0.0"
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
bootDevice=$(echo "/dev/$(lsblk -no pkname $(df /boot | awk 'NR==2 {print $1}'))") && diskType=$(blkid $bootDevice -o value -s PTTYPE) && efiPartition=$(fdisk -l $bootDevice | grep EFI | awk '{print $1}') && biosPartition=$(sudo sgdisk -p /dev/sda | awk 'BEGIN {IGNORECASE = 1} /ef02/ {print "/dev/sda" $1}') && grep -qs '/boot/efi' /etc/fstab && echo 'Boot device: '$bootDevice', disk type: '$diskType', EFI partition: '$efiPartition', BIOS partition: '$biosPartition', /boot/efi present in /etc/fstab'|| echo 'Boot device: '$bootDevice', disk type: '$diskType', EFI partition: '$efiPartition', BIOS partition: '$biosPartition', /boot/efi missing in /etc/fstab'
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
                        if ($checkCmdOutput -match "BIOS partition:\s*([^,]+),") {
                            $biosPartition = $matches[1]
                            if ($biosPartition -ne "") {
                                $biosPartitionCheck = $true
                            }
                        }
                        if ($checkCmdOutput -match "/boot/efi present") {
                            $bootEfiCheck = $true
                        }
                        if ($diskTypeCheck -and $efiPartitionCheck -and $biosPartitionCheck -and $bootEfiCheck) {
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
# MIIoXQYJKoZIhvcNAQcCoIIoTjCCKEoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAe65ummLZMbBNA
# A+bCzj2dIq2m7ZniAlv2nhQGfu+6/KCCDYswggYJMIID8aADAgECAhMzAAAD9LjE
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
# XcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGigwghokAgEB
# MIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNV
# BAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAP0uMRd4U5w
# tn4AAAAAA/QwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIKBypyaC5l0akzmEmnO7B+rk11plCrSbwLxLbzazui6GMEQGCisGAQQBgjcC
# AQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNy
# b3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQCeLor+c2EWnK65TBws+oTF8XYs
# HVKpdxuCLS0iaiXUUtAp7XXe8SdqAEWlF2TmT0qSPmjXtXOIsAYwdUusy7IE76xo
# tTKBzgl6bOoV1pB84TZ/LCVL2/eKzI8YeT819piIv0KFLvlK1CUoOEvzUvQv4NJ3
# cNpl7BeZpFXBxbQcjmr+R+4HkeIqsdBTDEGwOxnEmH+DMF5IqhgCWadsCL7tIeN0
# kz9nIpB86kxjE9kaYfeThmqNb1CZgf/zGXp1x/uny5a/bF+yueTJzqUlAm6+OrMN
# 7nZVKBCtATYs2pmNk7jL/kziWs0EQhKiDlgssNrvGkqV1LaalbUUJT36vGrloYIX
# sDCCF6wGCisGAQQBgjcDAwExghecMIIXmAYJKoZIhvcNAQcCoIIXiTCCF4UCAQMx
# DzANBglghkgBZQMEAgEFADCCAVoGCyqGSIb3DQEJEAEEoIIBSQSCAUUwggFBAgEB
# BgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIPM97JFVu7lng4rs/uH5AtRW
# Dn9RAPA+Pjb082zokKSPAgZnO790Fq4YEzIwMjQxMTI3MTA1NTA1LjkxOVowBIAC
# AfSggdmkgdYwgdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjMyMUEtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR/jCCBygwggUQoAMCAQIC
# EzMAAAH4o6EmDAxASP4AAQAAAfgwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwHhcNMjQwNzI1MTgzMTA4WhcNMjUxMDIyMTgzMTA4
# WjCB0zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQL
# Ex5uU2hpZWxkIFRTUyBFU046MzIxQS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDFHbeldicPYG44N15ezYK79PmQoj5sDDxxu03nQKb8UCuNfIvhFOox
# 7qVpD8Kp4xPGByS9mvUmtbQyLgXXmvH9W94aEoGahvjkOY5xXnHLHuH1OTn00CXk
# 80wBYoAhZ/bvRJYABbFBulUiGE9YKdVXei1W9qERp3ykyahJetPlns2TVGcHvQDZ
# ur0eTzAh4Le8G7ERfYTxfnQiAAezJpH2ugWrcSvNQQeVLxidKrfe6Lm4FysU5wU4
# Jkgu5UVVOASpKtfhSJfR62qLuNS0rKmAh+VplxXlwjlcj94LFjzAM2YGmuFgw2Vj
# F2ZD1otENxMpa111amcm3KXl7eAe5iiPzG4NDRdk3LsRJHAkgrTf6tNmp9pjIzhd
# IrWzRpr6Y7r2+j82YnhH9/X4q5wE8njJR1uolYzfEy8HAtjJy+KAj9YriSA+iDRQ
# E1zNpDANVelxT5Mxw69Y/wcFaZYlAiZNkicAWK9epRoFujfAB881uxCm800a7/Xa
# mDQXw78J1F+A8d86EhZDQPwAsJj4uyLBvNx6NutWXg31+fbA6DawNrxF82gPrXgj
# SkWPL+WrU2wGj1XgZkGKTNftmNYJGB3UUIFcal+kOKQeNDTlg6QBqR1YNPZsZJpR
# kkZVi16kik9MCzWB3+9SiBx2IvnWjuyG4ciUHpBJSJDbhdiFFttAIQIDAQABo4IB
# STCCAUUwHQYDVR0OBBYEFL3OxnPPntCVPmeu3+iK0u/U5Du2MB8GA1UdIwQYMBaA
# FJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUH
# MAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9z
# b2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQC
# MAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqG
# SIb3DQEBCwUAA4ICAQBh+TwbPOkRWcaXvLqhejK0JvjYfHpM4DT52RoEjfp+0MT2
# 0u5tRr/ExscHmtw2JGEUdn3dF590+lzj4UXQMCXmU/zEoA77b3dFY8oMU4UjGC1l
# jTy3wP1xJCmAZTPLDeURNl5s0sQDXsD8JOkDYX26HyPzgrKB4RuP5uJ1YOIR9rKg
# fYDn/nLAknEi4vMVUdpy9bFIIqgX2GVKtlIbl9dZLedqZ/i23r3RRPoAbJYsVZ7z
# 3lygU/Gb+bRQgyOOn1VEUfudvc2DZDiA9L0TllMxnqcCWZSJwOPQ1cCzbBC5Cudi
# dtEAn8NBbfmoujsNrD0Cwi2qMWFsxwbryANziPvgvYph7/aCgEcvDNKflQN+1LUd
# kjRlGyqY0cjRNm+9RZf1qObpJ8sFMS2hOjqAs5fRQP/2uuEaN2SILDhLBTmiwKWC
# qCI0wrmd2TaDEWUNccLIunmoHoGg+lzzZGE7TILOg/2C/vO/YShwBYSyoTn7Raa7
# m5quZ+9zOIt9TVJjbjQ5lbyV3ixLx+fJuf+MMyYUCFrNXXMfRARFYSx8tKnCQ5do
# iZY0UnmWZyd/VVObpyZ9qxJxi0SWmOpn0aigKaTVcUCk5E+z887jchwWY9HBqC3T
# SJBLD6sF4gfTQpCr4UlP/rZIHvSD2D9HxNLqTpv/C3ZRaGqtb5DyXDpfOB7H9jCC
# B3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAw
# gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMT
# KU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIx
# MDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57Ry
# IQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VT
# cVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhx
# XFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQ
# HJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1
# KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s
# 4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUg
# fX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3
# Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je
# 1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUY
# hEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUY
# P3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGC
# NxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4w
# HQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYB
# BAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcD
# CDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOC
# AgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/a
# ZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp
# 4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq
# 95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qB
# woEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG
# +jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3B
# FARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77
# IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJ
# fn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K
# 6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDx
# yKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNZMIICQQIBATCC
# AQGhgdmkgdYwgdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjMyMUEtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQC2
# RC395tZJDkOcb5opHM8QsIUT0aCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA6vFyKjAiGA8yMDI0MTEyNzEwMjU0
# NloYDzIwMjQxMTI4MTAyNTQ2WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDq8XIq
# AgEAMAoCAQACAgUPAgH/MAcCAQACAhQJMAoCBQDq8sOqAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBACYn1v8IBrp3NZXPIraJG8sjoSrg7oJ2W2B2c2ZHIT2/
# Uzu4gyoDunbY1aaBXAb7fQVlLNt3IMi2NVjc24Wgtuh7lai893bUwDgPGg/TPQ7l
# d3e6aV42Ny+YZSvZJdgIRbSV2n9aoF06yh0RmNalxKoyuw0jg6xLJABY4HDh0r+O
# fuqJEOFXxjNMoAqOs8n2pqBLB4Yv4iDT2ka3MfO+lRL0kKaN2JTk9ZzPvdtm7joc
# hTVPLHcI93dNtBVH6qfkYNCMEHqww3GSYnobZfyEl+pjHMFSL50WdyCciOCkyZFI
# ES9r6w2JWZxQgw9EAU0/KHO+TQprLlu2il/+PxieA7UxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfijoSYMDEBI/gABAAAB
# +DANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCDmqkYLC5LVUT93/+k4rCjb412VlY/K4dauLtGCBH8A
# FTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIO/MM/JfDVSQBQVi3xtHhR2M
# z3RC/nGdVqIoPcjRnPdaMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAH4o6EmDAxASP4AAQAAAfgwIgQgaZSbdoe1BuEazJsYiNrdBH6w
# hkSZfs+lNBHcHPlz05cwDQYJKoZIhvcNAQELBQAEggIAMqv8XdpYSF9efgb5OTLH
# JWM0kssiTr6M9QyV7QljM8xSmujFz+FbcFlruYmEFDEpm/Iqy4KJl3BpCWiyovIZ
# YRdTaaVki2N1Vab4ocB3Vo3Uxoj9RYeoAxPk5J9IFeVLWiaxcYMnvx+LZuaw3jYZ
# Tntni4WaJQ/NL60HVAjyqIYVKLhfcYPkZHo0aEBJW1hRfPzYgy44MnICZrB9ZdSy
# i+Pdw/soLegmnZvognF4vxfdxLEcTsYX1lNl/gQD3UkRDKijVuO9iGiwXtiSHCcx
# ybr1V1uzYU2EDh5QWrDALD3I5Nvfd/XVqhMIGSPsR2qgzK75WBcl60rIU0f5a6Hi
# 9kSqGTajOybD4rVC3gVTGmYx7xLyLnUXcLzuwwE6uWvZjUHnGGF62WFDN1Lr4uQ5
# X34hmoUszrvLGRIRqUUvQZLsWVma7j6b4HN5pu/HoKMvKqeN216vOHfg437kuZRk
# Kchy7ugSn/YdLhR/lk5jjkCNgGxCKXTX1aSRWpnQ6Ds9qzxzTRPWyIjaqEyFyQBo
# TPQLF7Q92FE6cQdU8c3Fo0OtA1ZgHxkmC1WaL2L4NtR+d/LAVVCE5u7vde3Zgy8k
# SYnB6y+shni3lUJktpTaOjeALtl6BEbyH+7IuLO93u7JPTLGsRESbClTTyZ2efMP
# Uhqkj1JBRkr++Xwl42JWXxs=
# SIG # End signature block
