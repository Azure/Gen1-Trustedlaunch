# (PREVIEW) Azure Gen1 to Gen2-Trusted launch VM Upgrade

[Azure Generation 2 (Gen2) VM](https://learn.microsoft.com/azure/virtual-machines/generation-2) is based on UEFI-based boot architecture which enables key scenarios including [Trusted Launch (TLVM)](https://learn.microsoft.com/azure/virtual-machines/trusted-launch). Gen2 TLVM provides customers with secure compute solutions with security capabilities like:

Feature Name    |    Description
-|-
Secure Boot    |    Protects OS against rootkits and boot kits.
vTPM    |    It serves as a dedicated secure vault for keys and measurements, enabling attestation by measuring the entire boot chain of your VM
Guest VM Attestation    |    Guest attestation extension enables proactive attestation and monitoring the boot integrity of your VMs.

Newer OS like Windows Server 2022 Azure Edition require UEFI, Windows 11 requires UEFI & vTPM as pre-requisite for installation. Additionally, for enabling [Azure Compute security benchmark](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows#secured-core) (like Secure Boot), UEFI support in OS is mandatory.

You can now upgrade existing Gen1 (BIOS) VMs to Trusted launch. Learn more about this feature at **https://aka.ms/TrustedLaunchUpgrade**
This repository provides end users with PowerShell script-based guidance which they can self-execute & upgrade existing Gen1 (BIOS) VMs to Gen2 (UEFI) VMs.

**NOTE**: Please review the list of [Known issues](#known-issues) before executing validation.

**IMPORTANT DISCLAIMER**

This script is not supported under any Microsoft standard support program or service.

This script is provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.

The entire risk arising out of the use or performance of the script and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.

## Pre-Requisites

Pre-Requisite    |    Description
-|-
On-board subscription for preview    |    Register for **Gen1 to Trusted launch upgrade preview** at https://aka.ms/Gen1ToTLUpgrade.
[PowerShell version 7.2 or above](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows)    |    Required version for parallel processing.
[Az PowerShell Module](https://learn.microsoft.com/powershell/azure/what-is-azure-powershell)    |    Required cmdlets for Azure Platform.
VM is in allocated / Running state.    |    Required to read current state and configuration of Gen1 VM and execute MBR to GPT conversion.
Operating System    |    Operating system should be [Trusted launch supported.](https://aka.ms/TrustedLaunch) except <ul><li>Windows Server 2016</li></ul>**NOTE**:<ul><li>For Linux VMs, execute MBR to GPT locally on VM. Refer to steps [Linux MBR to GPT conversion](#linux-os-mbr-to-gpt-conversion)<li> Windows Server 2016 does not natively supports `MBR to GPT` conversion.</li></ul>
Azure IaaS VM Agent    |    [Azure IaaS Windows VM Agent](https://learn.microsoft.com/azure/virtual-machines/extensions/agent-windows) OR [Azure IaaS Linux VM Agent](https://learn.microsoft.com/azure/virtual-machines/extensions/agent-linux) should be installed and healthy.
Disk Encryption    |    If enabled, Disable any OS disk encryption including Bitlocker, CRYPT prior to upgrade. All disk encryptions should be re-enabled post successful upgrade.
VM Backup    |    Azure Backup if enabled for VM(s) should be configured with Enhanced Backup Policy. Trusted launch security type cannot be enabled for Generation 2 VM(s) configured with Standard Policy backup protection.<br/>Existing Azure VM backup can be migrated from Standard to Enhanced policy using [Migrate Azure VM backups from standard to enhanced policy (preview)](https://learn.microsoft.com/azure/backup/backup-azure-vm-migrate-enhanced-policy)
VM Disaster Recovery    |    Azure site recovery (ASR) does not supports Trusted launch upgrade. If enabled, ASR should be disabled prior to upgrade and re-enabled post upgrade.
Linux VMs    |    Gen1 to Trusted launch upgrade script has been validated with Azure marketplace images Ubuntu 20.04, RHEL 8.4, SLES 15 SP3. For other distros, **mandatorily** validate the upgrade in lower environment before running in production.

## Best Practices

Best Practice    |    Description
-|-
Validate in lower environment    |    Enable Trusted launch on a test Generation 1 VM and ensure if any changes are required to meet the prerequisites before enabling Trusted launch on VMs associated with production workloads.
**Backup** Gen1 VM    |    Create restore point for Azure Generation 1 VM(s) associated with  workloads before enabling Trusted launch security type. You can use the Restore Point to re-create the disks and Generation 1 VM with the previous well-known state.
OS Disk free space    |    You will not be able to extend **Windows OS disk system volume** after MBR to GPT conversion. Recommendation is to extend system volume for future before executing Gen2-Trusted launch upgrade.
OS Defragmentation    |    **Windows OS disk volume** should be defragmented using command `Defrag C: /U /V`. This will reduce the risk of MBR to GPT conversion failure by freeing up end of partitions. For more details, refer to [defrag](https://learn.microsoft.com/windows-server/administration/windows-commands/defrag)
Known issues    |    Review the [Known issues](#known-issues) before executing upgrade.

## High-Level Upgrade Workflow

Id    |    Step    |    Description
-|-|-
1    |    Validate Pre-Requisites    |    Validate pre-requisites for executing script:<ul><li>Az.Account, Az.Compute PowerShell modules<li>Csv location (Refer to [sampleCsv](./.attachments/sample.csv) for schema details.)</ul>
2    |    Connect Azure Subscription and read Gen1 VM Configuration    |    Store Gen1 VM Configuration required for conversion:<ul><li>OS Disk Metadata<li>VM Size</li></ul>
3    |    Validate VM SKU Trusted launch Support   |    Validate if current VM Size assigned to Gen1 VM supports Trusted launch. If not, VM Size for Gen1 VM will need to be updated with [Trusted launch support](https://aka.ms/TrustedLaunch).<br/>For steps of changing VM Size, please refer to [Change the size of a Virtual Machine](https://learn.microsoft.com/azure/virtual-machines/resize-vm?tabs=portal).
4    |    Execute MBR to GPT conversion    |    Script will execute online MBR to GPT conversion of OS disk boot partition.<br/>**Note**: For Linux VMs created outside Azure cloud, refer to steps [Linux MBR to GPT conversion](#linux-mbr-to-gpt-conversion)
5    |    De-allocate and upgrade VM properties    |    Script will update the VM attributes from Gen1 to Gen2 and security type to Trusted launch.
6    |    Start VM    |    Post successful upgrade, VM will be started.

## Script execution

Parameter Name    |    Description    |    Mandatory
-|-|-
subscriptionId    |    Subscription ID for Gen1 VM to be upgraded.    |    True
tenantDomain    |    Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)    |    True
csvLocation    |    Local file path location of csv containing vmName, vmResourceGroupName, enableSecureBoot details.    |    True
batchSize      |    Number of machines which should be processed in parallel. Default set to 5.    |    False
useCloudShell    |    Use cloud shell in Azure Portal for script execution.    |    False

Csv column Name    |    Description    |    Mandatory
-|-|-
vmName    |    Resource Name of Gen1 VM to be upgraded.    |    True
vmResourceGroupName    |    Resource Group for Gen1 VM to be upgraded.    |    True
enableSecureBoot    |    If target Trusted Launch VM should be deployed with Secure Boot enabled (TRUE) or disabled (FALSE). By default set to **TRUE**.<br/>This option should be disabled if VM is hosting custom or unsigned boot drivers which cannot be attested.    |    False

**Example**

```azurepowershell
.\Upgrade-Gen1ToTL.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.onmicrosoft.com -csvLocation "C:\Temp\sampleCsv.csv"
    
# Upgrade all VMs provided in csv from Gen1 to Trusted launch with specific parameter values.
```

### Linux MBR to GPT conversion

>**DISCLAIMER**:
>
> - These steps are not supported by Microsoft or respective distro owners.
> - Review and validate the steps thoroughly before executing in production environment.
> - Take full backup of VM which can be used to restore VM as-is in event of any failure.
> - Ensure minimum 200M free disk space available on OS volume. Recommendation is to enlarge the OS disk by 200M before executing following steps for upgrade.

For Linux VMs which are created outside Azure OR which are not created using Azure marketplace/derived images, you need to run below steps to complete MBR to GPT conversion.

>**Note**: These steps do not apply for Linux VMs created using Azure marketplace or derived OS image.

Id    |    Step    |    Description
-|-|-
1    |    Query the OS Disk using below command<br/> `sudo lsblk -o NAME,HCTL,SIZE,MOUNTPOINT \| grep -i "sd"` | Identify the boot partition and associated disk<br/>![Identity boot partition](./.attachments/01-linux-identify-boot-partition.png)
2    |    Backup MBR partition:<br/>`sudo dd if=/dev/sda of=backup.mbr bs=512 count=1`    |    Backup should be taken on drive other than Boot drive.<br/>![Backup boot partition](./.attachments/02-backup-boot-partition.png)
3    |    Install `EFI Package`:<ul><li>**For Ubuntu**: `sudo apt install grub-efi-amd64`<br/>*Note*: `grub-efi-amd64-signed` is recommended if supported by OS configuration.<li>**For RHEL**: `sudo yum install gdisk grub2-efi-x64-modules efibootmgr dosfstools -y`</li></ul> | ![Ubuntu grub efi](./.attachments/01.On-Premise-Ubuntu.png)<br/>![RHEL grub efi](./.attachments/02.On-Premise-RHEL.png)
4    |    Execute gdisk command `sudo gdisk /dev/sda`to create new partition with following values:<br/><ul><li>Command: **n**<li>Partition Number: `default`<li>First Sector: **34**<li>Last Sector: **2047**<li>partition type **ef02**<li>Command: **w** to write the changes</ul>    |    ![Gdisk Execution](./.attachments/gdisk.png)
5    |    Update partition table changes:`sudo partprobe /dev/sda`    |    
6    |    Install Bootloader in re-partitioned boot disk:<ul><li>**For Ubuntu**: `sudo grub-install /dev/sda`<li>**For RHEL & SLES** `sudo grub2-install /dev/sda`</ul>    |    ![grub execute](./.attachments/grubinstall.png)
7    |    Execute gdisk to add an `EFI System` partition (ESP) with partition type **ef00**. Recommended size is **+200M** <br/>**Command**: `sudo gdisk /dev/sda`<ul><li>Command: **n**<li>Partition Number: `default`<li>First Sector:`default`<li>Last Sector:**+200M**<li>Partition type: **ef00**<li>Command: **w** to write the changes</li></ul> |    ![EF00 partition](./.attachments/03.On-PremiseEF02.png)
8    |    Execute gdisk to rename above created partition to `EFI-system`<br/>**Command**: `sudo gdisk /dev/sda`<ul><li>Command: **c**<li>Partition Number: `From Step 7 above`<li>Enter Name:`EFI-system` (case-sensitive)<li>Command: **w** to write the changes</li></ul>    |    ![EFI-system rename](./.attachments/04-On-PremiseEFI-System.png)
9    |    Update partition table changes:`sudo partprobe /dev/sda`    |    
10    |   Build vfat filesystem for ESP.<br/>`sudo mkfs -t vfat -v /dev/disk/by-partlabel/EFI-system`    |    ![Vfat ESP](./.attachments/05-vfat-ESP.png)
11    |   If does not exists already; create ESP Mountpoint<br/>`sudo mkdir /boot/efi`    |    
12    |   Copy existing files in /boot/efi to temporary /mnt/folder.<ol><li>`sudo mount -t vfat /dev/disk/by-partlabel/EFI-system /mnt`<li>`sudo mv  /boot/efi/* /mnt`<li>`sudo umount /mnt`</li></ol><br/>*Note*: You can skip step 12.2 if there're any error related to file does not exists.    |    
13    |   <ol><li>Open `/etc/fstab` using command `sudo vi /etc/fstab`<li>Add the ESP mountpoint to /etc/fstab. (replace spaces with tab key)<br/>`/dev/disk/by-partlabel/EFI-system /boot/efi vfat defaults 0 2`<li>Save `/etc/fstab` using command in vi editor `wq`.    |    ![ESP Mount](./.attachments/06-ESP-Mount.png)
14    |    Reload the systemd manager configuration using command `sudo systemctl daemon-reload`.    |    
15    |   Mount ESP<br/>`sudo mount /boot/efi`    |    
16    |   Install the GRUB EFI bootloader.<br/>**Ubuntu/Debian:**<br/>`sudo grub-install --target=x86_64-efi /dev/sda`<br/>**RHEL:**<br/>`sudo yum install grub2-efi shim -y`<br/> `sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg`    |    ![grub2 efi install](./.attachments/07a-grub2-efi-install.png)<br/>![grub 2 efi install contd](./.attachments/07b-grub2-efi-install.png)

## Post-Conversion Activities

After successful conversion of Gen1 to Trusted Launch VM, user needs to perform required steps for applicable scenarios from below list:

1. Validate health of Virtual Machine OS and workload hosted on converted Gen2 TLVM.
2. Re-enable all disk encryptions on Trusted launch virtual machine post successful upgrade.

## Troubleshooting

Share the log files available under folder `Gen1-Trustedlaunch-Upgrade` at `%userprofile%` with feature team to troubleshoot Gen1 to Trusted launch upgrade.

## Known issues

### Windows 11 boot fails

Windows 10 Gen1 VM is successfully upgraded to Trusted launch followed by successful Windows 11 in-place upgrade. However, the Windows 11 boot fails after Azure VM is stopped and started with below error.

![Windows 11 boot error](./.attachments/01.%20errorWindows11Boot.jpg)

**Resolved**: This issue has been fixed with [24H2 build version 26100.2314](https://learn.microsoft.com/windows/release-health/windows11-release-information#windows-11-current-versions-by-servicing-option). You can get ISO with this version from:

1. WSUS / Intune Windows 11 feature update for 24H2. OR,
2. Visual studio downloads OR,
3. ISO generated using [Create Windows 11 Installation media](https://www.microsoft.com/software-download/windows11).

### Cannot find room for the EFI system partition

This error occurs for one of following reason:

- There is no free space available on the system volume
- System volume is corrupted. You can validate by trying to Shrink Volume by few MBs under Disk Management console. Use command `chkdsk C:/v/f` to repair system volume.
- `Virtual Disk` service is not running or unable to communicate successfully. Service startup type should be set to `Manual`.
- `Optimize Drives` service is not running or unable to communicate successfully. Service startup type should be set to `Manual`.
- System volume disk is already configured with 4 MBR partitions (maximum supported by MBR disk layout). You need to delete one of the partition to make room for EFI system partition.
    1. Run `ReAgentc /info` to identify partition actively used by Recovery. Example: `Windows RE location:       \\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE`
    2. Run PowerShell cmdlet `Get-Partition -DiskNumber 0` to identify current partitions configured.
    3. Run PowerShell cmdlet `Remove-Partition -DiskNumber 0 -PartitionNumber X` to remove any extra **Recovery** partition not actively used by Recovery service as identified in Step 1.

### D Drive assigned to System Reserved Post upgrade

Temporary storage Drive letter assignment 'D' is changed to 'E' with previous letter assigned to System Reserved post-upgrade. The issue is being troubleshooted. execute below steps manually post-upgrade to workaround the issue:

After the upgrade check the disks on the server, if system reserved partition has the letter D:, do the following actions:

- reconfigure pagefile from D: to C:
- reboot the VM
- remove letter D: from the partition
- reboot the VM to show the temporary storage disk with D: letter

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
