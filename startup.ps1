<#
  .SYNOPSIS
      Startup script for contextualization of windows vm on OpenNebula
  .DESCRIPTION
      Startup script for contextualization of windows vm on OpenNebula. The function of this script : find and call the context.ps1
  .USAGE
      1. Copy the script to your hdd (using the default startup script folder is not obliged chose (C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\ ))  
      2. Open the local Group Policy Dialog by running gpedit.msc. Under: Computer Configuration => Windows Settings => Script => startup -> PowerShell Scripts -> Add
      3. Browse to your script
      4. NOT required but if need ... Script Parameters : -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted
      5. Run script order : PoweShell script first
  .AUTHOR
      Eric Nicolay (UCLouvain.be)
  .NOTES
      This script call the context.ps1 ($OpenNebulaContextScriptName) from your context drive ($ContextDrive)
  .OUTPUT
      log file : .opennebula-startup.out

#>

$OpenNebulaContextScriptName = "context2019.ps1" #your OpenNebula CONTEXT.PS1 name
$LogFullPath = "$env:SystemDrive\Admin\OpenNebula\.opennebula-startup.out"

Start-Transcript -Append -Path $LogFullPath | Out-Null
Write-Output "Running Script: $($MyInvocation.MyCommand.Definition)" -
Get-Date
Write-Output ""

$ContextDrive = Get-WmiObject Win32_Volume | ?{$_.Label -eq "CONTEXT"}
if($ContextDrive)
{
   $ContextDrivePowershellScript = $ContextDrive.Name+$OpenNebulaContextScriptName
   Write-Output "Calling this Script: $($ContextDrivePowershellScript)"
   Stop-Transcript | Out-Null
   Powershell.exe -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -file $ContextDrivePowershellScript
}else
  {
    Write-Output "!!!!  No CONTEXT DRIVE found !!!!!"
    Stop-Transcript | Out-Null
  } 