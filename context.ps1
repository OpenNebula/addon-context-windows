# -------------------------------------------------------------------------- #
# Copyright 2002-2014, OpenNebula Project (OpenNebula.org), C12G Labs        #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

# Original work by:

#################################################################
##### Windows Powershell Script to configure OpenNebula VMs #####
#####   Created by andremonteiro@ua.pt and tsbatista@ua.pt  #####
#####        DETI/IEETA Universidade de Aveiro 2011         #####
#################################################################

Set-ExecutionPolicy unrestricted -force # not needed if already done once on the VM
[string]$computerName = "$env:computername"
[string]$ConnectionString = "WinNT://$computerName"

function getContext($file) {
    $context = @{}
    switch -regex -file $file {
        "^([^=]+)='(.+?)'$" {
            $name, $value = $matches[1..2]
            $context[$name] = $value
        }
    }
    return $context
}

function addLocalUser($context) {
    # Create new user
        $username =  $context["USERNAME"]
        $password =  $context["PASSWORD"]

        $ADSI = [adsi]$ConnectionString

        if(!([ADSI]::Exists("WinNT://$computerName/$username"))) {
           $user = $ADSI.Create("user",$username)
           $user.setPassword($password)
           $user.SetInfo()
        }
        # Already exists, change password
        else{
           $admin = [ADSI]"WinNT://$env:computername/$username"
           $admin.psbase.invoke("SetPassword", $password)
        }

    # Set Password to Never Expires
    $admin = [ADSI]"WinNT://$env:computername/$username"
    $admin.UserFlags.value = $admin.UserFlags.value -bor 0x10000
    $admin.CommitChanges()

    # Add user to local Administrators
    $groups = "Administrators"
    $groups = (Get-WmiObject -Class "Win32_Group" | where { $_.SID -like "S-1-5-32-544" } | select -ExpandProperty Name)

    foreach ($grp in $groups) {
    if([ADSI]::Exists("WinNT://$computerName/$grp,group")) {
                $group = [ADSI] "WinNT://$computerName/$grp,group"
                        if([ADSI]::Exists("WinNT://$computerName/$username")) {
                                $group.Add("WinNT://$computerName/$username")
                        }
                }
        }
}

function configureNetwork($context) {
    $nicId = 0;
    $nicIpKey = "ETH" + $nicId + "_IP"
    while ($context[$nicIpKey]) {
        # Retrieve the data
        $nicPrefix = "ETH" + $nicId + "_"

        $ipKey      = $nicPrefix + "IP"
        $netmaskKey = $nicPrefix + "MASK"
        $macKey     = $nicPrefix + "MAC"
        $dnsKey     = $nicPrefix + "DNS"
        $gatewayKey = $nicPrefix + "GATEWAY"
        $networkKey = $nicPrefix + "NETWORK"

        $ip      = $context[$ipKey]
        $netmask = $context[$netmaskKey]
        $mac     = $context[$macKey]
        $dns     = $context[$dnsKey]
        $gateway = $context[$gatewayKey]
        $network = $context[$networkKey]

        $mac = $mac.ToUpper()
        if (!$netmask) {
            $netmask = "255.255.255.0"
        }
        if (!$network) {
            $network = $ip -replace "\.[^.]+$", ".0"
        }
        if ($nicId -eq 0 -and !$gateway) {
            $gateway = $ip -replace "\.[^.]+$", ".1"
        }

        # Run the configuration
        $nic = Get-WMIObject Win32_NetworkAdapterConfiguration | `
                where {$_.IPEnabled -eq "TRUE" -and $_.MACAddress -eq $mac}

        $nic.ReleaseDHCPLease()
        $nic.EnableStatic($ip , $netmask)
        if ($gateway) {
            $nic.SetGateways($gateway)
            if ($dns) {
                $dnsServers = $dns -split " "
                $nic.SetDNSServerSearchOrder($dnsServers)
                $nic.SetDynamicDNSRegistration("TRUE")
                # $nic.SetWINSServer($DNSServers[0], $DNSServers[1])
            }
        }

        # Next NIC
        $nicId++;
        $nicIpKey = "ETH" + $nicId + "_IP"
    }
}

function renameComputer($context) {
    $hostname = $context["SET_HOSTNAME"]
    if ($hostname) {
        $ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem
        $ComputerInfo.rename($hostname)
    }
}

function enableRemoteDesktop()
{
    # Windows 7 only - add firewall exception for RDP
    netsh advfirewall Firewall set rule group="Remote Desktop" new enable=yes

    # Enable RDP
    $Terminal = (Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)
    return $Terminal
}

function enablePing()
{
    #Create firewall manager object
    $FWM=new-object -com hnetcfg.fwmgr

    # Get current profile
    $pro=$fwm.LocalPolicy.CurrentProfile
    $pro.IcmpSettings.AllowInboundEchoRequest=$true
}

function runScripts($context, $contextLetter)
{
    # Execute
    $initscripts = $context["INIT_SCRIPTS"]

    if ($initscripts) {
        foreach ($script in $initscripts.split(" ")) {
            $script = $contextLetter + $script
            if (Test-Path $script) {
                & $script
            }
        }
    }
}

function isContextualized()
{
    Test-Path "c:\.opennebula-context"
}

function setContextualized()
{
    echo "contextualized" | Out-File "c:\.opennebula-context"
}

# Return if VM has already been contextualized
if (isContextualized) {
    Write-Host "VM already contextualized."
    exit 0
}

# Get all drives and select only the one that has "CONTEXT" as a label
$contextDrive = Get-WMIObject Win32_Volume | ? { $_.Label -eq "CONTEXT" }

# Return if no CONTEXT drive found
if ($contextDrive -eq $null) {
    Write-Host "No Context CDROM found."
    exit 1
}

# At this point we can obtain the letter of the contextDrive
$contextLetter     = $contextDrive.Name
$contextScriptPath = $contextLetter + "context.sh"

# Execute script
if(Test-Path $contextScriptPath) {
    $context = getContext $contextScriptPath

    addLocalUser $context
    renameComputer $context
    enableRemoteDesktop
    enablePing
    configureNetwork $context
    runScripts $context $contextLetter
    setContextualized
}
