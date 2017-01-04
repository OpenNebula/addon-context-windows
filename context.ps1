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
    # ATTENTION - language/regional settings have influence on this group, "Administrators" fits for English
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

        $ip6Key      = $nicPrefix + "IP6"
        $gw6Key      = $nicPrefix + "GATEWAY6"

        $ip      = $context[$ipKey]
        $netmask = $context[$netmaskKey]
        $mac     = $context[$macKey]
        $dns     = $context[$dnsKey]
        $gateway = $context[$gatewayKey]
        $network = $context[$networkKey]

	$ip6     = $context[$ip6Key]
	$gw6     = $context[$gw6Key]

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
        $nic = $false
        while(!$nic) {
            $nic = Get-WMIObject Win32_NetworkAdapterConfiguration | `
                    where {$_.IPEnabled -eq "TRUE" -and $_.MACAddress -eq $mac}
            Start-Sleep -s 1
        }

        # release DHCP lease only if adapter is DHCP configured
        if ($nic.DHCPEnabled) {
            $nic.ReleaseDHCPLease() | Out-Null
        }

        # set static IP address and retry for few times if there was a problem
        # with acquiring write lock (2147786788) for network configuration
        # https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
        $retry = 10
        do {
            $retry--
            Start-Sleep -s 1
            $rtn = $nic.EnableStatic($ip , $netmask)
        } while ($rtn.ReturnValue -eq 2147786788 -and $retry);

        if ($gateway) {
            $nic.SetGateways($gateway)
            if ($dns) {
                $dnsServers = $dns -split " "
                $nic.SetDNSServerSearchOrder($dnsServers)
                $nic.SetDynamicDNSRegistration("TRUE")
                # $nic.SetWINSServer($DNSServers[0], $DNSServers[1])
            }
        }

        if ($ip6) {
	    # We need the connection ID (i.e. "Local Area Connection",
	    # which can be discovered from the NetworkAdapter object
	    $na = Get-WMIObject Win32_NetworkAdapter | `
		where {$_.deviceId -eq $nic.index}

            netsh interface ipv6 add address $na.NetConnectionId $ip6

            if ($gw6) {
		netsh interface ipv6 add route ::/0 $na.NetConnectionId $gw6
            }
            # TODO: maybe IPv6-based DNS servers should be added here?
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

    # Execute START_SCRIPT and START_SCRIPT_64
    $startScript   = $context["START_SCRIPT"]
    $startScript64 = $context["START_SCRIPT_BASE64"]

    if ($startScript64) {
        $startScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($startScript64))
    }

    if ($startScript) {
        $startScriptPS = "$env:SystemDrive\.opennebula-startscript.ps1"
        $startScript | Out-File $startScriptPS "UTF8"
        & $startScriptPS
    }
}

function isContextualized()
{
    return $FALSE
}

function setContextualized()
{
    echo "contextualized" | Out-File "$env:SystemDrive\.opennebula-context"
}

################################################################################
# Main
################################################################################

# Return if VM has already been contextualized
if (isContextualized) {
    Write-Host "VM already contextualized."
    exit 0
}

# Get all drives and select only the one that has "CONTEXT" as a label
$contextDrive = Get-WMIObject Win32_Volume | ? { $_.Label -eq "CONTEXT" }

if ($contextDrive) {
    # At this point we can obtain the letter of the contextDrive
    $contextLetter     = $contextDrive.Name
    $contextScriptPath = $contextLetter + "context.sh"
} else {

    # Try the VMware API
    $vmwareContext = & "$env:ProgramFiles\VMware\VMware Tools\vmtoolsd.exe" --cmd "info-get guestinfo.opennebula.context" | Out-String

    if ($vmwareContext -eq "") {
        Write-Host "No Context CDROM found."
        exit 1
    }

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmwareContext)) | Out-File "$env:SystemDrive\context.sh" "UTF8"
    $contextScriptPath = "$env:SystemDrive\context.sh"
}

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

# vim: ai ts=4 sts=4 et sw=4
