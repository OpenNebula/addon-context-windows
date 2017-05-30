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

Start-Transcript -Append -Path "$env:SystemDrive\.opennebula-context.out" | Out-Null

Write-Output "Running Script: $($MyInvocation.InvocationName)"
Get-Date
Write-Output ""

Set-ExecutionPolicy unrestricted -force # not needed if already done once on the VM
[string]$computerName = "$env:computername"
[string]$ConnectionString = "WinNT://$computerName"

function getContext($file) {
    Write-Host "Loading Context File"
    $context = @{}
    switch -regex -file $file {
        "^([^=]+)='(.+?)'$" {
            $name, $value = $matches[1..2]
            $context[$name] = $value
        }
    }
    return $context
}

function envContext($context) {
    ForEach ($h in $context.GetEnumerator()) {
        $name = "Env:"+$h.Name
        Set-Item $name $h.Value
    }
}

function addLocalUser($context) {
    # Create new user
    $username =  $context["USERNAME"]
    $password =  $context["PASSWORD"]

    if ($username -Or $password) {

        if ($username -eq $null) {
            # ATTENTION - Language/Regional settings have influence on the naming
            #             of this user. Use the User SID instead (S-1-5-21domain-500)
            $username = (Get-WmiObject -Class "Win32_UserAccount" |
                         where { $_.SID -like "S-1-5-21[0-9-]*-500" } |
                         select -ExpandProperty Name)
        }

        Write-Output "Creating Account for $username"

        $ADSI = [adsi]$ConnectionString

        if(!([ADSI]::Exists("WinNT://$computerName/$username"))) {
            # User does not exist, Create the User
            Write-Output "- Creating account"
            $user = $ADSI.Create("user",$username)
            $user.setPassword($password)
            $user.SetInfo()
        } else {
            # User exists, Set Password
            Write-Output "- Setting Password"
            $admin = [ADSI]"WinNT://$env:computername/$username"
            $admin.psbase.invoke("SetPassword", $password)
        }

        # Set Password to Never Expire
        Write-Output "- Setting password to never expire"
        $admin = [ADSI]"WinNT://$env:computername/$username"
        $admin.UserFlags.value = $admin.UserFlags.value -bor 0x10000
        $admin.CommitChanges()

        # Add user to local Administrators
        # ATTENTION - Language/Regional settings have influence on the naming
        #             of this group. Use the Group SID instead (S-1-5-32-544)
        $groups = (Get-WmiObject -Class "Win32_Group" |
                   where { $_.SID -like "S-1-5-32-544" } |
                   select -ExpandProperty Name)

        ForEach ($grp in $groups) {

            # Make sure the Group exists
            If([ADSI]::Exists("WinNT://$computerName/$grp,group")) {

                # Check if the user is a Member of the Group
                $group = [ADSI] "WinNT://$computerName/$grp,group"
                $members = @($group.psbase.Invoke("Members"))

                $memberNames = @()
                $members | ForEach-Object {
                               $memberNames += $_.GetType().InvokeMember(
                                   "Name", 'GetProperty', $null, $_, $null);
                           }

                If (-Not $memberNames.Contains($username)) {

                    # Make sure the user exists, again
                    if([ADSI]::Exists("WinNT://$computerName/$username")) {

                        # Add the user
                        Write-Output "- Adding to $grp"
                        $group.Add("WinNT://$computerName/$username")
                    }
                }
            }
        }
    }
    Write-Output ""
}

function configureNetwork($context) {

    # Get the NIC in the Context
    $nicIds = ($context.Keys | Where {$_ -match '^ETH\d+_IP6?$'} | ForEach-Object {$_ -replace '(^ETH|_IP$|_IP6$)',''} | Get-Unique)

    $nicId = 0;

    foreach ($nicId in $nicIds) {
        # Retrieve data from Context
        $nicIpKey = "ETH" + $nicId + "_IP"
        $nicIp6Key = "ETH" + $nicId + "_IP6"
        $nicPrefix = "ETH" + $nicId + "_"

        $ipKey        = $nicPrefix + "IP"
        $netmaskKey   = $nicPrefix + "MASK"
        $macKey       = $nicPrefix + "MAC"
        $dnsKey       = $nicPrefix + "DNS"
        $dnsSuffixKey = $nicPrefix + "SEARCH_DOMAIN"
        $gatewayKey   = $nicPrefix + "GATEWAY"
        $networkKey   = $nicPrefix + "NETWORK"

        $ip6Key       = $nicPrefix + "IP6"
        $ip6ULAKey    = $nicPrefix + "IP6_ULA"
        $ip6PrefixKey = $nicPrefix + "IP6_PREFIX_LENGTH"
        $gw6Key       = $nicPrefix + "GATEWAY6"

        $ip        = $context[$ipKey]
        $netmask   = $context[$netmaskKey]
        $mac       = $context[$macKey]
        $dns       = (($context[$dnsKey] -split " " | Where {$_ -match '^(([0-9]*).?){4}$'}) -join ' ')
        $dns6      = (($context[$dnsKey] -split " " | Where {$_ -match '^(([0-9A-F]*):?)*$'}) -join ' ')
        $dnsSuffix = $context[$dnsSuffixKey]
        $gateway   = $context[$gatewayKey]
        $network   = $context[$networkKey]

        $ip6       = $context[$ip6Key]
        $ip6ULA    = $context[$ip6ULAKey]
        $ip6Prefix = $context[$ip6PrefixKey]
        $gw6       = $context[$gw6Key]

        $mac = $mac.ToUpper()
        if (!$netmask) {
            $netmask = "255.255.255.0"
        }
        if (!$ip6Prefix) {
            $ip6Prefix = "64"
        }
        if (!$network) {
            $network = $ip -replace "\.[^.]+$", ".0"
        }
        if ($nicId -eq 0 -and !$gateway) {
            $gateway = $ip -replace "\.[^.]+$", ".1"
        }

        # Load the NIC Configuration Object
        $nic = $false
        while(!$nic) {
            $nic = Get-WMIObject Win32_NetworkAdapterConfiguration | `
                    where {$_.IPEnabled -eq "TRUE" -and $_.MACAddress -eq $mac}
            Start-Sleep -s 1
        }

        Write-Output ("Configuring Network Settings: " + $nic.Description.ToString())

        # Release the DHCP lease, will fail if adapter not DHCP Configured
        Write-Output "- Release DHCP Lease"
        $ret = $nic.ReleaseDHCPLease()
        If ($ret.ReturnValue) {
            Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
        } Else {
            Write-Output "  ... Success"
        }

        if ($ip) {
            # set static IP address and retry for few times if there was a problem
            # with acquiring write lock (2147786788) for network configuration
            # https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
            Write-Output "- Enable Static IP"
            $retry = 10
            do {
                $retry--
                Start-Sleep -s 1
                $ret = $nic.EnableStatic($ip , $netmask)
            } while ($ret.ReturnValue -eq 2147786788 -and $retry);
            If ($ret.ReturnValue) {
                Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
            } Else {
                Write-Output "  ... Success"
            }


            if ($gateway) {

                # Set the Gateway
                Write-Output "- Set Gateway"
                $ret = $nic.SetGateways($gateway)
                If ($ret.ReturnValue) {
                    Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
                } Else {
                    Write-Output "  ... Success"
                }

                If ($dns) {

                    # DNS Servers
                    $dnsServers = $dns -split " "

                    # DNS Server Search Order
                    Write-Output "- Set DNS Server Search Order"
                    $ret = $nic.SetDNSServerSearchOrder($dnsServers)
                    If ($ret.ReturnValue) {
                        Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        Write-Output "  ... Success"
                    }

                    # Set Dynamic DNS Registration
                    Write-Output "- Set Dynamic DNS Registration"
                    $ret = $nic.SetDynamicDNSRegistration("TRUE")
                    If ($ret.ReturnValue) {
                        Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        Write-Output "  ... Success"
                    }

                    # WINS Addresses
                    # $nic.SetWINSServer($DNSServers[0], $DNSServers[1])
                }

                if ($dnsSuffix) {

                    # DNS Suffixes
                    $dnsSuffixes = $dnsSuffix -split " "

                    # Set DNS Suffix Search Order
                    Write-Output "- Set DNS Suffix Search Order"
                    $ret = ([WMIClass]"Win32_NetworkAdapterConfiguration").SetDNSSuffixSearchOrder(($dnsSuffixes))
                    If ($ret.ReturnValue) {
                        Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        Write-Output "  ... Success"
                    }

                    # Set Primary DNS Domain
                    Write-Output "- Set Primary DNS Domain"
                    $ret = $nic.SetDNSDomain($dnsSuffixes[0])
                    If ($ret.ReturnValue) {
                        Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        Write-Output "  ... Success"
                    }
                }
            }
        }

        if ($ip6) {
            # We need the connection ID (i.e. "Local Area Connection",
            # which can be discovered from the NetworkAdapter object
            $na = Get-WMIObject Win32_NetworkAdapter | `
                    where {$_.deviceId -eq $nic.index}


            # Disable router discovery
            Write-Output "- Disable IPv6 router discovery"
            netsh interface ipv6 set interface $na.NetConnectionId `
                advertise=disabled routerdiscover=disabled | Out-Null

            If ($?) {
                Write-Output "  ... Success"
            } Else {
                Write-Output "  ... Failed"
            }

            # Remove old IPv6 addresses
            Write-Output "- Removing old IPv6 addresses"
            if (Get-Command Remove-NetIPAddress -errorAction SilentlyContinue) {
                # Windows 8.1 and Server 2012 R2 and up
                # we want to remove everything except the link-local address
                Remove-NetIPAddress -InterfaceAlias $na.NetConnectionId `
                    -AddressFamily IPv6 -Confirm:$false `
                    -PrefixOrigin Other,Manual,Dhcp,RouterAdvertisement `
                    -errorAction SilentlyContinue

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Nothing to do"
                }
            } Else {
                Write-Output "  ... Not implemented"
            }

            # Set IPv6 Address
            Write-Output "- Set IPv6 Address"
            netsh interface ipv6 add address $na.NetConnectionId $ip6/$ip6Prefix
            if ($ip6ULA) {
                netsh interface ipv6 add address $na.NetConnectionId $ip6ULA/64
            }

            # Set IPv6 Gateway
            if ($gw6) {
                netsh interface ipv6 add route ::/0 $na.NetConnectionId $gw6
            }

            If ($dns6) {
                # IPv6 DNS Servers
                $dns6Servers = $dns6 -split " "

                # Remove old IPv6 DNS Servers
                Write-Output "- Removing old IPv6 DNS Servers"
                netsh interface ipv6 set dnsservers $na.NetConnectionId source=dhcp

                # Set IPv6 DNS Servers
                Write-Output "- Set IPv6 DNS Servers"
                foreach ($dns6Server in $dns6Servers) {
                    netsh interface ipv6 add dnsserver $na.NetConnectionId address=$dns6Server
                }
            }
        }
    }
    Write-Output ""
}

function renameComputer($context) {

    # Initialize Variables
    $current_hostname = hostname
    $context_hostname = $context["SET_HOSTNAME"]
    $logged_hostname = "Unknown"

    if (! $context_hostname) {
        return
    }

    # Check for the .opennebula-renamed file
    If (Test-Path "$env:SystemDrive\.opennebula-renamed") {

        # Grab the JSON content
        $json = Get-Content -Path "$env:SystemDrive\.opennebula-renamed" `
                | Out-String

        # Convert to a Hash Table and set the Logged Hostname
        try {
            $status = $json | ConvertFrom-Json
            $logged_hostname = $status.ComputerName
        }
        # Invalid JSON
        catch [System.ArgumentException] {
            Write-Output "Invalid JSON:"
            Write-Output $json.ToString()
        }
    }

    If ((!(Test-Path "$env:SystemDrive\.opennebula-renamed")) -or `
        ($context_hostname.ToLower() -ne $logged_hostname.ToLower())) {

        # .opennebula-renamed not found or the logged_name does not match the
        # context_name, rename the computer

        Write-Output "Changing Hostname to $context_hostname"
        # Load the ComputerSystem Object
        $ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem

        # Rename the computer
        $ret = $ComputerInfo.rename($context_hostname)

        $contents = @{}
        $contents["ComputerName"] = $context_hostname
        ConvertTo-Json $contents | Out-File "$env:SystemDrive\.opennebula-renamed"

        # Check success
        If ($ret.ReturnValue) {

            # Returned Non Zero, Failed, No restart
            Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
            Write-Output "      Check the computername."
            Write-Output "Possible Issues: The name cannot include control" `
                         "characters, leading or trailing spaces, or any of" `
                         "the following characters: `" / \ [ ] : | < > + = ; , ?"

        } Else {

            # Returned Zero, Success
            Write-Output "... Success"

            # Restart the Computer
            Write-Output "... Rebooting"
            Restart-Computer -Force

            # Exit here so the script doesn't continue to run
            Exit 0
        }
    } else {
        If ($current_hostname -eq $context_hostname) {
            Write-Output "Computer Name already set: $context_hostname"
        }
        ElseIf (($current_hostname -ne $context_hostname) -and `
                ($context_hostname -eq $logged_hostname)) {
            Write-Output "Computer Rename Attempted but failed:"
            Write-Output "- Current: $current_hostname"
            Write-Output "- Context: $context_hostname"
        }
    }
    Write-Output ""
}

function enableRemoteDesktop()
{
    Write-Output "Enabling Remote Desktop"
    # Windows 7 only - add firewall exception for RDP
    Write-Output "- Enable Remote Desktop Rule Group"
    netsh advfirewall Firewall set rule group="Remote Desktop" new enable=yes

    # Enable RDP
    Write-Output "- Enable Allow Terminal Services Connections"
    $ret = (Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)
    If ($ret.ReturnValue) {
        Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
    } Else {
        Write-Output "  ... Success"
    }
    Write-Output ""
}

function enablePing()
{
    Write-Output "Enabling Ping"
    #Create firewall manager object
    $fwm=new-object -com hnetcfg.fwmgr

    # Get current profile
    $pro=$fwm.LocalPolicy.CurrentProfile

    Write-Output "- Enable Allow Inbound Echo Requests"
    $ret = $pro.IcmpSettings.AllowInboundEchoRequest=$true
    If ($ret) {
        Write-Output "  ... Success"
    } Else {
        Write-Output "  ... Failed"
    }

    Write-Output ""
}

function runScripts($context, $contextLetter)
{
    Write-Output "Running Scripts"

    # Get list of scripts to run, " " delimited
    $initscripts = $context["INIT_SCRIPTS"]

    if ($initscripts) {

        # Parse each script and run it
        ForEach ($script in $initscripts.split(" ")) {

            $script = $contextLetter + $script
            If (Test-Path $script) {
                Write-Output "- $script"
                envContext($context)
                & $script
            }

        }
    }

    # Execute START_SCRIPT or START_SCRIPT_64
    $startScript   = $context["START_SCRIPT"]
    $startScript64 = $context["START_SCRIPT_BASE64"]

    If ($startScript64) {
        $startScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($startScript64))
    }

    If ($startScript) {

        # Save the script as .opennebula-startscript.ps1
        $startScriptPS = "$env:SystemDrive\.opennebula-startscript.ps1"
        $startScript | Out-File $startScriptPS "UTF8"

        # Launch the Script
        Write-Output "- $startScriptPS"
        envContext($context)
        & $startScriptPS

    }
    Write-Output ""
}

function extendPartition($disk, $part)
{
  "select disk $disk","select partition $part","extend" | diskpart | Out-Null
}

function extendPartitions()
{
    Write-Output "- Extend partitions"

    #$diskIds = ((wmic diskdrive get Index | Select-String "[0-9]+") -replace '\D','')
    $diskId = 0

    $partIds = ((wmic partition where DiskIndex=$diskId get Index | Select-String "[0-9]+") -replace '\D','' | %{[int]$_ + 1})

    ForEach ($partId in $partIds) {
        extendPartition $diskId $partId
    }
}

################################################################################
# Main
################################################################################

# Get all drives and select only the one that has "CONTEXT" as a label
$contextDrive = Get-WMIObject Win32_Volume | ? { $_.Label -eq "CONTEXT" }

if ($contextDrive) {
    # At this point we can obtain the letter of the contextDrive
    $contextLetter     = $contextDrive.Name
    $contextScriptPath = $contextLetter + "context.sh"
} else {

    # Try the VMware API
    $vmtoolsd = "${env:ProgramFiles}\VMware\VMware Tools\vmtoolsd.exe"
    if (-Not (Test-Path $vmtoolsd)) {
        $vmtoolsd = "${env:ProgramFiles(x86)}\VMware\VMware Tools\vmtoolsd.exe"
    }

    $vmwareContext = ""
    if (Test-Path $vmtoolsd) {
        $vmwareContext = & $vmtoolsd --cmd "info-get guestinfo.opennebula.context" | Out-String
    }

    if ("$vmwareContext" -eq "") {
        Write-Host "No Context CDROM found."
        exit 1
    }

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmwareContext)) | Out-File "$env:SystemDrive\context.sh" "UTF8"
    $contextScriptPath = "$env:SystemDrive\context.sh"
}

# Execute script
if(Test-Path $contextScriptPath) {
    $context = getContext $contextScriptPath
    extendPartitions
    renameComputer $context
    addLocalUser $context
    enableRemoteDesktop
    enablePing
    configureNetwork $context
    runScripts $context $contextLetter
}

Stop-Transcript | Out-Null

