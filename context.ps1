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

# global variable pointing to the private .contextualization directory
$global:ctxDir="$env:SystemDrive\.onecontext"

# Check, if above defined context directory exists
If ( !(Test-Path "$ctxDir") ) {
  mkdir "$ctxDir"
}

# Move old logfile away - so we have a current log containing the output of the last boot
If ( Test-Path "$ctxDir\opennebula-context.log" ) {
  mv "$ctxDir\opennebula-context.log" "$ctxDir\opennebula-context-old.log"
}

# Start now logging to logfile
Start-Transcript -Append -Path "$ctxDir\opennebula-context.log" | Out-Null

## check if we are running powershell(x86) on a 64bit system, if so restart as 64bit
## initial code: http://cosmonautdreams.com/2013/09/03/Getting-Powershell-to-run-in-64-bit.html
If ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    # This is only set in a x86 Powershell running on a 64bit Windows
    Write-Output "- Detected 32bit architecture"

    Write-Output "Restarting into a 64bit powershell"

    # Stop-Transcript here new - unlock logfile
    Stop-Transcript | Out-Null

    If ($myInvocation.Line) {
        &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile $myInvocation.Line
    } Else {
        &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
    }

    exit $lastexitcode
}

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
                               # https://p0w3rsh3ll.wordpress.com/2016/06/14/any-documented-adsi-changes-in-powershell-5-0/
                               $memberNames += ([ADSI]$_).psbase.InvokeGet('Name')
                           }

                If (-Not ($memberNames -Contains $username)) {

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
    $nicIds = ($context.Keys | Where {$_ -match '^ETH\d+_IP6?$'} | ForEach-Object {$_ -replace '(^ETH|_IP$|_IP6$)',''} | Sort-Object -Unique)

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
        $mtuKey       = $nicPrefix + "MTU"
        $metricKey    = $nicPrefix + "METRIC"

        $ip        = $context[$ipKey]
        $netmask   = $context[$netmaskKey]
        $mac       = $context[$macKey]
        $dns       = (($context[$dnsKey] -split " " | Where {$_ -match '^(([0-9]*).?){4}$'}) -join ' ')
        $dns6      = (($context[$dnsKey] -split " " | Where {$_ -match '^(([0-9A-F]*):?)*$'}) -join ' ')
        $dnsSuffix = $context[$dnsSuffixKey]
        $gateway   = $context[$gatewayKey]
        $network   = $context[$networkKey]
        $mtu       = $context[$mtuKey]
        $metric    = $context[$metricKey]

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
        $retry = 30
        do {
            $retry--
            Start-Sleep -s 1
            $nic = Get-WMIObject Win32_NetworkAdapterConfiguration | `
                    where {$_.IPEnabled -eq "TRUE" -and $_.MACAddress -eq $mac}
        } while (!$nic -and $retry)

        If (!$nic) {
            Write-Output ("Configuring Network Settings: " + $mac)
            Write-Output ("  ... Failed: Interface with MAC not found")
            Continue
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
            Write-Output "- Set Static IP"
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

            # Set IPv4 MTU
            if ($mtu) {
                Write-Output "- Set MTU: ${mtu}"
                netsh interface ipv4 set interface $nic.InterfaceIndex mtu=$mtu

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Failed"
                }
            }

            if ($gateway) {

                # Set the Gateway
                if ($metric) {
                    Write-Output "- Set Gateway with metric"
                    $ret = $nic.SetGateways($gateway, $metric)
                } Else {
                    Write-Output "- Set Gateway"
                    $ret = $nic.SetGateways($gateway)
                }
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
            If ($? -And $ip6ULA) {
                netsh interface ipv6 add address $na.NetConnectionId $ip6ULA/64
            }

            If ($?) {
                Write-Output "  ... Success"
            } Else {
                Write-Output "  ... Failed"
            }

            # Set IPv6 Gateway
            if ($gw6) {
                Write-Output "- Set IPv6 Gateway"
                netsh interface ipv6 add route ::/0 $na.NetConnectionId $gw6

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Failed"
                }
            }

            # Set IPv6 MTU
            if ($mtu) {
                Write-Output "- Set IPv6 MTU: ${mtu}"
                netsh interface ipv6 set interface $nic.InterfaceIndex mtu=$mtu

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Failed"
                }
            }

            # Remove old IPv6 DNS Servers
            Write-Output "- Removing old IPv6 DNS Servers"
            netsh interface ipv6 set dnsservers $na.NetConnectionId source=static address=

            If ($dns6) {
                # Set IPv6 DNS Servers
                Write-Output "- Set IPv6 DNS Servers"
                $dns6Servers = $dns6 -split " "
                foreach ($dns6Server in $dns6Servers) {
                    netsh interface ipv6 add dnsserver $na.NetConnectionId address=$dns6Server
                }
            }

            doPing($ip6)
        }

        # Get the aliases for the NIC in the Context
        $aliasIds = ($context.Keys | Where {$_ -match "^ETH${nicId}_ALIAS\d+_IP6?$"} | ForEach-Object {$_ -replace '(^ETH\d+_ALIAS|_IP$|_IP6$)',''} | Sort-Object -Unique)

        foreach ($aliasId in $aliasIds) {
            $aliasPrefix    = "ETH${nicId}_ALIAS${aliasId}"
            $aliasIp        = $context[$aliasPrefix + '_IP']
            $aliasNetmask   = $context[$aliasPrefix + '_MASK']
            $aliasIp6       = $context[$aliasPrefix + '_IP6']
            $aliasIp6ULA    = $context[$aliasPrefix + '_IP6_ULA']
            $aliasIp6Prefix = $context[$aliasPrefix + '_IP6_PREFIX_LENGTH']
            $detach         = $context[$aliasPrefix + '_DETACH']
            $external       = $context[$aliasPrefix + '_EXTERNAL']

            if ($external -and ($external -eq "YES")) {
                continue
            }

            if (!$aliasNetmask) {
                $aliasNetmask = "255.255.255.0"
            }

            if (!$aliasIp6Prefix) {
                $aliasIp6Prefix = "64"
            }

            if ($aliasIp -and !$detach) {
                Write-Output "- Set Additional Static IP (${aliasPrefix})"
                netsh interface ipv4 add address $nic.InterfaceIndex $aliasIp $aliasNetmask

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Failed"
                }
            }

            if ($aliasIp6 -and !$detach) {
                Write-Output "- Set Additional IPv6 Address (${aliasPrefix})"
                netsh interface ipv6 add address $nic.InterfaceIndex $aliasIp6/$aliasIp6Prefix
                If ($? -And $aliasIp6ULA) {
                    netsh interface ipv6 add address $nic.InterfaceIndex $aliasIp6ULA/64
                }

                If ($?) {
                    Write-Output "  ... Success"
                } Else {
                    Write-Output "  ... Failed"
                }
            }
        }

        If ($ip) {
            doPing($ip)
        }
    }

    Write-Output ""
}

function setTimeZone($context) {
    $timezone = $context['TIMEZONE']

    If ($timezone) {
        Write-Output "Configuring time zone '${timezone}'"

        tzutil /s "${timezone}"

        If ($?) {
            Write-Output '  ... Success'
        } Else {
            Write-Output '  ... Failed'
        }
    }
}

function renameComputer($context) {

    # Initialize Variables
    $current_hostname = hostname
    $context_hostname = $context["SET_HOSTNAME"]

    # SET_HOSTNAME was not set but maybe DNS_HOSTNAME was...
    if (! $context_hostname) {
        $dns_hostname = $context["DNS_HOSTNAME"].ToLower()

        if ($dns_hostname -eq "yes") {

            # we will set our hostname based on the reverse dns lookup - the IP
            # in question is the first one with a set default gateway
            # (as is done by get_first_ip in addon-context-linux)

            Write-Output "Requested change of Hostname via reverse DNS lookup (DNS_HOSTNAME=YES)"
            $first_ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}).IPAddress | select-object -first 1
            $context_hostname = [System.Net.Dns]::GetHostbyAddress($first_ip).HostName
            Write-Output "Resolved Hostname is: $context_hostname"
        } Else {

            # no SET_HOSTNAME or DNS_HOSTNAME - skip setting hostname
            return
        }
    }

    $splitted_hostname = $context_hostname.split('.')
    $context_hostname  = $splitted_hostname[0]
    $context_domain    = $splitted_hostname[1..$splitted_hostname.length] -join '.'

    If ($context_domain) {
        Write-Output "Changing Domain to $context_domain"

        $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
        $ret = $networkConfig.SetDnsDomain($context_domain)

        If ($ret.ReturnValue) {

            # Returned Non Zero, Failed, No restart
            Write-Output ("  ... Failed: " + $ret.ReturnValue.ToString())
        } Else {

            # Returned Zero, Success
            Write-Output " ... Success"
        }
    }

    # Check for the .opennebula-renamed file
    $logged_hostname  = ""
    If (Test-Path "$ctxDir\.opennebula-renamed") {

        # Grab the JSON content
        $json = Get-Content -Path "$ctxDir\.opennebula-renamed" `
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
    } Else {

        # no renaming was ever done - we fallback to our current Hostname
        $logged_hostname  = $current_hostname
    }

    If (($current_hostname -ne $context_hostname) -and `
            ($context_hostname -eq $logged_hostname)) {

        # avoid rename->reboot loop - if we detect that rename attempt was done
        # but failed then we drop log message about it and finish...

        Write-Output "Computer Rename Attempted but failed:"
        Write-Output "- Current: $current_hostname"
        Write-Output "- Context: $context_hostname"
    } ElseIf ($context_hostname -ne $current_hostname) {

        # the current_name does not match the context_name, rename the computer

        Write-Output "Changing Hostname to $context_hostname"
        # Load the ComputerSystem Object
        $ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem

        # Rename the computer
        $ret = $ComputerInfo.rename($context_hostname)

        $contents = @{}
        $contents["ComputerName"] = $context_hostname
        ConvertTo-Json $contents | Out-File "$ctxDir\.opennebula-renamed"

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
    } Else {

        # Hostname is set and correct
        Write-Output "Computer Name already set: $context_hostname"
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

function doPing($ip, $retries=20)
{
    Write-Output "- Ping Interface IP $ip"

    $ping = $false
    $retry = 0
    do {
        $retry++
        Start-Sleep -s 1
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
    } while (!$ping -and ($retry -lt $retries))

    If ($ping) {
        Write-Output "  ... Success ($retry tries)"
    } Else {
        Write-Output "  ... Failed ($retry tries)"
    }
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
        $startScriptPS = "$ctxDir\.opennebula-startscript.ps1"
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

    "rescan" | diskpart

    #$diskIds = ((wmic diskdrive get Index | Select-String "[0-9]+") -replace '\D','')
    $diskId = 0

    #$partIds = ((wmic partition where DiskIndex=$diskId get Index | Select-String "[0-9]+") -replace '\D','' | %{[int]$_ + 1})
    $partIds = "select disk $diskId", "list partition" | diskpart | Select-String -Pattern "^\s+\w+ (\d+)\s+" -AllMatches | %{$_.matches.groups[1].Value}

    ForEach ($partId in $partIds) {
        extendPartition $diskId $partId
    }
}

function reportReady()
{
    $reportReady     = $context['REPORT_READY']
    $oneGateEndpoint = $context['ONEGATE_ENDPOINT']
    $vmId            = $context['VMID']
    $token           = $context['ONEGATE_TOKEN']

    if ($reportReady -and $reportReady.ToUpper() -eq 'YES') {
        Write-Output 'Report Ready to OneGate'

        if (!$oneGateEndpoint) {
            Write-Output ' ... Failed: ONEGATE_ENDPOINT not set'
            return
        }

        if (!$vmId) {
            Write-Output ' ... Failed: VMID not set'
            return
        }

        if (!$token) {
            Write-Output " ... Token not set. Try file"
            $tokenPath = $contextLetter + 'token.txt'
            if (Test-Path $tokenPath) {
                $token = Get-Content $tokenPath
            } else {
                Write-Output " ... Failed: Token file not found"
                return
            }
        }

        try {

            $body = 'READY = YES'
            $target= $oneGateEndpoint + '/vm'

            [System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($target)
            $webRequest.Timeout = 10000
            $webRequest.Method = 'PUT'
            $webRequest.Headers.Add('X-ONEGATE-TOKEN', $token)
            $webRequest.Headers.Add('X-ONEGATE-VMID', $vmId)
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
            $webRequest.ContentLength = $buffer.Length

            if ($oneGateEndpoint -ilike "https://*") {
                #For reporting on HTTPS OneGateEndpoint
                Write-Output "... Use HTTPS for OneGateEndpoint report: $oneGateEndpoint"
                $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
                [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
                [System.Net.ServicePointManager]::Expect100Continue = $false
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            }

            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($buffer, 0, $buffer.Length)
            $requestStream.Flush()
            $requestStream.Close()

            $response = $webRequest.getResponse()
            if ($response.StatusCode -eq 'OK') {
                Write-Output ' ... Success'
            } else {
                Write-Output ' ... Failed'
                Write-Output $response.StatusCode
            }
        }
        catch {
            $errorMessage = $_.Exception.Message

            Write-Output ' ... Failed'
            Write-Output $errorMessage
        }
    }
}

################################################################################
# Main
################################################################################

# Check the working WMI
if (-Not (Get-WMIObject -ErrorAction SilentlyContinue Win32_Volume)) {
    Write-Output "WMI not ready, exiting"
    Stop-Transcript | Out-Null
    exit 1
}

Write-Output "Detecting contextualization data"
Write-Output "- Looking for CONTEXT ISO"

# Get all drives and select only the one that has "CONTEXT" as a label
$contextDrive = Get-WMIObject Win32_Volume | ? { $_.Label -eq "CONTEXT" }

if ($contextDrive) {
    Write-Output "  ... Found"

    # At this point we can obtain the letter of the contextDrive
    $contextLetter     = $contextDrive.Name
    $contextScriptPath = $contextLetter + "context.sh"
} else {
    Write-Output "  ... Not found"
    Write-Output "- Looking for VMware tools"

    # Try the VMware API
    foreach ($pf in ${env:ProgramFiles}, ${env:ProgramFiles(x86)}, ${env:ProgramW6432}) {
        $vmtoolsd = "${pf}\VMware\VMware Tools\vmtoolsd.exe"
        if (Test-Path $vmtoolsd) {
            Write-Output "  ... Found in ${vmtoolsd}"
            break
        } else {
            Write-Output "  ... Not found in ${vmtoolsd}"
        }
    }

    $vmwareContext = ""
    if (Test-Path $vmtoolsd) {
        $vmwareContext = & $vmtoolsd --cmd "info-get guestinfo.opennebula.context" | Out-String
    }

    if ("$vmwareContext" -eq "") {
        Write-Host "No contextualization data found"
        Stop-Transcript | Out-Null
        exit 1
    }

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmwareContext)) | Out-File "$ctxDir\context.sh" "UTF8"
    $contextScriptPath = "$ctxDir\context.sh"
}

# Execute script
if(Test-Path $contextScriptPath) {
    $context = getContext $contextScriptPath

    extendPartitions
    setTimeZone $context
    addLocalUser $context
    enableRemoteDesktop
    enablePing
    configureNetwork $context
    renameComputer $context
    runScripts $context $contextLetter
    reportReady
}

Stop-Transcript | Out-Null
