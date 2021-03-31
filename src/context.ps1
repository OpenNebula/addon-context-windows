# -------------------------------------------------------------------------- #
# Copyright 2002-2021, OpenNebula Project, OpenNebula Systems                #
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

################################################################################
# Functions
################################################################################

function logmsg($message)
{
    # powershell 4 does not automatically add newline in the transcript so we
    # workaround it by adding it explicitly and using the NoNewline argument
    # we ensure that it will not be added twice
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm K')] $message`r`n" -NoNewline
}

function getContext($file)
{
    logmsg "* Loading Context File"
    $context = @{}
    switch -regex -file $file {
        "^([^=]+)='(.+?)'$" {
            $name, $value = $matches[1..2]
            $context[$name] = $value
        }
    }
    return $context
}

function envContext($context)
{
    ForEach ($h in $context.GetEnumerator()) {
        $name = "Env:"+$h.Name
        Set-Item $name $h.Value
    }
}

function contextChanged($file, $last_checksum)
{
    $new_checksum = Get-FileHash -Algorithm SHA256 $file
    $ret = $last_checksum.Hash -ne $new_checksum.Hash
    return $ret
}

function waitForContext($checksum)
{
    # This object will be set and returned at the end
    $contextPaths = New-Object PsObject -Property @{
        contextScriptPath=$null ;
        contextPath=$null ;
        contextDrive=$null ;
        contextLetter=$null ;
        contextInitScriptPath=$null
        }

    # How long to wait before another poll (in seconds)
    $sleep = 30

    logmsg "* Starting a wait-loop with the interval of $sleep seconds..."

    Write-Host "`r`n" -NoNewline
    Write-Host "***********************`r`n" -NoNewline
    Write-Host "*** WAIT-LOOP START ***`r`n" -NoNewline
    Write-Host "***********************`r`n" -NoNewline
    Write-Host "`r`n" -NoNewline

    do {
        logmsg "* Detecting contextualization data"
        logmsg "- Looking for CONTEXT ISO"

        # Reset the contextPath
        $contextPaths.contextPath = ""

        # Get all drives and select only the one that has "CONTEXT" as a label
        $contextPaths.contextDrive = Get-WMIObject Win32_Volume | ? { $_.Label -eq "CONTEXT" }

        if ($contextPaths.contextDrive) {
            logmsg "  ... Found"

            # At this point we can obtain the letter of the contextDrive
            $contextPaths.contextLetter = $contextPaths.contextDrive.Name
            $contextPaths.contextPath = $contextPaths.contextLetter + "context.sh"
            $contextPaths.contextInitScriptPath = $contextPaths.contextLetter
        } else {
            logmsg "  ... Not found"
            logmsg "- Looking for VMware tools"

            # Try the VMware API
            foreach ($pf in ${env:ProgramFiles}, ${env:ProgramFiles(x86)}, ${env:ProgramW6432}) {
                $vmtoolsd = "${pf}\VMware\VMware Tools\vmtoolsd.exe"
                if (Test-Path $vmtoolsd) {
                    logmsg "  ... Found in ${vmtoolsd}"
                    break
                } else {
                    logmsg "  ... Not found in ${vmtoolsd}"
                }
            }

            $vmwareContext = ""
            if (Test-Path $vmtoolsd) {
                $vmwareContext = & $vmtoolsd --cmd "info-get guestinfo.opennebula.context" | Out-String
            }

            if ("$vmwareContext" -ne "") {
                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmwareContext)) | Out-File "$ctxDir\context.sh" "UTF8"
                $contextPaths.contextLetter = $env:SystemDrive + "\"
                $contextPaths.contextPath = "$ctxDir\context.sh"
                $contextPaths.contextInitScriptPath = "$ctxDir\.init-scripts\"

                if (!(Test-Path $contextPaths.contextInitScriptPath)) {
                    mkdir $contextPaths.contextInitScriptPath
                }

                # Look for INIT_SCRIPTS
                $fileId = 0
                while ($true) {
                    $vmwareInitFilename = & $vmtoolsd --cmd "info-get guestinfo.opennebula.file.${fileId}" | Select-Object -First 1 | Out-String

                    $vmwareInitFilename = $vmwareInitFilename.Trim()

                    if ($vmwareInitFilename -eq "") {
                        # no file found
                        break
                    }

                    $vmwareInitFileContent64 = & $vmtoolsd --cmd "info-get guestinfo.opennebula.file.${fileId}" | Select-Object -Skip 1 | Out-String

                    # Sanitize the filenames (drop any path from them and instead use our directory)
                    $vmwareInitFilename = $contextPaths.contextInitScriptPath + [System.IO.Path]::GetFileName("$vmwareInitFilename")

                    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmwareInitFileContent64)) | Out-File "${vmwareInitFilename}" "UTF8"

                    $fileId++
                }
            }

        }

        # Terminate the wait-loop only when context.sh is found and changed
        if ([string]$contextPaths.contextPath -ne "" -and (Test-Path $contextPaths.contextPath)) {
            logmsg "- Found contextualization data: $($contextPaths.contextPath)"

            # Context must differ
            if (contextChanged $contextPaths.contextPath $checksum) {
                Break
            } else {
                logmsg "- Contextualization data were not changed"
            }
        } else {
            logmsg "- No contextualization data found"
        }

        logmsg "  ... Cleanup for the next iteration ..."
        cleanup $contextPaths

        logmsg "  ... Sleep for $($sleep)s ..."
        Write-Host "`r`n" -NoNewline
        Start-Sleep -Seconds $sleep
    } while ($true)

    Write-Host "`r`n" -NoNewline
    Write-Host "***********************`r`n" -NoNewline
    Write-Host "***  WAIT-LOOP END  ***`r`n" -NoNewline
    Write-Host "***********************`r`n" -NoNewline
    Write-Host "`r`n" -NoNewline

    # make a copy of the context.sh in the case another event would happen and
    # trigger a new context.sh while still working on the previous one which
    # would result in a mismatched checksum...
    $contextPaths.contextScriptPath = "$ctxDir\.opennebula-context.sh"
    Copy-Item -Path $contextPaths.contextPath -Destination $contextPaths.contextScriptPath -Force

    return $contextPaths
}

function addLocalUser($context)
{
    # Create new user
    $username =  $context["USERNAME"]
    $password =  $context["PASSWORD"]
    $password64 = $context["PASSWORD_BASE64"]

    If ($password64) {
        $password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password64))
    }

    if ($username -Or $password) {

        if ($username -eq $null) {
            # ATTENTION - Language/Regional settings have influence on the naming
            #             of this user. Use the User SID instead (S-1-5-21domain-500)
            $username = (Get-WmiObject -Class "Win32_UserAccount" |
                         where { $_.SID -like "S-1-5-21[0-9-]*-500" } |
                         select -ExpandProperty Name |
                         get-Unique -AsString)
        }

        logmsg "* Creating Account for $username"

        $ADSI = [adsi]$ConnectionString

        if(!([ADSI]::Exists("WinNT://$computerName/$username"))) {
            # User does not exist, Create the User
            logmsg "- Creating account"
            $user = $ADSI.Create("user",$username)
            $user.setPassword($password)
            $user.SetInfo()
        } else {
            # User exists, Set Password
            logmsg "- Setting Password"
            $admin = [ADSI]"WinNT://$env:computername/$username"
            $admin.psbase.invoke("SetPassword", $password)
        }

        # Set Password to Never Expire
        logmsg "- Setting password to never expire"
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
                        logmsg "- Adding to $grp"
                        $group.Add("WinNT://$computerName/$username")
                    }
                }
            }
        }
    }
    Write-Host "`r`n" -NoNewline
}

function configureNetwork($context)
{

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
            logmsg ("* Configuring Network Settings: " + $mac)
            logmsg ("  ... Failed: Interface with MAC not found")
            Continue
        }

        logmsg ("* Configuring Network Settings: " + $nic.Description.ToString())

        # Release the DHCP lease, will fail if adapter not DHCP Configured
        logmsg "- Release DHCP Lease"
        $ret = $nic.ReleaseDHCPLease()
        If ($ret.ReturnValue) {
            logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
        } Else {
            logmsg "  ... Success"
        }

        if ($ip) {
            # set static IP address and retry for few times if there was a problem
            # with acquiring write lock (2147786788) for network configuration
            # https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
            logmsg "- Set Static IP"
            $retry = 10
            do {
                $retry--
                Start-Sleep -s 1
                $ret = $nic.EnableStatic($ip , $netmask)
            } while ($ret.ReturnValue -eq 2147786788 -and $retry);
            If ($ret.ReturnValue) {
                logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
            } Else {
                logmsg "  ... Success"
            }

            # Set IPv4 MTU
            if ($mtu) {
                logmsg "- Set MTU: ${mtu}"
                netsh interface ipv4 set interface $nic.InterfaceIndex mtu=$mtu

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Failed"
                }
            }

            if ($gateway) {

                # Set the Gateway
                if ($metric) {
                    logmsg "- Set Gateway with metric"
                    $ret = $nic.SetGateways($gateway, $metric)
                } Else {
                    logmsg "- Set Gateway"
                    $ret = $nic.SetGateways($gateway)
                }
                If ($ret.ReturnValue) {
                    logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
                } Else {
                    logmsg "  ... Success"
                }

                If ($dns) {

                    # DNS Servers
                    $dnsServers = $dns -split " "

                    # DNS Server Search Order
                    logmsg "- Set DNS Server Search Order"
                    $ret = $nic.SetDNSServerSearchOrder($dnsServers)
                    If ($ret.ReturnValue) {
                        logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        logmsg "  ... Success"
                    }

                    # Set Dynamic DNS Registration
                    logmsg "- Set Dynamic DNS Registration"
                    $ret = $nic.SetDynamicDNSRegistration("TRUE")
                    If ($ret.ReturnValue) {
                        logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        logmsg "  ... Success"
                    }

                    # WINS Addresses
                    # $nic.SetWINSServer($DNSServers[0], $DNSServers[1])
                }

                if ($dnsSuffix) {

                    # DNS Suffixes
                    $dnsSuffixes = $dnsSuffix -split " "

                    # Set DNS Suffix Search Order
                    logmsg "- Set DNS Suffix Search Order"
                    $ret = ([WMIClass]"Win32_NetworkAdapterConfiguration").SetDNSSuffixSearchOrder(($dnsSuffixes))
                    If ($ret.ReturnValue) {
                        logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        logmsg "  ... Success"
                    }

                    # Set Primary DNS Domain
                    logmsg "- Set Primary DNS Domain"
                    $ret = $nic.SetDNSDomain($dnsSuffixes[0])
                    If ($ret.ReturnValue) {
                        logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
                    } Else {
                        logmsg "  ... Success"
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
            logmsg "- Disable IPv6 router discovery"
            netsh interface ipv6 set interface $na.NetConnectionId `
                advertise=disabled routerdiscover=disabled | Out-Null

            If ($?) {
                logmsg "  ... Success"
            } Else {
                logmsg "  ... Failed"
            }

            # Remove old IPv6 addresses
            logmsg "- Removing old IPv6 addresses"
            if (Get-Command Remove-NetIPAddress -errorAction SilentlyContinue) {
                # Windows 8.1 and Server 2012 R2 and up
                # we want to remove everything except the link-local address
                Remove-NetIPAddress -InterfaceAlias $na.NetConnectionId `
                    -AddressFamily IPv6 -Confirm:$false `
                    -PrefixOrigin Other,Manual,Dhcp,RouterAdvertisement `
                    -errorAction SilentlyContinue

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Nothing to do"
                }
            } Else {
                logmsg "  ... Not implemented"
            }

            # Set IPv6 Address
            logmsg "- Set IPv6 Address"
            netsh interface ipv6 add address $na.NetConnectionId $ip6/$ip6Prefix
            If ($? -And $ip6ULA) {
                netsh interface ipv6 add address $na.NetConnectionId $ip6ULA/64
            }

            If ($?) {
                logmsg "  ... Success"
            } Else {
                logmsg "  ... Failed"
            }

            # Set IPv6 Gateway
            if ($gw6) {
                logmsg "- Set IPv6 Gateway"
                netsh interface ipv6 add route ::/0 $na.NetConnectionId $gw6

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Failed"
                }
            }

            # Set IPv6 MTU
            if ($mtu) {
                logmsg "- Set IPv6 MTU: ${mtu}"
                netsh interface ipv6 set interface $nic.InterfaceIndex mtu=$mtu

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Failed"
                }
            }

            # Remove old IPv6 DNS Servers
            logmsg "- Removing old IPv6 DNS Servers"
            netsh interface ipv6 set dnsservers $na.NetConnectionId source=static address=

            If ($dns6) {
                # Set IPv6 DNS Servers
                logmsg "- Set IPv6 DNS Servers"
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
                logmsg "- Set Additional Static IP (${aliasPrefix})"
                netsh interface ipv4 add address $nic.InterfaceIndex $aliasIp $aliasNetmask

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Failed"
                }
            }

            if ($aliasIp6 -and !$detach) {
                logmsg "- Set Additional IPv6 Address (${aliasPrefix})"
                netsh interface ipv6 add address $nic.InterfaceIndex $aliasIp6/$aliasIp6Prefix
                If ($? -And $aliasIp6ULA) {
                    netsh interface ipv6 add address $nic.InterfaceIndex $aliasIp6ULA/64
                }

                If ($?) {
                    logmsg "  ... Success"
                } Else {
                    logmsg "  ... Failed"
                }
            }
        }

        If ($ip) {
            doPing($ip)
        }
    }

    Write-Host "`r`n" -NoNewline
}

function setTimeZone($context)
{
    $timezone = $context['TIMEZONE']

    If ($timezone) {
        logmsg "* Configuring time zone '${timezone}'"

        tzutil /s "${timezone}"

        If ($?) {
            logmsg '  ... Success'
        } Else {
            logmsg '  ... Failed'
        }
    }
}

function renameComputer($context)
{
    # Initialize Variables
    $current_hostname = hostname
    $context_hostname = $context["SET_HOSTNAME"]

    # SET_HOSTNAME was not set but maybe DNS_HOSTNAME was...
    if (! $context_hostname) {
        $dns_hostname = $context["DNS_HOSTNAME"]

        if ($dns_hostname -ne $null -and $dns_hostname.ToUpper() -eq "YES") {

            # we will set our hostname based on the reverse dns lookup - the IP
            # in question is the first one with a set default gateway
            # (as is done by get_first_ip in addon-context-linux)

            logmsg "* Requested change of Hostname via reverse DNS lookup (DNS_HOSTNAME=YES)"
            $first_ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}).IPAddress | select-object -first 1
            $context_hostname = [System.Net.Dns]::GetHostbyAddress($first_ip).HostName
            logmsg "- Resolved Hostname is: $context_hostname"
        } Else {

            # no SET_HOSTNAME nor DNS_HOSTNAME - skip setting hostname
            return
        }
    }

    $splitted_hostname = $context_hostname.split('.')
    $context_hostname  = $splitted_hostname[0]
    $context_domain    = $splitted_hostname[1..$splitted_hostname.length] -join '.'

    If ($context_domain) {
        logmsg "* Changing Domain to $context_domain"

        $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
        $ret = $networkConfig.SetDnsDomain($context_domain)

        If ($ret.ReturnValue) {

            # Returned Non Zero, Failed, No restart
            logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
        } Else {

            # Returned Zero, Success
            logmsg "  ... Success"
        }
    }

    # Check for the .opennebula-renamed file
    $logged_hostname  = ""
    If (Test-Path "$ctxDir\.opennebula-renamed") {
        logmsg "- Using the JSON file: $ctxDir\.opennebula-renamed"

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
            logmsg " [!] Invalid JSON:"
            Write-Host $json.ToString()
        }
    } Else {

        # no renaming was ever done - we fallback to our current Hostname
        $logged_hostname  = $current_hostname
    }

    If (($current_hostname -ne $context_hostname) -and `
            ($context_hostname -eq $logged_hostname)) {

        # avoid rename->reboot loop - if we detect that rename attempt was done
        # but failed then we drop log message about it and finish...

        logmsg "* Computer Rename Attempted but failed:"
        logmsg "- Current: $current_hostname"
        logmsg "- Context: $context_hostname"
    } ElseIf ($context_hostname -ne $current_hostname) {

        # the current_name does not match the context_name, rename the computer

        logmsg "* Changing Hostname to $context_hostname"
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
            logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
            Write-Host "      Check the computername. "
            Write-Host "Possible Issues: The name cannot include control " `
                       "characters, leading or trailing spaces, or any of " `
                       "the following characters: `" / \ [ ] : | < > + = ; , ?"

        } Else {

            # Returned Zero, Success
            logmsg "  ... Success"

            # Restart the Computer
            logmsg "  ... Rebooting"
            Restart-Computer -Force

            # Exit here so the script doesn't continue to run
            Exit 0
        }
    } Else {

        # Hostname is set and correct
        logmsg "* Computer Name already set: $context_hostname"
    }

    Write-Host "`r`n" -NoNewline
}

function enableRemoteDesktop()
{
    logmsg "* Enabling Remote Desktop"
    # Windows 7 only - add firewall exception for RDP
    logmsg "- Enable Remote Desktop Rule Group"
    netsh advfirewall Firewall set rule group="Remote Desktop" new enable=yes

    # Enable RDP
    logmsg "- Enable Allow Terminal Services Connections"
    $ret = (Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)
    If ($ret.ReturnValue) {
        logmsg ("  ... Failed: " + $ret.ReturnValue.ToString())
    } Else {
        logmsg "  ... Success"
    }
    Write-Host "`r`n" -NoNewline
}

function enablePing()
{
    logmsg "* Enabling Ping"
    #Create firewall manager object
    $fwm=new-object -com hnetcfg.fwmgr

    # Get current profile
    $pro=$fwm.LocalPolicy.CurrentProfile

    logmsg "- Enable Allow Inbound Echo Requests"
    $ret = $pro.IcmpSettings.AllowInboundEchoRequest=$true
    If ($ret) {
        logmsg "  ... Success"
    } Else {
        logmsg "  ... Failed"
    }

    Write-Host "`r`n" -NoNewline
}

function doPing($ip, $retries=20)
{
    logmsg "- Ping Interface IP $ip"

    $ping = $false
    $retry = 0
    do {
        $retry++
        Start-Sleep -s 1
        $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
    } while (!$ping -and ($retry -lt $retries))

    If ($ping) {
        logmsg "  ... Success ($retry tries)"
    } Else {
        logmsg "  ... Failed ($retry tries)"
    }
}

function runScripts($context, $contextPaths)
{
    logmsg "* Running Scripts"

    # Get list of scripts to run, " " delimited
    $initscripts = $context["INIT_SCRIPTS"]

    if ($initscripts) {
        # Parse each script and run it
        ForEach ($script in $initscripts.split(" ")) {

            # Sanitize the filename (drop any path from them and instead use our directory)
            $script = $contextPaths.contextInitScriptPath + [System.IO.Path]::GetFileName($script.Trim())

            if (Test-Path $script) {
                logmsg "- $script"
                envContext($context)
                pswrapper "$script"
            }

        }
    } else {
        # Emulate the init.sh fallback behavior from Linux
        $script = $contextPaths.contextInitScriptPath + "init.ps1"

        if (Test-Path $script) {
            logmsg "- $script"
            envContext($context)
            pswrapper "$script"
        }
    }

    # Execute START_SCRIPT or START_SCRIPT_64
    $startScript   = $context["START_SCRIPT"]
    $startScript64 = $context["START_SCRIPT_BASE64"]

    if ($startScript64) {
        $startScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($startScript64))
    }

    if ($startScript) {

        # Save the script as .opennebula-startscript.ps1
        $startScriptPS = "$ctxDir\.opennebula-startscript.ps1"
        $startScript | Out-File $startScriptPS "UTF8"

        # Launch the Script
        logmsg "- $startScriptPS"
        envContext($context)
        pswrapper "$startScriptPS"
        removeFile "$startScriptPS"
    }
    Write-Host "`r`n" -NoNewline
}

function extendPartition($disk, $part)
{
  "select disk $disk","select partition $part","extend" | diskpart | Out-Null
}

function extendPartitions()
{
    logmsg "* Extend partitions"

    "rescan" | diskpart

    #$diskIds = ((wmic diskdrive get Index | Select-String "[0-9]+") -replace '\D','')
    $diskId = 0

    #$partIds = ((wmic partition where DiskIndex=$diskId get Index | Select-String "[0-9]+") -replace '\D','' | %{[int]$_ + 1})
    $partIds = "select disk $diskId", "list partition" | diskpart | Select-String -Pattern "^\s+\w+ (\d+)\s+" -AllMatches | %{$_.matches.groups[1].Value}

    ForEach ($partId in $partIds) {
        extendPartition $diskId $partId
    }
}

function reportReady($context, $contextLetter)
{
    $reportReady     = $context['REPORT_READY']
    $oneGateEndpoint = $context['ONEGATE_ENDPOINT']
    $vmId            = $context['VMID']
    $token           = $context['ONEGATE_TOKEN']

    if ($reportReady -and $reportReady.ToUpper() -eq 'YES') {
        logmsg '* Report Ready to OneGate'

        if (!$oneGateEndpoint) {
            logmsg '  ... Failed: ONEGATE_ENDPOINT not set'
            return
        }

        if (!$vmId) {
            logmsg '  ... Failed: VMID not set'
            return
        }

        if (!$token) {
            logmsg "  ... Token not set. Try file"
            $tokenPath = $contextLetter + 'token.txt'
            if (Test-Path $tokenPath) {
                $token = Get-Content $tokenPath
            } else {
                logmsg "  ... Failed: Token file not found"
                return
            }
        }

        try {

            $body = 'READY=YES'
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
                logmsg "  ... Use HTTPS for OneGateEndpoint report: $oneGateEndpoint"
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
                logmsg '  ... Success'
            } else {
                logmsg "  ... Failed: $($response.StatusCode)"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message

            logmsg "  ... Failed:`r`n$errorMessage"
        }
    }
}

function ejectContextCD($cdrom_drive)
{
    if (-Not $cdrom_drive) {
        return
    }

    $eject_cdrom = $context['EJECT_CDROM']

    if ($eject_cdrom -ne $null -and $eject_cdrom.ToUpper() -eq 'YES') {
        logmsg '* Ejecting context CD'
        try {
            $disk_master = New-Object -ComObject IMAPI2.MsftDiscMaster2
            for ($cdrom_id = 0; $cdrom_id -lt $disk_master.Count; $cdrom_id++) {
                $disk_recorder = New-Object -ComObject IMAPI2.MsftDiscRecorder2
                $disk_recorder.InitializeDiscRecorder($disk_master.Item($cdrom_id))
                if ($disk_recorder.VolumeName -eq $cdrom_drive.DeviceID) {
                    $disk_recorder.EjectMedia()
                    break
                }
            }
        } catch {
            logmsg "  ... Failed to eject the CD: $_"
        }
    }
}

function removeFile($file)
{
    if ($file -ne "" -and (Test-Path $file)) {
        logmsg "* Removing the file: ${file}"
        Remove-Item -Path $file -Force
    }
}

function removeDir($dir)
{
    if ($dir -ne "" -and (Test-Path $dir)) {
        logmsg "* Removing the directory: ${dir}"
        Remove-Item -Path $dir -Recurse -Force
    }
}

function cleanup($contextPaths)
{
    if ($contextPaths.contextDrive) {
        # Eject CD with 'context.sh' if requested
        ejectContextCD $contextPaths.contextDrive
    } else {
        # Delete 'context.sh' if not on CD-ROM
        removeFile $contextPaths.contextPath

        # and downloaded init scripts
        removeDir $contextPaths.contextInitScriptPath
    }
}

function pswrapper($path)
{
    # source:
    #   - http://cosmonautdreams.com/2013/09/03/Getting-Powershell-to-run-in-64-bit.html
    #   - https://ss64.com/nt/syntax-64bit.html
    If ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
        # This is only set in a x86 Powershell running on a 64bit Windows

        $realpath = [string]$(Resolve-Path "$path")

        # Run 64bit powershell as a subprocess and there execute the command
        #
        # NOTE: virtual subdir 'sysnative' exists only when running 32bit binary under 64bit system
        & "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -Command "$realpath"
    } Else {
        & "$path"
    }
}

################################################################################
# Main
################################################################################

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

logmsg "* Running Script: $($MyInvocation.MyCommand.Path)"

Set-ExecutionPolicy unrestricted -force # not needed if already done once on the VM
[string]$computerName = "$env:computername"
[string]$ConnectionString = "WinNT://$computerName"

# Check the working WMI
if (-Not (Get-WMIObject -ErrorAction SilentlyContinue Win32_Volume)) {
    logmsg "- WMI not ready, exiting"
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host "`r`n" -NoNewline
Write-Host "*********************************`r`n" -NoNewline
Write-Host "*** ENTERING THE SERVICE LOOP ***`r`n" -NoNewline
Write-Host "*********************************`r`n" -NoNewline
Write-Host "`r`n" -NoNewline

# infinite loop
$checksum = ""
do {
    # Stay in this wait-loop until context.sh emerges and its path is stored
    $contextPaths = waitForContext($checksum)

    # Parse context file
    $context = getContext $contextPaths.contextScriptPath

    # Execute the contextualization actions
    extendPartitions
    setTimeZone $context
    addLocalUser $context
    enableRemoteDesktop
    enablePing
    configureNetwork $context
    renameComputer $context
    runScripts $context $contextPaths
    reportReady $context $contextPaths.contextLetter

    # Save the 'applied' context.sh checksum for the next recontextualization
    logmsg "* Calculating the checksum of the file: $($contextPaths.contextScriptPath)"
    $checksum = Get-FileHash -Algorithm SHA256 $contextPaths.contextScriptPath
    logmsg "  ... $($checksum.Hash)"
    # and remove the file itself
    removeFile $contextPaths.contextScriptPath

    # Cleanup at the end
    cleanup $contextPaths

    Write-Host "`r`n" -NoNewline

} while ($true)

Stop-Transcript | Out-Null
