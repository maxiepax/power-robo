#$Global:ptModulePath = (Get-InstalledModule -Name VMware.PlatformTools).InstalledLocation
$Global:PvdModulePath = "C:\Users\adm-kjohansson\Documents\GitHub\power-robo"

#######################################################################################################################
#Region                                            L O G G I N G                                            ###########

Function LogMessage {
    Param (
        [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION","ADVISORY","NOTE","QUESTION","WAIT")] [String]$type = "INFO",
        [Parameter (Mandatory = $false)] [String]$colour,
        [Parameter (Mandatory = $false)] [Switch]$skipnewline
    )

    If (!$colour) {
        $colour = "92m" #Green
    }

    If ($type -eq "INFO")
    {
        $messageColour = "92m" #Green
    }
    elseIf ($type -in "ERROR","EXCEPTION")
    {
        $messageColour = "91m" # Red
    }
    elseIf ($type -in "WARNING","ADVISORY","QUESTION")
    {
        $messageColour = "93m" #Yellow
    }
    elseIf ($type -in "NOTE","WAIT")
    {
        $messageColour = "97m" # White
    }

    If (!$threadTag) {$threadTag = "..."; $threadColour = "97m"}

    <#
    Reference Colours
    31m Red
    32m Green
    33m Yellow
    36m Cyan
    37m White
    91m Bright Red
    92m Bright Green
    93m Bright Yellow
    95m Bright Magenta
    96m Bright Cyan
    97m Bright White
    #>

    $ESC = [char]0x1b
    $timestampColour = "97m"

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"

    $threadTag = $threadTag.toUpper()
    If ($headlessPassed)
    {
		If ($skipnewline)
			{
				Write-Host -NoNewline "[$timestamp] [$threadTag] [$type] $message"
			}
		else
			{
				Write-Host "[$timestamp] [$threadTag] [$type] $message"
			}
	}
    else
    {
		If ($skipnewline)
		{
			Write-Host -NoNewline "$ESC[${timestampcolour} [$timestamp]$ESC[${threadColour} [$threadTag]$ESC[${messageColour} [$type] $message$ESC[0m"
		}
		else
		{
			Write-Host "$ESC[${timestampcolour} [$timestamp]$ESC[${threadColour} [$threadTag]$ESC[${messageColour} [$type] $message$ESC[0m"
		}
	}
    $logContent = '[' + $timeStamp + '] [' +$threadTag + '] ' + $type + ' ' + $message
    Add-Content -path $logFile $logContent
}

#######################################################################################################################
#Region                                             M E N U S                                               ###########

Function Start-PowerRoboMenu {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$jsonPath,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$binaryPath,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$logFile
    )
    LogMessage -type INFO -message $logFile
    Try {
        $Script:menuHeader = "Power Robo"
        $Script:jsonPath = $jsonPath
        $Script:binaryPath = $binaryPath

        $submenuTitle = ("Deployment Options")

        $headingItem01 = "Two node"
        $menuItem01 = "Two node with witness"

        $headingItem02 = "Three node (or more)"
        $menuItem02 = "Three node without witness"

        $headingItem99 = "Help"
        $menuItem99 = "Documentation"


        Do {
            if (!$headlessPassed) { Clear-Host }
            if ($headlessPassed) {
                Write-Host ""; Write-Host -Object $menuHeader -ForegroundColor Magenta
            } elseif (Get-InstalledModule -Name WriteAscii -ErrorAction SilentlyContinue) {
                Write-Host ""; Write-Ascii -InputObject $menuHeader -ForegroundColor Magenta
            }

            if ($commonObject) {
                $menuTitle = "Version $utilityBuild | Topology: $($commonObject.environment.topology) | Networking: $($commonObject.environment.networkingModel) | $submenuTitle"
            } else {
                $menuTitle = "$submenuTitle"
            }
            Write-Host ""; Write-Host -Object " $menuTitle" -ForegroundColor Cyan

            Write-Host ""; Write-Host -Object " $headingItem01" -ForegroundColor Yellow; Write-Host ""
            Write-Host -Object " 01. $menuItem01" -ForegroundColor White

            Write-Host ""; Write-Host -Object " $headingItem02" -ForegroundColor Yellow; Write-Host ""
            Write-Host -Object " 02. $menuItem02" -ForegroundColor White

            Write-Host ""; Write-Host -Object " $headingItem99" -ForegroundColor Yellow; Write-Host ""
            Write-Host -Object " 99. $menuItem99" -ForegroundColor White

            Write-Host -Object ''
            $menuInput = if ($clioptions) { Get-NextSolutionOption } else { Read-Host -Prompt ' Select Option (or B to go Back) to Return to Previous Menu' }
            $menuInput = $MenuInput -replace "`t|`n|`r", ""
            if ($MenuInput -like "0*") { $MenuInput = ($MenuInput -split ("0"), 2)[1] }
            Switch ($menuInput) {
                1 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $menuTitle" -Foregroundcolor Cyan; Write-Host ''
                    Start-TwoNodeClusterMenu
                }

                B {
                    if (!$headlessPassed) { Clear-Host }
                    Break
                }
            }
        }
        Until ($MenuInput -eq 'b')
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Start-PowerRoboMenu

Function Start-TwoNodeClusterMenu {
    Try {
        $jsonSpecFile = "settings.json"
        $submenuTitle = ("Two Node with witness")

        $headingItem01 = "Generate Config Files"
        $menuitem01 = "Generate VCSA deployment specification"

        $headingItem02 = "Verification"
        $menuitem11 = "Verify required files exist"
        $menuitem12 = "Verify infrastructure"

        $headingItem03 = "Deployment"
        $menuitem21 = "Deploy VCSA"
        $menuitem22 = "Deploy witness"

        $headingItem04 = "Post-Configuration"
        $menuitem31 = "Configure basic things"
        $menuitem32 = "Setup vSAN"

        Do {
            if (!$headlessPassed) { Clear-Host }
            if ($headlessPassed) {
                Write-Host ""; Write-Host -Object $menuHeader -ForegroundColor Magenta
            } elseif (Get-InstalledModule -Name WriteAscii -ErrorAction SilentlyContinue) {
                Write-Host ""; Write-Ascii -InputObject $menuHeader -ForegroundColor Magenta
            }


            $menuTitle = "$submenuTitle"
            Write-Host ""; Write-Host -Object " $menuTitle" -ForegroundColor Cyan

            Write-Host ""; Write-Host -Object " $headingItem01" -ForegroundColor Yellow
            Write-Host -Object " 01. $menuItem01" -ForegroundColor White

            Write-Host ""; Write-Host -Object " $headingItem02" -ForegroundColor Yellow
            Write-Host -Object " 11. $menuItem11" -ForegroundColor White
            Write-Host -Object " 12. $menuItem12" -ForegroundColor White

            Write-Host ""; Write-Host -Object " $headingItem03" -ForegroundColor Yellow
            Write-Host -Object " 21. $menuItem21" -ForegroundColor White
            Write-Host -Object " 22. $menuItem22" -ForegroundColor White

            Write-Host ""; Write-Host -Object " $headingItem04" -ForegroundColor Yellow
            Write-Host -Object " 31. $menuItem31" -ForegroundColor White
            Write-Host -Object " 32. $menuItem32" -ForegroundColor White

            Write-Host -Object ''
            $menuInput = if ($clioptions) { Get-NextSolutionOption } else { Read-Host -Prompt ' Select Option (or B to go Back) to Return to Previous Menu' }
            $menuInput = $MenuInput -replace "`t|`n|`r", ""
            if ($MenuInput -like "0*") { $MenuInput = ($MenuInput -split ("0"), 2)[1] }
            Switch ($menuInput) {
                1 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem01" -Foregroundcolor Cyan; Write-Host ''
                    New-generateVCSAJson -jsonFile ($jsonPath + $jsonSpecFile)
                    waitKey
                }
                11 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem12" -Foregroundcolor Cyan; Write-Host ''
                    Test-ESXiHosts2nodeFiles -binaryPath ($binaryPath)
                    waitKey
                }
                12 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem12" -Foregroundcolor Cyan; Write-Host ''
                    Test-ESXiHosts2node -jsonPath ($jsonPath)
                    waitKey
                }
                21 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem21" -Foregroundcolor Cyan; Write-Host ''
                    New-VCSADeployment -binaryPath $binaryPath -jsonPath $jsonPath -logFile $logFile
                    anyKey
                }
                B {
                    if (!$headlessPassed) { Clear-Host }
                    Break
                }
            }
        }
        Until ($MenuInput -eq 'b')
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

#######################################################################################################################
#Region                                    I N F O  G A T H E R I N G                                       ###########

Function Get-deploymentConfig ($jsonPath) {
    Try {
        $deploymentConfig = Get-Content -Path $jsonPath"settings.json" -Raw | ConvertFrom-Json
        LogMessage -type INFO -message "Finding $($jsonPath)settings.json: SUCCESSFUL"
        return $deploymentConfig
    } Catch {
        LogMessage -type ERROR -message $_.Exception.Message
    }
}

Function Get-vSANCompatibleDrives ($esxiHost, $password) {
    $Null = @(
        Connect-VIServer -Server $esxiHost -user root -Password $password
        LogMessage -type INFO -message "Connecting to ESXi host $($esxiHost): SUCCESSFUL"
        $esxcli = Get-EsxCli -VMhost $esxiHost
        $disks = $esxcli.storage.core.device.list.Invoke() | Select-Object -Property Device, @{ n = "Size"; e = { [int]($_.Size) } } | Where-Object { $_.Size -gt 500000 }
        Disconnect-VIServer -Server $esxiHost -Confirm:$false
        LogMessage -type INFO -message "Disconnecting from ESXi host $($esxiHost): SUCCESSFUL"
        )
    return $disks
}

Function New-generateVCSAJson () {

    $isoLetter = New-mountVCSAIso($binaryPath)
    $deploymentConfig = Get-deploymentConfig($jsonPath)
    
    # copy the .json example to the folder
    $vcsaOrigJson = "$($isoLetter):\vcsa-cli-installer\templates\install\vCSA_with_cluster_on_ESXi.json"
    LogMessage -type INFO -message "Copying the json Template from the VCSA ISO to local disk"
    
    Copy-Item $vcsaOrigJson -Destination $jsonPath
    
    # modify the json file
    $vcsaJson = Get-Content "$($jsonPath)\vCSA_with_cluster_on_ESXi.json" -raw | ConvertFrom-Json
    LogMessage -type INFO -message "Reading VCSA json file into memory: SUCCESSFUL"
    
    #Target ESXi 
    $vcsaJson.new_vcsa.esxi.hostname = $deploymentConfig.hosts.esxi01.mgmt.ip
    $vcsaJson.new_vcsa.esxi.password = $deploymentConfig.hosts.esxi01.password
    LogMessage -type INFO -message "Modifying target esxi settings: SUCCESSFUL"
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.datacenter = $deploymentConfig.vcenter.datacenter
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.cluster = $deploymentConfig.vcenter.cluster
    
    #vSAN Settings
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.compression_only = $deploymentConfig.vcenter.compression
    LogMessage -type INFO -message "Gathering Disks to be used by vSAN: SUCCESSFUL"
    $disks = Get-vSANCompatibleDrives -esxiHost "10.11.11.101" -Password "VMw@re1!"
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.storage_pool.single_tier = $disks.Device
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.vsan_hcl_database_path = "$($jsonPath)all.json"
    LogMessage -type INFO -message "Modifying vSAN settings: SUCCESSFUL"
    
    
    #vCenter Appliance Settings
    $vcsaJson.new_vcsa.appliance.deployment_option = $deploymentConfig.vcenter.deployment_size
    $vcsaJson.new_vcsa.appliance.name = $deploymentConfig.vcenter.vm_name
    LogMessage -type INFO -message "Modifying VCSA Appliance settings: SUCCESSFUL"
    
    #vCenter Network
    $vcsaJson.new_vcsa.network.ip = $deploymentConfig.vcenter.mgmt.ip
    
    $dns = ""
    if ($deploymentConfig.global.dns01) { $dns = $deploymentConfig.global.dns01 }
    if ($deploymentConfig.global.dns02) { $dns = "$dns,$($deploymentConfig.global.dns02)" }
    $vcsaJson.new_vcsa.network.dns_servers = $dns
    LogMessage -type INFO -message "Modifying VCSA DNS settings: SUCCESSFUL"
    
    $vcsaJson.new_vcsa.network.prefix = $deploymentConfig.vcenter.mgmt.prefix
    $vcsaJson.new_vcsa.network.gateway = $deploymentConfig.vcenter.mgmt.gw
    $vcsaJson.new_vcsa.network.system_name = $deploymentConfig.vcenter.mgmt.fqdn
    LogMessage -type INFO -message "Modifying VCSA Network settings: SUCCESSFUL"
    
    #vCenter OS Settings
    $vcsaJson.new_vcsa.os.password = $deploymentConfig.vcenter.appliance_password
    LogMessage -type INFO -message "Modifying VCSA OS password: SUCCESSFUL"
    
    
    if ($deploymentConfig.global.ntp01) {
        $ntp = ""
        if ($deploymentConfig.global.ntp01) { $ntp = $deploymentConfig.global.ntp01 }
        if ($deploymentConfig.global.ntp02) { $ntp = "$ntp,$($deploymentConfig.global.ntp02)" }
        $vcsaJson.new_vcsa.os.ntp_servers = $ntp
    } else {
        LogMessage -type INFO -message "No NTP specified, fallbacking to VMware Tools Sync: SUCCESSFUL"
        $vcsaJson.new_vcsa.os = $vcsajson.new_vcsa.os | Select-Object * -ExcludeProperty ntp_servers
        $vcsaJson.new_vcsa.os | Add-Member -Name time_tools_sync -Value $true -MemberType NoteProperty
    }
    LogMessage -type INFO -message "Modifying VCSA NTP settings: SUCCESSFUL"
    
    #vCenter SSO
    $vcsaJson.new_vcsa.sso.domain_name = $deploymentConfig.vcenter.sso_domain
    $vcsaJson.new_vcsa.sso.password = $deploymentConfig.vcenter.sso_administrator_password
    LogMessage -type INFO -message "Modifying VCSA SSO settings: SUCCESSFUL"
    
    #CEIP
    $vcsaJson.ceip.settings.ceip_enabled = $deploymentConfig.vcenter.ceip
    LogMessage -type INFO -message "Modifying VCSA CEIP Policy: SUCCESSFUL"
    
    # save the modified json file
    $vcsaJson | ConvertTo-Json -depth 32| set-content "$($jsonPath)\modified_vCSA_with_cluster_on_ESXi.json"
    LogMessage -type INFO -message "Writing new VCSA json config file to $($jsonPath)\modified_vCSA_with_cluster_on_ESXi.json: SUCCESSFUL"
    
    }

#######################################################################################################################
#Region                                       V E R I F I C A T I O N                                       ###########
Function Test-SilentNetConnection {
    <#
        .SYNOPSIS
        Tests the network connection without spamming the console.

        .PARAMETER ComputerName
        IP or FQDN to the host you want to test network connection to.

        .EXAMPLE
        Test-SilentNetworkConnection -ComputerName 10.11.11.101

        .NOTES
        Author: Ken Gould
        Github: https://github.com/feardamhan
    #>

    Param (
        [Parameter (Mandatory = $true)] [String]$computerName
    )
    $OriginalPref = $ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'
    $PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Quiet'
    $testResult = Test-NetConnection -ComputerName $computerName -warningAction SilentlyContinue
    $Global:ProgressPreference = $OriginalPref
    Return $testResult
}

Function Test-ESXiHosts2node {
    Param (
        [Parameter (Mandatory = $true)] [Object]$jsonPath
    )
    $config = Get-deploymentConfig -json $jsonPath
    
    if (Test-SilentNetConnection -computerName $config.hosts.esxi01.mgmt.ip) {
        LogMessage -type INFO -message "Testing connectivity to $($config.hosts.esxi01.mgmt.ip): SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Testing connectivity to $($config.hosts.esxi01.mgmt.ip): FAILED"
    }
    if (Test-SilentNetConnection -computerName $config.hosts.esxi02.mgmt.ip) {
        LogMessage -type INFO -message "Testing connectivity to $($config.hosts.esxi02.mgmt.ip): SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Testing connectivity to $($config.hosts.esxi02.mgmt.ip): FAILED"
    }
    if (Test-SilentNetConnection -computerName $config.witnesshost.mgmt.ip) {
        LogMessage -type INFO -message "Testing connectivity to $($config.witnesshost.mgmt.ip): SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Testing connectivity to $($config.witnesshost.mgmt.ip): FAILED"
    }

    if ($config.global.dns01) {
        if (Test-SilentNetConnection -computerName $config.hosts.esxi01.mgmt.fqdn) {
            LogMessage -type INFO -message "Testing connectivity to $($config.hosts.esxi01.mgmt.fqdn): SUCCESSFUL"
        } else {
            LogMessage -type WARNING -message "Testing connectivity to $($config.hosts.esxi01.mgmt.fqdn): FAILED"
        }
        if (Test-SilentNetConnection -computerName $config.hosts.esxi02.mgmt.fqdn) {
            LogMessage -type INFO -message "Testing connectivity to $($config.hosts.esxi02.mgmt.fqdn): SUCCESSFUL"
        } else {
            LogMessage -type WARNING -message "Testing connectivity to $($config.hosts.esxi02.mgmt.fqdn): FAILED"
        }
        if (Test-SilentNetConnection -computerName $config.witnesshost.mgmt.fqdn) {
            LogMessage -type INFO -message "Testing connectivity to $($config.witnesshost.mgmt.fqdn): SUCCESSFUL"
        } else {
            LogMessage -type WARNING -message "Testing connectivity to $($config.witnesshost.mgmt.fqdn): FAILED"
        }
    } else {
        LogMessage -type INFO -message "No DNS configured: SKIPPING"
    }

    if (Connect-VIServer -Server $config.hosts.esxi01.mgmt.ip -user root -Password $config.hosts.esxi01.password) {
        LogMessage -type INFO -message "Testing credentials for $($config.hosts.esxi01.mgmt.ip): SUCCESSFUL"
        $esxcli = Get-EsxCli -VMhost $config.hosts.esxi01.mgmt.ip
        $disks = $esxcli.storage.core.device.list.Invoke() | Select-Object -Property Device, @{ n = "Size"; e = { [int]($_.Size) } } | Where-Object { $_.Size -gt 500000 }
        if ($disks) {
            LogMessage -type INFO -message "Checking for vSAN Claimable disks on $($config.hosts.esxi01.mgmt.ip): SUCCESSFUL"
        } else {
            LogMessage -type ERROR -message "Checking for vSAN Claimable disks on $($config.hosts.esxi01.mgmt.ip): FAILED"
        }  
        disconnect-viserver -Server $config.hosts.esxi01.mgmt.ip -Confirm:$false
    } else {
        LogMessage -type WARNING -message "Testing credentials for $($config.hosts.esxi01.mgmt.ip): FAILED"
    }
    if (Connect-VIServer -Server $config.hosts.esxi02.mgmt.ip -user root -Password $config.hosts.esxi02.password) {
        LogMessage -type INFO -message "Testing credentials for $($config.hosts.esxi02.mgmt.ip): SUCCESSFUL"
        $esxcli = Get-EsxCli -VMhost $config.hosts.esxi02.mgmt.ip
        $disks = $esxcli.storage.core.device.list.Invoke() | Select-Object -Property Device, @{ n = "Size"; e = { [int]($_.Size) } } | Where-Object { $_.Size -gt 500000 }
        if ($disks) {
            LogMessage -type INFO -message "Checking for vSAN Claimable disks on $($config.hosts.esxi01.mgmt.ip): SUCCESSFUL"
        } else {
            LogMessage -type ERROR -message "Checking for vSAN Claimable disks on $($config.hosts.esxi01.mgmt.ip): FAILED"
        } 
        disconnect-viserver -Server $config.hosts.esxi02.mgmt.ip -Confirm:$false
    } else {
        LogMessage -type WARNING -message "Testing credentials for $($config.hosts.esxi02.mgmt.ip): FAILED"
    }
    if (Connect-VIServer -Server $config.witnesshost.mgmt.ip -user root -Password $config.witnesshost.password) {
        LogMessage -type INFO -message "Testing credentials for $($config.witnesshost.mgmt.ip): SUCCESSFUL"
        disconnect-viserver -Server $config.witnesshost.mgmt.ip -Confirm:$false
    } else {
        LogMessage -type WARNING -message "Testing credentials for $($config.witnesshost.mgmt.ip): FAILED"
    }
}

Function Test-ESXiHosts2nodeFiles {
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath
    )
    
    $vcsaISO = Get-ChildItem $binaryPath -Filter *VCSA* | % { $_.FullName }
    if ($vcsaISO) {
        LogMessage -type INFO -message "Checking binaries folder for VCSA ISO: SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Cloud not find VCSA ISO: FAILURE"
    }

    $vcsaISO = Get-ChildItem $binaryPath -Filter *VMware-vSAN-ESA-Witness* | % { $_.FullName }
    if ($vcsaISO) {
        LogMessage -type INFO -message "Checking binaries folder for ESA Witness OVA: SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Cloud not find ESA Witness OVA: FAILURE"
    }
}

#######################################################################################################################
#Region                                         S U P P O R T I N G                                         ###########

Function New-mountVCSAIso () {
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath
        )

    #locate the ESXi installable
    $vcsaISO = Get-ChildItem $binaryPath -Filter *VCSA* | % { $_.FullName }
    if ($vcsaISO) {
        LogMessage -type INFO -message "Checking binaries folder for VCSA ISO: SUCCESSFUL"
        # mount the ISO
        $isoDrive = Mount-DiskImage -ImagePath $vcsaISO -PassThru
        LogMessage -type INFO -message "Mounting the ISO: SUCCESSFUL"

        # get the DriveLetter currently assigned to the drive (a single [char])
        $isoLetter = ($isoDrive | Get-Volume).DriveLetter
        LogMessage -type INFO -message "Mounted the ISO to $($isoLetter): SUCCESSFUL"

        return $isoLetter
    } else {
        LogMessage -type INFO -message "Cloud not find VCSA ISO: FAILURE"
        break
    }
}

#######################################################################################################################
#Region                                         D E P L O Y M E N T                                         ###########

Function New-VSANWitnessDeployment {
   Param (
        [Parameter (Mandatory = $true)] [Object]$witnessProp,
        [Parameter (Mandatory = $true)] [Object]$binaries
        )
    #Check for Witness OVA in binary folder
    $witnessSearchString = $binaries + "VMware-vSAN-ESA-Witness*"
    $localWitnessFile = Get-ChildItem -path $witnessSearchString
    If ($localWitnessFile)
    {
        $applianceOVA = $localWitnessFile.VersionInfo.FileName
    }
    else
    {
        LogMessage -type ERROR -message "VSAN Witness OVA with Build $witnessBuild not found"
        anykey
        Break
    }
    #Environment Details

    $datastoreName = $witnessProp.datastoreName
    $dns = "$($witnessProp.dns.dns01),$($witnessProp.dns.dns02)"
    $dns1 = $witnessProp.dns.dns01
    $dns2 = $witnessProp.dns.dns02
    $dnsDomain = $witnessProp.dns.search
    $ntp = "$($witnessProp.ntp.ntp01),$($witnessProp.ntp.ntpServer2)"

    #Appliance Details
    $guestUser = "root"
    $Command_Path = '/bin/python'
    $hostname = $witnessProp.hostname
    $witnessFqdn = $hostname + "." + $dnsDomain
    $vmName = $witnessProp.vm_name
    $ipAddress0 = $witnessProp.ip
    $netmask0= $witnessProp.netmask
    $gateway0 = $witnessProp.gateway
    $mgmtVlan = $witnessProp.mgmtVlan
    $vsannetwork = "Management"
    $verifyCommand = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --verifyOnly --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --powerOn --name="' + $vmName + '" --vmFolder="' + $environmentFolder + '" --net:"Management Network=' + $segmentName+ '" --net:"Secondary Network=' + $segmentName +'" --datastore="' + $datastoreName +'" --X:injectOvfEnv --prop:guestinfo.hostname="' + $hostname +'" --prop:guestinfo.ipaddress0="' + $ipAddress0 + '" --prop:guestinfo.netmask0="' + $netmask0 + '" --prop:guestinfo.gateway0="' + $gateway0 + '" --prop:guestinfo.dns="' + $dns + '" --prop:guestinfo.dnsDomain="' + $dnsDomain + '" --prop:guestinfo.ntp="' + $ntp +'" --prop:guestinfo.passwd="' + $witnessProp.hostCredentials.esxiPassword + '" --prop:guestinfo.vsannetwork="' + $vsannetwork + '" "' + $applianceOVA + '" "vi://' + $ssoUser + ':' + $ssoPassword + '@' + $mgmtvCenterFQDN + '/' + $targetDatacenter + '/host/' + $targetCluster + '/"'
    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --powerOn --name="' + $vmName + '" --vmFolder="' + $environmentFolder + '" --net:"Management Network=' + $segmentName+ '" --net:"Secondary Network=' + $segmentName +'" --datastore="' + $datastoreName +'" --X:injectOvfEnv --prop:guestinfo.hostname="' + $hostname +'" --prop:guestinfo.ipaddress0="' + $ipAddress0 + '" --prop:guestinfo.netmask0="' + $netmask0 + '" --prop:guestinfo.gateway0="' + $gateway0 + '" --prop:guestinfo.dns="' + $dns + '" --prop:guestinfo.dnsDomain="' + $dnsDomain + '" --prop:guestinfo.ntp="' + $ntp +'" --prop:guestinfo.passwd="' + $witnessProp.hostCredentials.esxiPassword + '" --prop:guestinfo.vsannetwork="' + $vsannetwork + '" "' + $applianceOVA + '" "vi://' + $ssoUser + ':' + $ssoPassword + '@' + $mgmtvCenterFQDN + '/' + $targetDatacenter + '/host/' + $targetCluster + '/"'


    #Deploy Appliance
    $session = Connect-VIServer $infrastructureSettings.infrastructureVC.fqdn -user $infrastructureSettings.infrastructureVC.username -pass $infrastructureSettings.infrastructureVC.password -ErrorAction SilentlyContinue

    LogMessage -Type INFO -Message "Pre-validating witness deployment"
    $verifyWitness = Invoke-Expression "& $verifyCommand"
    If ($verifyWitness[-1] -eq "Completed successfully")
    {
        $command | Out-File $logFile -encoding ASCII -append
        LogMessage -Type INFO -Message "Deploying vSAN Witness Appliance to $($witnessProp.witnesshost)"
        Invoke-Expression "& $command" | Out-File $logFile -Encoding ASCII -Append
        LogMessage -Type WAIT -Message "[$vmName] Waiting for VM Tools to start"
        Do {
            $toolsStatus = GetVMToolsStatus -vmname $vmName
        } Until (($toolsStatus -eq "toolsOld") -OR ($toolsStatus -eq "toolsOk"))
        Sleep 60

        # Set Management VLAN
        LogMessage -Type INFO -Message "[$vmName] Configuring Management VLAN"
        $scriptCommand = '/bin/esxcli.py network vswitch standard portgroup set -p "Management Network" -v ' + $mgmtVlan
        runGuestOpInESXiVM -vm_moref (Get-VM $vmName).ExtensionData.MoRef -guest_username $guestUser -guest_password $witnessProp.hostCredentials.esxiPassword -guest_command_path $command_path -guest_command_args $scriptCommand
        LogMessage -Type INFO -Message "[$vmName] Ensuring SSH is Running"
        $scriptCommand = 'vim-cmd hostsvc/start_ssh'
        runGuestOpInESXiVM -vm_moref (Get-VM $vmName).ExtensionData.MoRef -guest_username $guestUser -guest_password $witnessProp.hostCredentials.esxiPassword -guest_command_path $command_path -guest_command_args $scriptCommand
        $scriptCommand = 'vim-cmd hostsvc/enable_ssh'
        runGuestOpInESXiVM -vm_moref (Get-VM $vmName).ExtensionData.MoRef -guest_username $guestUser -guest_password $witnessProp.hostCredentials.esxiPassword -guest_command_path $command_path -guest_command_args $scriptCommand
        disconnectinfrastructureVC

        LogMessage -Type WAIT -Message "[$vmName] Waiting for Management Interface to be reachable"
        Do {} Until (Test-SilentNetConnection -ComputerName $ipaddress0)

        Connect-VCFvCenter -instanceObject $instanceObject
        LogMessage -Type INFO -Message "[$vmName] Adding Host to vCenter"
        Add-VMHost $witnessFqdn -Location $((Get-Datacenter).name) -user $witnessProp.hostCredentials.esxiUsername -password $witnessProp.hostCredentials.esxiPassword -Force | Out-Null
        LogMessage -Type WAIT -Message "Allowing vCenter Inventory to Synchronize"
        Sleep 90

        #Remove VMK1
        LogMessage -Type INFO -Message "[$vmName] Removing vmk1"
        Get-VMHost $witnessFqdn | Get-VMHostNetworkAdapter -Name vmk1 | Remove-VMHostNetworkAdapter -Confirm:$false
        #Remove Virtual Switch
        LogMessage -Type INFO -Message "[$vmName] Removing secondarySwitch"
        Get-VMHost $witnessFqdn | Get-VirtualSwitch -name "secondarySwitch" | Remove-VirtualSwitch -confirm:$false

        #Form Object suitable for calling to Set-EsxiNtp Function
        $witnessObject = New-Object -TypeName psobject
        $witnessObject | Add-Member -notepropertyname 'esxiUsername' -notepropertyvalue $guestUser
        $witnessObject | Add-Member -notepropertyname 'esxiPassword' -notepropertyvalue $witnessProp.hostCredentials.esxiPassword
        $witnessObject | Add-Member -notepropertyname 'ntpServer1' -notepropertyvalue $witnessProp.ntp.ntpServer1
        $witnessObject | Add-Member -notepropertyname 'ntpServer2' -notepropertyvalue $witnessProp.ntp.ntpServer2
        $witnessObject | Add-Member -notepropertyname 'hostname' -notepropertyvalue $hostname
        $witnessObject | Add-Member -notepropertyname 'mgmtIp' -notepropertyvalue $ipaddress0
        $witnessObject | Add-Member -notepropertyname 'fqdn' -notepropertyvalue $witnessFqdn
        Get-VMHost -name $witnessFqdn | Get-VMHostService | Where-Object {$_.label -eq "SSH"} | Start-VMHostService | Out-Null
        $hostConnection = connectHost -hostObject $witnessObject -silent
        Set-EsxiNtp -hostObject $witnessObject
        disconnectHost -hostIp $witnessObject.mgmtIp

        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
    }
     else
    {
        disconnectinfrastructureVC
        LogMessage -Type ERROR -Message "Deployment pre-validation of Witness failed. Please ensure the OVA was successfully staged to binaries folder."
        anyKey
        Break
    }

}

Function New-VCSADeployment () {
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath,
        [Parameter (Mandatory = $true)] [Object]$jsonPath,
        [Parameter (Mandatory = $true)] [Object]$logFile
        )
        
    $isoLetter = New-mountVCSAIso -binaryPath $binaryPath
    LogMessage -type INFO -message "Mounting VCSA ISO: SUCCESSFUL"

    $verifyTemplateCommand = "$($isoLetter):\vcsa-cli-installer\win32\vcsa-deploy.exe install $($jsonPath)\modified_vCSA_with_cluster_on_ESXi.json --accept-eula --no-esx-ssl-verify --verify-template-only"
    $verifyPrecheckCommand = "$($isoLetter):\vcsa-cli-installer\win32\vcsa-deploy.exe install $($jsonPath)\modified_vCSA_with_cluster_on_ESXi.json --accept-eula --no-esx-ssl-verify --precheck-only"
    $deployCommand = "$($isoLetter):\vcsa-cli-installer\win32\vcsa-deploy.exe install $($jsonPath)\modified_vCSA_with_cluster_on_ESXi.json --accept-eula --no-esx-ssl-verify --terse"


    $verifyTemplate = Invoke-Expression "& $verifyTemplateCommand"
    if ($verifyTemplate|where{$_ -match "failed"}) {
            LogMessage -type INFO -message "VCSA Template verification: FAILED"
            break
    } else {
        LogMessage -type INFO -message "VCSA Template verification: SUCCESSFUL"
        $verifyPrecheck = Invoke-Expression "& $verifyPrecheckCommand"
        if ($verifyPrecheck|where{$_ -match "failed"}) {
            LogMessage -type INFO -message "VCSA Precheck verification: FAILED"
            break
        } else {
            LogMessage -type INFO -message "VCSA Precheck verification: SUCCESSFUL"
            LogMessage -type INFO -message "Starting deployment of VCSA: SUCCESSFUL"
            Invoke-Expression "& $deployCommand" | Out-File $logFile -Encoding ASCII -Append
        }
    }      
}