#$Global:ptModulePath = (Get-InstalledModule -Name VMware.PlatformTools).InstalledLocation
$Global:PvdModulePath = "C:\Users\adm-kjohansson\Documents\GitHub\power-robo"

#######################################################################################################################
#Region                                            L O G G I N G                                            ###########

Function LogMessage {
    <#
        .SYNOPSIS
        Logs messages to console and file.

        .PARAMETER message
        The message to be showed and logged.

        .PARAMETER type
        The type of message to be logged.

        .PARAMETER colour
        Optional colour other than defaults.

        .PARAMETER skipnewline
        Dont create a new line.

        .EXAMPLE
        LogMessage -type INFO -message "Validating folder exists: SUCCESSFUL"

        .NOTES
         Author: Ken Gould
        Github: https://github.com/feardamhan
    #>
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
Function anyKey
{
    Write-Host ''; Write-Host -Object ' Press any key to continue/return to menu...' -ForegroundColor Yellow; Write-Host '';
	If ($headlessPassed){
		$response = if (!$clioptions) { Read-Host } else { "" }
	} else {
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
	}
}

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
        $menuitem22 = "Deploy vSAN Witness"
        
        $headingItem04 = "Post-Configuration"
        $menuitem31 = "Join remaining hosts to VCSA"
        $menuitem32 = "Create Distributed vSwitch"
        $menuitem33 = "Configure ESXi hosts"
        $menuitem34 = "Setup vSAN"

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
            Write-Host -Object " 33. $menuItem33" -ForegroundColor White
            Write-Host -Object " 34. $menuItem34" -ForegroundColor White

            Write-Host -Object ''
            $menuInput = if ($clioptions) { Get-NextSolutionOption } else { Read-Host -Prompt ' Select Option (or B to go Back) to Return to Previous Menu' }
            $menuInput = $MenuInput -replace "`t|`n|`r", ""
            if ($MenuInput -like "0*") { $MenuInput = ($MenuInput -split ("0"), 2)[1] }
            Switch ($menuInput) {
                1 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem01" -Foregroundcolor Cyan; Write-Host ''
                    New-generateVCSAJson -jsonFile ($jsonPath + $jsonSpecFile)
                    anyKey
                }
                11 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem12" -Foregroundcolor Cyan; Write-Host ''
                    Test-ESXiHosts2nodeFiles -binaryPath ($binaryPath)
                    anyKey
                }
                12 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem12" -Foregroundcolor Cyan; Write-Host ''
                    Test-ESXiHosts2node -jsonPath ($jsonPath)
                    anyKey
                }
                21 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem21" -Foregroundcolor Cyan; Write-Host ''
                    New-VCSADeployment -binaryPath $binaryPath -jsonPath $jsonPath -logFile $logFile
                    anyKey
                }
                22 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem22" -Foregroundcolor Cyan; Write-Host ''
                    Start-vSANWitnessDeployment -binaryPath $binaryPath -jsonPath $jsonPath
                    anyKey
                }
                31 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem31" -Foregroundcolor Cyan; Write-Host ''
                    Start-JoinAdditionalESXiHosts -jsonPath $jsonPath
                    anyKey
                }
                32 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem32" -Foregroundcolor Cyan; Write-Host ''
                    Start-CreatevDSdelvSS -jsonPath $jsonPath
                    anyKey
                }
                33 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem33" -Foregroundcolor Cyan; Write-Host ''
                    Start-ConfigureEsxiHosts -jsonPath $jsonPath
                    anyKey
                }
                34 {
                    if (!$headlessPassed) { Clear-Host }; Write-Host `n " $submenuTitle : $menuItem34" -Foregroundcolor Cyan; Write-Host ''
                    Start-ConfigureTwoNodevSANwithWitness -jsonPath $jsonPath
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

Function Get-vSANCompatibleDrives {
    Param (
        [Parameter (Mandatory = $true)] [String]$esxiHost,
        [Parameter (Mandatory = $true)] [String]$password
    )
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
    $esxhost = $deploymentConfig.hosts | Select-Object -First 1
    
    # copy the .json example to the folder
    $vcsaOrigJson = "$($isoLetter):\vcsa-cli-installer\templates\install\vCSA_with_cluster_on_ESXi.json"
    LogMessage -type INFO -message "Copying the json Template from the VCSA ISO to local disk"
    
    Copy-Item $vcsaOrigJson -Destination $jsonPath
    
    # modify the json file
    $vcsaJson = Get-Content "$($jsonPath)\vCSA_with_cluster_on_ESXi.json" -raw | ConvertFrom-Json
    LogMessage -type INFO -message "Reading VCSA json file into memory: SUCCESSFUL"
    
    #Target ESXi 
    $vcsaJson.new_vcsa.esxi.hostname = $esxhost.mgmt.ip
    $vcsaJson.new_vcsa.esxi.password = $esxhost.password
    LogMessage -type INFO -message "Modifying target esxi settings: SUCCESSFUL"
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.datacenter = $deploymentConfig.vcenter.datacenter
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.cluster = $deploymentConfig.vcenter.cluster
    
    #vSAN Settings
    LogMessage -type INFO -message "Gathering Disks to be used by vSAN: SUCCESSFUL"
    $disks = Get-vSANCompatibleDrives -esxiHost $esxhost.mgmt.ip -Password $esxhost.password
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.storage_pool.single_tier = $disks.Device
    $vcsaJson.new_vcsa.esxi.VCSA_cluster.vsan_hcl_database_path = "$($jsonPath)/$($deploymentConfig.vcenter.hcl_json)"
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
    
    LogMessage -type NOTE -message "Generation of VCSA json: COMPLETED"
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
    
    foreach ($esxihost in $config.hosts) {
        if (Test-SilentNetConnection -computerName $esxihost.mgmt.ip) {
            LogMessage -type INFO -message "Testing connectivity to $($esxihost.mgmt.ip): SUCCESSFUL"
        } else {
            LogMessage -type WARNING -message "Testing connectivity to $($esxihost.mgmt.ip): FAILED"
        }
    }

    if (Test-SilentNetConnection -computerName $config.witnesstarget.common.ip) {
        LogMessage -type INFO -message "Testing connectivity to $($config.witnesstarget.common.ip): SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Testing connectivity to $($config.witnesstarget.common.ip): FAILED"
    }

    if ($config.global.dns01) {
        foreach ($esxihost in $config.hosts) {
            if ($esxihost.mgmt.fqdn) {
                if (Test-SilentNetConnection -computerName $esxihost.mgmt.fqdn) {
                    LogMessage -type INFO -message "Testing connectivity to $($esxihost.mgmt.fqdn): SUCCESSFUL"
                } else {
                    LogMessage -type WARNING -message "Testing connectivity to $($esxihost.mgmt.fqdn): FAILED"
                }
            } else {
                LogMessage -type WARNING -message "Missing FQDN for $($esxihost.mgmt.ip): FAILED"
            }
        }
    
        if ($config.witnesstarget.mgmt.fqdn) {
            if (Test-SilentNetConnection -computerName $config.witnesstarget.mgmt.fqdn) {
                LogMessage -type INFO -message "Testing connectivity to $($config.witnesstarget.common.fqdn): SUCCESSFUL"
            } else {
                LogMessage -type WARNING -message "Testing connectivity to $($config.witnesstarget.common.fqdn): FAILED"
            }
        } else {
            LogMessage -type WARNING -message "missing FQDN for $($config.witnesstarget.common.ip): FAILED"
        }

    } else {
        LogMessage -type INFO -message "No DNS configured: SKIPPING"
    }

    foreach ($esxihost in $config.hosts) {
        if (Connect-VIServer -Server $esxihost.mgmt.ip -user root -Password $esxihost.password) {
            LogMessage -type INFO -message "[$($esxihost.mgmt.ip)] Testing credentials: SUCCESSFUL"
            $esxcli = Get-EsxCli -VMhost $esxihost.mgmt.ip
            $disks = $esxcli.storage.core.device.list.Invoke() | Select-Object -Property Device, @{ n = "Size"; e = { [int]($_.Size) } } | Where-Object { $_.Size -gt 500000 }
            if ($disks) {
                LogMessage -type INFO -message "[$($esxihost.mgmt.ip)] Checking for vSAN Claimable disks: SUCCESSFUL"
                foreach ($disk in $disks) {
                    LogMessage -type INFO -message "[$($esxihost.mgmt.ip)] Found vSAN eligeable disk $($disk.device) with size $($disk.size)mb: SUCCESSFUL"
                }
            } else {
                LogMessage -type ERROR -message "[$($esxihost.mgmt.ip)] Checking for vSAN Claimable disks: FAILED"
            }  
            Disconnect-viserver -Server $esxihost.mgmt.ip -Confirm:$false
        } else {
            LogMessage -type WARNING -message "[$($esxihost.mgmt.ip)] Testing credentials: FAILED"
            Disconnect-viserver -Server $esxihost.mgmt.i -Confirm:$false

        }
    }

    if (Connect-VIServer -Server $config.witnesstarget.common.ip -user root -Password $config.witnesstarget.common.password) {
        LogMessage -type INFO -message "[$($config.witnesstarget.common.ip)] Testing credentials: SUCCESSFUL"
        if (Get-Datastore -Name $config.witnesstarget.common.datastore) {
            LogMessage -type INFO -message "[$($config.witnesstarget.common.ip)] Checking if datastore $($config.witnesstarget.common.datastore) exists: SUCCESSFUL"
        } else {
            LogMessage -type WARNING -message "[$($config.witnesstarget.common.ip)] Checking if datastore $($config.witnesstarget.common.datastore) exists: FAILED"
        }

        if (Get-VirtualPortGroup -Name $config.witnesstarget.common.portgroup_name) {
            LogMessage -type INFO -message "[$($config.witnesstarget.common.ip)] Checking if portgroup $($config.witnesstarget.common.portgroup_name) exists: SUCCESSFUL"
            if ((Get-VirtualPortGroup -Name $config.witnesstarget.common.portgroup_name).VLanId -eq $config.witnesstarget.common.portgroup_vlan) {
                LogMessage -type INFO -message "[$($config.witnesstarget.common.ip)] Checking if portgroup has the vlan $($config.witnesstarget.common.portgroup_vlan): SUCCESSFUL"
            } else {
            LogMessage -type INFO -message "[$($config.witnesstarget.common.ip)] Checking if portgroup has the vlan $($config.witnesstarget.common.portgroup_vlan): SUCCESSFUL"
            }
        } else {
            LogMessage -type WARNING -message "[$($config.witnesstarget.common.ip)] Checking if datastore $($config.witnesstarget.common.portgroup_name) exists: FAILED"
        }    
    } else {
        LogMessage -type WARNING -message "[$($config.witnesstarget.common.ip)] Testing credentials: FAILED"
        Disconnect-viserver -Server $config.witnesstarget.common.ip -Confirm:$false
    }

    LogMessage -Type NOTE -Message "Verifying Infrastructure: COMPLETED"

}

Function Test-ESXiHosts2nodeFiles {
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath
    )
    
    $vcsaISO = Get-ChildItem $binaryPath -Filter *VCSA* | ForEach-Object { $_.FullName }
    if ($vcsaISO) {
        LogMessage -type INFO -message "Checking binaries folder for VCSA ISO: SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Cloud not find VCSA ISO: FAILURE"
    }

    $vcsaISO = Get-ChildItem $binaryPath -Filter *VMware-vSAN-ESA-Witness* | ForEach-Object { $_.FullName }
    if ($vcsaISO) {
        LogMessage -type INFO -message "Checking binaries folder for ESA Witness OVA: SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "Cloud not find ESA Witness OVA: FAILURE"
    }
    
    LogMessage -Type NOTE -Message "Verifying required files: COMPLETED"
}

#######################################################################################################################
#Region                                         S U P P O R T I N G                                         ###########

Function New-mountVCSAIso () {
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath
        )

    #locate the ESXi installable
    $vcsaISO = Get-ChildItem $binaryPath -Filter *VCSA* | ForEach-Object { $_.FullName }
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

Function Get-VMToolsStatus {
    <#
        .SYNOPSIS
        Gets the VM tools status of a VM

        .PARAMETER vmName
        The Name of the VM

        .EXAMPLE
        Get-VMToolsStatus -vmName MySpecialVM

        .NOTES
        Author: Ken Gould
        Github: https://github.com/feardamhan
    #>
    Param (
        [Parameter (mandatory = $true)] [String]$vmName
    )

    $vmView = Get-View -ViewType VirtualMachine -Filter @{'Name' = $vmName }
    $vmToolStatus = $vmView.Guest.ToolsStatus
    Return $vmToolStatus
}

#######################################################################################################################
#Region                                         D E P L O Y M E N T                                         ###########

Function Start-vSANWitnessDeployment {
    <#
        .SYNOPSIS
        Wrapper to deploy the vSAN witness.

        .PARAMETER jsonPath
        Path to the JSON folder.

        .PARAMETER binaryPath
        Path to the Binaries folder.

        .EXAMPLE
        Start-vSANWitnessDeployment jsonPath '.\json\' -binaries '.\binaries\'

        .NOTES

        Author : Kim Johansson
        Github: https://github.com/maxiepax
    #>
    Param (
        [Parameter (Mandatory = $true)] [Object]$binaryPath,
        [Parameter (Mandatory = $true)] [Object]$jsonPath
        )

    $config = Get-deploymentConfig -jsonPath $jsonPath

    $deploymentSpec = @{
        'witnessHostUsername' = $config.witnesstarget.common.user
        'witnessHostPassword' = $config.witnesstarget.common.password
        'witnessHostDatastore' = $config.witnesstarget.common.datastore
        'witnessHostPortGroup' = $config.witnesstarget.common.portgroup_name
        'witnessVMHostname' = $config.vsanwitness.hostname
        'witnessVMName' = $config.vsanwitness.vm_name
        'witnessVMIP' = $config.vsanwitness.ip
        'witnessVMNetmask' = $config.vsanwitness.netmask
        'witnessVMGateway' = $config.vsanwitness.gateway
        'witnessVMPassword' = $config.vsanwitness.password
        'dnsdomain' = $config.global.dnssearch
        'vcenterPassword' = $config.vcenter.sso_administrator_password
        'datacenter' = $config.vcenter.datacenter
    }

    if ($config.witnesstarget.common.fqdn) {
        #use FQDN instead of IP
        $deploymentSpec.Add('witnessTarget', $config.witnesstarget.common.fqdn)
    } else {
        $deploymentSpec.Add('witnessTarget', $config.witnesstarget.common.ip)
    }

    if ($config.vsanwitness.fqdn) {
        #use FQDN instead of IP
        $deploymentSpec.Add('witnessVMFQDN', $config.vsanwitness.fqdn)
    } else {
        $deploymentSpec.Add('witnessVMFQDN', $config.vsanwitness.ip)
    }

    if ($config.vcenter.mgmt.fqdn) {
        #use FQDN instead of IP
        $deploymentSpec.Add('vcenter', $config.vcenter.mgmt.fqdn)
    } else {
        $deploymentSpec.Add('vcenter', $config.vcenter.mgmt.ip)
    }

    $dns = ""
    if ($config.global.dns01) { $dns = $config.global.dns01 }
    if ($config.global.dns01 -And $config.global.dns02) { $dns = "$dns,$($config.global.dns02)" }
    $deploymentSpec.Add('dns', $dns)

    $ntp = ""
    if ($config.global.ntp01) { $ntp = $config.global.ntp01 }
    if ($config.global.ntp01 -And $config.global.ntp02) { $ntp = "$ntp,$($config.global.ntp02)" }
    $deploymentSpec.Add('ntp', $ntp)

    if ($config.witnesstarget.vcenter.datacenter -And $config.witnesstarget.vcenter.cluster) { 
        #Will deploy to vCenter
        $connectionString = "vi://$($deploymentSpec.witnessHostUsername):$($deploymentSpec.witnessHostPassword)@$($deploymentSpec.witnesstarget)/$($config.vsanwitness.vcenter.datacenter)/host/$($config.vsanwitness.vcenter.cluster)/"
        $deploymentSpec.Add('connectionString', $connectionString)
    } else {
        #will deploy to ESXi
        $connectionString = "vi://$($deploymentSpec.witnessHostUsername):$($deploymentSpec.witnessHostPassword)@$($deploymentSpec.witnesstarget)"
        $deploymentSpec.Add('connectionString', $connectionString)
    }   

    LogMessage -Type NOTE -Message "Building Deployment Specification: SUCCESSFULL"

    Write-Output $deploymentSpec

    New-VSANWitnessDeployment -witnessProp $deploymentSpec -binaries $binaryPath
    
}

Function New-VSANWitnessDeployment {
    <#
        .SYNOPSIS
        Deploys a new vSAN Witness to target ESXi or vCenter

        .PARAMETER witnessProp
        Properties required by the unattended deployment.

        .PARAMETER binaries
        Path to the folder where the VCSA ISO is located.

        .EXAMPLE
        New-VSANWitnessDeployment -witnessProp $properties -binaries $binaries

        .NOTES
        Original Author: Ken Gould
        Github: https://github.com/feardamhan

        Modified by: Kim Johansson
        Github: https://github.com/maxiepax
    #>
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
    } else {
        LogMessage -type ERROR -message "VSAN Witness OVA with Build $witnessBuild not found"
        anykey
        Break
    }
    #Environment Details

    $datastoreName = $witnessProp.witnessHostDatastore
    $dns = $witnessProp.dns
    $dnsDomain = $witnessProp.dnsdomain
    $ntp = $witnessProp.ntp

    #Appliance Details

    $hostname = $witnessProp.witnessVMHostname
    $vmName = $witnessProp.witnessVMName
    $ipAddress0 = $witnessProp.witnessVMIP
    $netmask0= $witnessProp.witnessVMNetmask
    $gateway0 = $witnessProp.witnessVMGateway
    $vsannetwork = "Management"
    $portgroup = $witnessProp.witnessHostPortGroup 

    $verifyCommand = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --verifyOnly --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --powerOn --name="' + $vmName + '" --vmFolder="" --net:"Management Network=' + $portgroup + '" --net:"Secondary Network=' + $portgroup +'" --datastore="' + $datastoreName +'" --X:injectOvfEnv --prop:guestinfo.hostname="' + $hostname +'" --prop:guestinfo.ipaddress0="' + $ipAddress0 + '" --prop:guestinfo.netmask0="' + $netmask0 + '" --prop:guestinfo.gateway0="' + $gateway0 + '" --prop:guestinfo.dns="' + $dns + '" --prop:guestinfo.dnsDomain="' + $dnsDomain + '" --prop:guestinfo.ntp="' + $ntp +'" --prop:guestinfo.passwd="' + $witnessProp.witnessVMPassword + '" --prop:guestinfo.vsannetwork="' + $vsannetwork + '" "' + $applianceOVA + '" "' + $witnessProp.connectionString + '"'
    $command = '"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe" --noSSLVerify --acceptAllEulas --allowAllExtraConfig --diskMode=thin --powerOn --name="' + $vmName + '" --vmFolder="" --net:"Management Network=' + $portgroup + '" --net:"Secondary Network=' + $portgroup +'" --datastore="' + $datastoreName +'" --X:injectOvfEnv --prop:guestinfo.hostname="' + $hostname +'" --prop:guestinfo.ipaddress0="' + $ipAddress0 + '" --prop:guestinfo.netmask0="' + $netmask0 + '" --prop:guestinfo.gateway0="' + $gateway0 + '" --prop:guestinfo.dns="' + $dns + '" --prop:guestinfo.dnsDomain="' + $dnsDomain + '" --prop:guestinfo.ntp="' + $ntp +'" --prop:guestinfo.passwd="' + $witnessProp.witnessVMPassword + '" --prop:guestinfo.vsannetwork="' + $vsannetwork + '" "' + $applianceOVA + '" "' + $witnessProp.connectionString + '"'
   
    #Deploy Appliance
    Connect-VIServer -server $witnessProp.witnessTarget -user $witnessProp.witnessHostUsername -pass $witnessProp.witnessHostPassword -ErrorAction SilentlyContinue | Out-Null

    LogMessage -Type INFO -Message "Pre-validating witness deployment"
    $verifyWitness = Invoke-Expression "& $verifyCommand"
    If ($verifyWitness[-1] -eq "Completed successfully") {   
        LogMessage -Type INFO -Message "Pre-validation of witness deployment: SUCCESSFUL"
        $command | Out-File $logFile -encoding ASCII -append
        LogMessage -Type INFO -Message "Deploying vSAN Witness Appliance to $($witnessProp.witnessTarget)"
        Invoke-Expression "& $command" | Out-File $logFile -Encoding ASCII -Append
        LogMessage -Type WAIT -Message "[$vmName] Waiting for VM Tools to start"
        Do {
            $toolsStatus = Get-VMToolsStatus -vmname $vmName
        } Until (($toolsStatus -eq "toolsOld") -OR ($toolsStatus -eq "toolsOk"))
        Start-Sleep 60
        Disconnect-VIserver $witnessProp.witnessTarget -Confirm:$false

        LogMessage -Type WAIT -Message "[$vmName] Waiting for Management Interface to be reachable"
        Do {} Until (Test-SilentNetConnection -ComputerName $ipaddress0)

        Connect-VIServer -server $witnessProp.vcenter -user administrator@vsphere.local -Password $witnessProp.vcenterPassword | Out-Null
        LogMessage -Type INFO -Message "[$vmName] Adding Host to vCenter"
        Add-VMHost -Name $witnessProp.witnessVMFQDN -Location $witnessProp.datacenter -user root -password $witnessProp.witnessVMPassword -Force | Out-Null
        LogMessage -Type WAIT -Message "Allowing vCenter Inventory to Synchronize"
        Start-Sleep 90

        #Remove VMK1
        LogMessage -Type INFO -Message "[$vmName] Removing vmk1"
        Get-VMHost $witnessProp.witnessVMFQDN | Get-VMHostNetworkAdapter -Name vmk1 | Remove-VMHostNetworkAdapter -Confirm:$false
        #Remove Virtual Switch
        LogMessage -Type INFO -Message "[$vmName] Removing secondarySwitch"
        Get-VMHost $witnessProp.witnessVMFQDN | Get-VirtualSwitch -name "secondarySwitch" | Remove-VirtualSwitch -confirm:$false
    
        Disconnect-VIServer * -Force -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        LogMessage -Type NOTE -Message "Deploying vSAN witness: SUCCESSFUL"
    }
     else
    {
        Disconnect-VIServer -Server $witnessTarget
        LogMessage -Type ERROR -Message "Deployment pre-validation of Witness failed. Please ensure the OVA was successfully staged to binaries folder."
        anyKey
        Break
    }
  
    LogMessage -Type NOTE -Message "Deployment and configuration of vSAN Witness: COMPLETED"

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
    if ($verifyTemplate| Where-Object {$_ -match "failed"}) {
            LogMessage -type INFO -message "VCSA Template verification: FAILED"
            LogMessage -type INFO -message "DEBUG: $($verifyTemplateCommand)"
            break
    } else {
        LogMessage -type INFO -message "VCSA Template verification: SUCCESSFUL"
        $verifyPrecheck = Invoke-Expression "& $verifyPrecheckCommand"
        if ($verifyPrecheck| Where-Object {$_ -match "failed"}) {
            LogMessage -type INFO -message "VCSA Precheck verification: FAILED"
            LogMessage -type INFO -message "DEBUG: $($verifyPrecheckCommand)"
            break
        } else {
            LogMessage -type INFO -message "VCSA Precheck verification: SUCCESSFUL"
            LogMessage -type INFO -message "Starting deployment of VCSA: SUCCESSFUL"
            Invoke-Expression "& $deployCommand" | Out-File $logFile -Encoding ASCII -Append
        }
    }
    LogMessage -type NOTE -message "VCSA deployment: COMPLETED"
      
}

#######################################################################################################################
#Region                                   C O N F I G U R A T I O N                                         ###########

Function Start-JoinAdditionalESXiHosts {
    Param (
        [Parameter (Mandatory = $true)] [Object]$jsonPath
        )
        
    $config = Get-deploymentConfig -jsonPath $jsonPath

    Connect-VIServer -server $config.vcenter.mgmt.ip -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    foreach ($esxihost in $config.hosts) {
        if ($esxihost.mgmt.fqdn) {
            if (Get-VMHost -Name $esxihost.mgmt.fqdn) {
                LogMessage -type WARNING -message "Host $($esxihost.mgmt.fqdn) already added to cluster: SKIPPING"
            } else { 
                Add-VMHost -Name $esxihost.mgmt.fqdn -Location $config.vcenter.cluster -User $esxihost.user -Password $esxihost.password -Force
                LogMessage -type INFO -message "Host $($esxihost.mgmt.fqdn) added to cluster: SUCCESSFUL"
            }
        } else {
            if (Get-VMHost -Name $esxihost.mgmt.ip) {
                LogMessage -type WARNING -message "Host $($esxihost.mgmt.ip) already added to cluster: SKIPPING"
            } else { 
                Add-VMHost -Name $esxihost.mgmt.ip -Location $config.vcenter.cluster -User $esxihost.user -Password $esxihost.password -Force
                LogMessage -type INFO -message "Host $($esxihost.mgmt.ip) added to cluster: SUCCESSFUL"
            }
        }
    }
    Disconnect-VIServer -server $config.vcenter.mgmt.ip -Confirm:$false
}

Function Start-CreatevDSdelvSS {
    Param (
        [Parameter (Mandatory = $true)] [Object]$jsonPath
        )
        
    $config = Get-deploymentConfig -jsonPath $jsonPath

    if ($config.vcenter.mgmt.fqdn) {
        Connect-VIServer -server $config.vcenter.mgmt.fqdn -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    } else {
        Connect-VIServer -server $config.vcenter.mgmt.ip -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    }
    
    $datacenter = Get-Datacenter -Name $config.vcenter.datacenter
    if($datacenter) {
        LogMessage -type INFO -message "Found $($datacenter) object: SUCCESSFUL"
    } else {
        LogMessage -type INFO -message "Could not find the datacenter object called $($config.vcenter.datacenter): SUCCESSFUL"
        break
    }
    
    $hosts = Get-Cluster -Name $config.vcenter.cluster | Get-VMHost
    if($hosts) {
        foreach ($esxihost in $hosts) { 
            LogMessage -type INFO -message "Found $($esxihost) eligeable to join the switch: SUCCESSFUL"
        }
    } else {
        LogMessage -type INFO -message "Could not find any hosts eligeable to join the switch: SUCCESSFUL"
        break
    } 
    
    if((Get-VDSwitch -Location $datacenter).Name -eq $config.vcenter.dvswitch.name) {
        LogMessage -type WARNING -message "Distributed vSwitch already exists: SKIPPING"
    } else {
        $dvs = New-VDSwitch -Name $config.vcenter.dvswitch.name -Location $datacenter
        if(($dvs).Name -eq $config.vcenter.dvswitch.name) {
            LogMessage -type INFO -message "Creating Distributed vSwitch: SUCCESSFUL"
        } else {
            LogMessage -type ERROR -message "Creating Distributed vSwitch: FAILED"
            break
        }

        Get-VDSwitch -Name $config.vcenter.dvswitch.name | Set-VDSwitch -Mtu $config.vcenter.dvswitch.mtu | Out-Null
        LogMessage -type INFO -message "Setting Distributed vSwitch MTU to $($config.vcenter.dvswitch.mtu): SUCCESSFUL"

        foreach ($pg in $config.vcenter.dvswitch.portgroups) { 
            LogMessage -type INFO -message "Creating portgroup $($pg.name) with vlan $($pg.vlan): SUCCESSFUL"
            $dvs | New-VDPortgroup -Name $pg.name -VLanId $pg.vlan
        }
        
        $dvsnic = $hosts | Get-VMHostNetworkAdapter -Name $config.vcenter.dvswitch.second_uplink
        if($dvsnic){
            foreach ($nic in $dvsnic) { 
                LogMessage -type INFO -message "Found $($nic) to be joined to the switch: SUCCESSFUL"
            }
        } else {
            LogMessage -type ERROR -message "Could not find $($nic) to be joined to the switch: FAILED"
            break
        }
        
        Add-VDSwitchVMHost -VDSwitch $dvs -VMHost $hosts
        LogMessage -type INFO -message "Adding hosts to the switch: SUCCESSFUL"

        foreach ($esxihost in $hosts) {
            $esxi = Get-VMHost -Name $esxihost.Name
            $pnic = Get-VMHostNetworkAdapter -VMHost $esxi -Name $config.vcenter.dvswitch.second_uplink
            $vmk0 = Get-VMHostNetworkAdapter -VMHost $esxi -Name "vmk0"
            LogMessage -type INFO -message "[$($esxihost.Name)] Finding vmk0: SUCCESSFUL"
            $dvs | Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $pnic -VMHostVirtualNic $vmk0 -VirtualNicPortgroup 'management' -Confirm:$false
            LogMessage -type INFO -message "[$($esxihost.Name)] Adding uplink $($dvsnic) and migrating vmk0: SUCCESSFUL"
        }
       
        LogMessage -type INFO -message "Done adding uplinks and migrating management vmkernel: SUCCESSFUL"
    }

    if((Get-Cluster -Name $config.vcenter.cluster | Get-VM -Name $config.vcenter.vm_name | Get-NetworkAdapter).NetworkName -eq "VM Network") {
        Get-Cluster -Name $config.vcenter.cluster | Get-VM -Name $config.vcenter.vm_name | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName "management" -Confirm:$false
        LogMessage -type INFO -message "Migrating vCenter to Distributed vSwitch: SUCCESSFUL"
    } else {
        LogMessage -type WARNING -message "vCenter already migrated to Distributed vSwitch: SKIPPING"
    }

    foreach ($esxihost in $hosts) {
        LogMessage -type INFO -message "[$($esxihost.Name)] Preparing to remove vSwitch0"
        $vswitch = Get-VirtualSwitch -Name "vSwitch0" -VMhost $esxihost.Name
        if($vswitch) {
            LogMessage -type INFO -message "[$($esxihost.Name)] Deleting vSwitch0: SUCCESSFUL"
            Remove-VirtualSwitch -VirtualSwitch $vswitch -Confirm:$false
        } else {
            LogMessage -type WARNING -message "[$($esxihost.Name)] Could not find vSwitch0: SKIPPING"
        }

        $first_pnic = Get-VMhost -Name $esxihost.Name | Get-VMHostNetworkAdapter -Name $config.vcenter.dvswitch.first_uplink
        Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $first_pnic -DistributedSwitch $dvs -Confirm:$false
        LogMessage -type INFO -message "[$($esxihost.Name)] adding $($config.vcenter.dvswitch.first_uplink) to Distributed Switch: SUCCESSFUL"
    }

    Disconnect-VIServer -server $config.vcenter.mgmt.ip -Confirm:$false
}

Function Start-ConfigureEsxiHosts {
    Param (
        [Parameter (Mandatory = $true)] [Object]$jsonPath
    )
    $config = Get-deploymentConfig -jsonPath $jsonPath
    
    if ($config.vcenter.mgmt.fqdn) {
        Connect-VIServer -server $config.vcenter.mgmt.fqdn -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    } else {
        Connect-VIServer -server $config.vcenter.mgmt.ip -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    }

    foreach ($esxihost in $config.hosts) {  
        $esx = Get-VMhost -Name $esxihost.mgmt.ip
        $switch = Get-VirtualSwitch -VMhost $esx -Name $config.vcenter.dvswitch.name

        if(Get-VMHost -Name $esx | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.vMotionEnabled}) {
            LogMessage -type WARNING -message "[$($esx.Name)] VMotion interface with ip $($esxihost.vmotion.ip) and netmask $($esxihost.vmotion.netmask) with mtu $($esxihost.vmotion.mtu) exists: SKIPPING"
        } else {
            New-VMHostNetworkAdapter -VMHost $esx -PortGroup 'vmotion' -VirtualSwitch $switch -Mtu $esxihost.vmotion.mtu -VMotionEnabled:$true -IP $esxihost.vmotion.ip -SubnetMask $esxihost.vmotion.netmask | Out-Null
            LogMessage -type INFO -message "[$($esx.Name)] Adding VMotion interface with ip $($esxihost.vmotion.ip) and netmask $($esxihost.vmotion.netmask) with mtu $($esxihost.vmotion.mtu): SUCCESSFUL"
        }

        if(Get-VMHost -Name $esx | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VsanTrafficEnabled}) {
            LogMessage -type WARNING -message "[$($esx.Name)] vSAN interface with ip $($esxihost.vsan.ip) and netmask $($esxihost.vsan.netmask) with mtu $($esxihost.vsan.mtu) exists: SKIPPING"
        } else {
            New-VMHostNetworkAdapter -VMHost $esx -PortGroup 'vsan' -VirtualSwitch $switch -Mtu $esxihost.vsan.mtu -VsanTrafficEnabled $true -IP $esxihost.vsan.ip -SubnetMask $esxihost.vsan.netmask | Out-Null
            LogMessage -type INFO -message "[$($esx.Name)] Adding vSAN interface with ip $($esxihost.vsan.ip) and netmask $($esxihost.vsan.netmask) with mtu $($esxihost.vsan.mtu): SUCCESSFUL"
        }

        $esxcli = Get-EsxCli -VMHost $esx
        $wts_set = $esxcli.vsan.network.list() | Where-Object VmkNicName -eq vmk0 | Select-Object TrafficType
        if($wts_set) {
            LogMessage -type WARNING -message "[$($esx.Name)] Witness Traffic Separation already set to interface vmk0: WARNING"

        } else {
            Get-VMHost -Name $esx | Get-EsxCli -v2 | ForEach-Object {$_.vsan.network.ip.add.Invoke(@{traffictype='witness';interfacename='vmk0'})}
            LogMessage -type INFO -message "[$($esx.Name)] Adding Witness Traffic Separation to interface vmk0: SUCCESSFUL"
        }

        if($config.global.dns01) {
            if(((Get-VMhost -Name 10.11.11.101 | ForEach-Object { $_ | Select-Object Name, @{N="DNSAddress";E={($_ | Get-VMhostNetwork).DNSAddress -join "," }} }).DNSAddress) -eq "$($config.global.dns01),$($config.global.dns02)"){
                LogMessage -type WARNING -message "[$($esx.Name)] DNS already configured: SKIPPING"
            } else {
                Get-VMHostNetwork -VMHost $esx | Set-VMHostNetwork -DomainName $config.global.dnssearch -DNSAddress $config.global.dns01 , $config.global.dns02 -Confirm:$false
                LogMessage -type INFO -message "[$($esx.Name)] Configuring DNS settings to primary dns $($config.global.dns01), secondary dns $($config.global.dns02), and search $($config.global.dnssearch): SUCCESSFUL"
            }
        }

        if($config.global.ntp01) {
            if(Get-VMHost -Name $esx  | Get-VMHostNtpServer | Select-String -Pattern $config.global.ntp01) {
                LogMessage -type WARNING -message "[$($esx.Name)] NTP already configured: SKIPPING"
            } else {
                Add-VMHostNTPServer -NtpServer $config.global.ntp01 , $config.global.ntp02 -VMHost $esx -Confirm:$false
                LogMessage -type INFO -message "[$($esx.Name)] Configuring NTP settings to primary ntp $($config.global.dns01), secondary ntp $($config.global.dns02): SUCCESSFUL"
                Get-VMHost -name $esx | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "on" | Out-Null
                LogMessage -type INFO -message "[$($esx.Name)] Enabling NTP Service: SUCCESSFUL"
                Get-VMHostFirewallException -VMHost $esx | Where-Object {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true | Out-Null
                LogMessage -type INFO -message "[$($esx.Name)] Allowing NTP Traffic through firewall: SUCCESSFUL"
                Get-VMHostService -VMHost $esx | Where-Object {$_.Key -eq "ntpd"} | Restart-VMHostService -Confirm:$false | Out-Null
                LogMessage -type INFO -message "[$($esx.Name)] Restarting NTP Service: SUCCESSFUL"
            }
        }

        if($config.global.syslog){
            if (((Get-VMHostSysLogServer -VMHost $esx) | Select-Object *,@{N='syslog';E={$_.Host,$_.Port -join ':'}}).syslog -eq $config.global.syslog) {
                LogMessage -type WARNING -message "[$($esx.Name)] Syslog already configured: SKIPPING"
            } else {
                $esx | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value $config.global.syslog -Confirm:$false | Out-Null
                LogMessage -type INFO -message "[$($esx.Name)] Configuring syslog to $($config.global.syslog): SUCCESSFUL"
                $esxcli = Get-EsxCli -VMHost $esx
                $esxcli.system.syslog.reload()
                LogMessage -type INFO -message "[$($esx.Name)] reloading syslog: SUCCESSFUL"
            }
        }
    }

    LogMessage -type INFO -message "[$($config.vcenter.cluster)] Setting SSH startup policy to disabled: SUCCESSFUL"
    Get-VMhost | get-vmhostservice | where-object {$_.key -eq "TSM-SSH"} | set-vmhostservice -policy "Off"

    LogMessage -type INFO -message "[$($config.vcenter.cluster)] Turning off SSH: SUCCESSFUL"
    Get-VMhost | get-VMHostService | where-object {$_.Label -eq "SSH"} | Stop-VMHostService -Confirm:$false

    LogMessage -type INFO -message "[$($config.vcenter.cluster)] Setting SSH startup policy to disabled: SUCCESSFUL"
    get-vmhost | get-vmhostservice | where-object {$_.key -eq "TSM"} | set-vmhostservice -policy "Off"

    LogMessage -type INFO -message "[$($config.vcenter.cluster)] Turning off SSH: SUCCESSFUL"
    get-vmhost | get-vmhostservice | where-object {$_.key -eq "TSM"} | Stop-VMHostService -Confirm:$false


    Disconnect-VIServer -server $config.vcenter.mgmt.ip -Confirm:$false
    LogMessage -type NOTE -message "Configuring hosts: COMPLETED"

}

Function Start-ConfigureTwoNodevSANwithWitness {
    Param (
        [Parameter (Mandatory = $true)] [Object]$jsonPath
    )

    $config = Get-deploymentConfig -jsonPath $jsonPath
    
    if ($config.vcenter.mgmt.fqdn) {
        Connect-VIServer -server $config.vcenter.mgmt.fqdn -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    } else {
        Connect-VIServer -server $config.vcenter.mgmt.ip -user administrator@vsphere.local -pass $config.vcenter.sso_administrator_password -ErrorAction SilentlyContinue | Out-Null
    }

    $cluster = Get-Cluster -Name $config.vcenter.cluster
    if ($cluster.ExtensionData.HciConfig.WorkflowState -eq "in_progress")
    {
        LogMessage -type INFO -message "[$($config.vcenter.cluster)] Disabling Quickstart"
        $Cluster.ExtensionData.AbandonHciWorkflow()
    }

    LogMessage -type INFO -message "[$($config.hosts[1].mgmt.ip)] Gathering list of disks to be used by vSAN"
    $disks = Get-vSANCompatibleDrives -esxihost $config.hosts[1].mgmt.ip -password $config.hosts[1].password

    foreach ($disk in $disks) {
        Add-VsanStoragePoolDisk -VMHost (Get-VMHost $config.hosts[1].mgmt.ip) -VsanStoragePoolDiskType "singleTier" -DiskCanonicalName $disk.Device | Out-Null
        LogMessage -type INFO -message "[$($config.hosts[1].mgmt.ip)] Added disk $($disk.Device)"
    }

    $witness = Get-VMhost -name $config.vsanwitness.ip
    $cluster = Get-Cluster -Name $config.vcenter.cluster
    $primary_fd = New-VsanFaultDomain -Name 'Preferred' -VMHost $config.hosts[0].mgmt.ip
    New-VsanFaultDomain -Name 'Secondary' -VMHost $config.hosts[1].mgmt.ip | Out-Null
    Set-VsanClusterConfiguration -Configuration $cluster -StretchedClusterEnabled $true -PreferredFaultDomain $primary_fd -WitnessHost $witness -PerformanceServiceEnabled:$true -Confirm:$false | Out-Null
    
    #$vmhost = Get-Vmhost $config.vsanwitness.ip
    #$spec=Initialize-SettingsHostsEnablementSoftwareEnableSpec -SkipSoftwareCheck $false
    #Invoke-SetHostEnablementSoftwareAsync -Host $vmhost.ExtensionData.MoRef.Value -SettingsHostsEnablementSoftwareEnableSpec $spec
    #LogMessage -type INFO -message "[$($config.vsanwitness.ip)] Switching Witness to use vLCM Image: SUCCESSFUL"

    #$build = Get-VMHost -Name $config.vsanwitness.ip | Select-Object Build
    #$desiredBuild = Get-LCMImage -Type 'BaseImage' | Where-Object { $_.Version -Like "*$($build.Build)" }    
    #$desiredImage = Get-LCMImage -Version $desiredBuild.Version -Type BaseImage
   <#
   .SYNOPSIS
   Short description
   
   .DESCRIPTION
   Long description
   
   .PARAMETER jsonPath
   Parameter description
   
   .EXAMPLE
   An example
   
   .NOTES
   General notes
   #>Get-VMHost -Name $config.vsanwitness.ip | Set-VMHost -BaseImage $desiredImage
}