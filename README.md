# Power ROBO
An poweshell based automation to quickly spin up VMware based edge deployments. The automation gathers the information specified by you in the settings.json file, it then uses these values to provide a few menu options to quickly deploy a edge site.

Choose between two options, 2-node with witness, or 3+ node deployment.

# 2-node with witness
This option requires you to have two ESXi nodes backed by a Switch fabric that provides Management, VMotion, and vSAN VLANs.
Along with either a 3rd ESXi host that can host the Witness VM, or a remote vCenter with cluster that could house multiple Witness VMs.
<img width="613" alt="image" src="https://github.com/user-attachments/assets/bf610848-9899-43b0-9ac7-073880a82709">

# 3+ nodes without witness (not ready yet)
This option does not require a witness but still handles the generation of files, and deployment of vcenter, and automation of configuring the cluster.

<img width="610" alt="image" src="https://github.com/user-attachments/assets/4dcd3f28-1b08-43c1-b05b-990b8d0aa8a1">


# pre-requirements

required dependencies:
```
Install-Module -Name VMware.PowerCLI
Install-Module -Name VMware.Sdk.vSphere.Esx.Settings required
Install-Module -Name VMware.Sdk.vSphere.Cis
```

## host requirements
ESXi has to be installed, management vmkernel has to be configured with a valid IP, netmask, gateway and VLAN ID. The Portgroup "VM Network" requries to have the same VLAN ID during the installation.

## network requirements
The Switches need to be configured with the networks Management, VMotion, and vSAN. These should all have a highly available gateway (VRRP/HSRP). The password for the ESXi hosts needs to be known.

## Usage
Pull the github repo to a folder. <br/>
Place the VCSA .iso, and vSAN ESA Witness .ova in the /binaries folder. <br/>
In the /json folder, modify the settings.json to your liking. You can choose to not use dns/fqdn, or use fqdn. <br/>
run the cmd: start-powerRoboMenu -jsonPath .\json\ -binaryPath .\binaries\ -logFile .\logs\robo.log <br/>
Step through the menu items ensuring that they complete successfully.
