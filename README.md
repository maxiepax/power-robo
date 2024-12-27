# Power ROBO
An poweshell based automation to quickly spin up VMware based edge deployments. The automation gathers the information specified by you in the settings.json file, it then uses these values to provide a few menu options to quickly deploy a edge site.

Choose between two options, 2-node with witness, or multi node deployment.

## Supported topologies

### 2-node with witness
This option requires you to have two ESXi nodes backed by a Switch fabric that provides Management, VMotion, and vSAN VLANs.
Along with either a 3rd ESXi host that can host the Witness VM, or a remote vCenter with cluster that could house multiple Witness VMs.
<img width="803" alt="image" src="https://github.com/user-attachments/assets/c81c03fe-9716-47dc-9ddf-a238fe3ccceb" />


### 3+ nodes without witness
This option does not require a witness but still handles the generation of files, and deployment of vcenter, and automation of configuring the cluster.

<img width="562" alt="image" src="https://github.com/user-attachments/assets/c9dad6af-745b-4169-bb1f-6410f00fe421" />


## pre-requirements

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
In the /json folder, modify the settings.json to your liking. You can choose to not use dns/fqdn, or use fqdn. If you're using 2-node simply ignore all host objects but the top two, if you need more than three just add more. <br/>
If you're not doing a witness deployment, just ignore the witness inputs. <br/>
run the cmd: start-powerRoboMenu -jsonPath .\json\ -binaryPath .\binaries\ -logFile .\logs\robo.log <br/>
Step through the menu items ensuring that they complete successfully.
