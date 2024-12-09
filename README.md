# Power ROBO
An poweshell based automation to quickly spin up VMware based edge deployments. The automation gathers the information specified by you in the settings.json file, it then uses these values to provide a few menu options to quickly deploy a edge site.

Choose between two options, 2-node with witness, or 3+ node deployment.

# 2-node with witness
This option requires you to have two ESXi nodes backed by a Switch fabric that provides Management, VMotion, and vSAN VLANs.
Along with either a 3rd ESXi host that can host the Witness VM, or a remote vCenter with cluster that could house multiple Witness VMs.
<img width="613" alt="image" src="https://github.com/user-attachments/assets/bf610848-9899-43b0-9ac7-073880a82709">

# 3+ nodes without witness (not ready yet)
This option does not require a witness but still handles the generation of files, and deployment of vcenter, and automation of configuring the cluster.
<img width="551" alt="image" src="https://github.com/user-attachments/assets/55522486-515b-43ec-85b9-e174864ac24c">


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
