# Openshift vSphere Install
Automated environment for spinning up OCP on VSphere lab

## `govc` notes

```bash
govc version
# govc 0.27.5

govc about
# FullName:     VMware vCenter Server 7.0.3 build-**19717403**
# Name:         VMware vCenter Server
# Vendor:       VMware, Inc.
# Version:      7.0.3
# ...

govc datacenter.info
# Name:                Your Datacenter
#   Path:              /Your Datacenter
#   Hosts:             4
#   Clusters:          1
#   Virtual Machines:  6
#   Networks:          1
#   Datastores:        1

govc ls
# /Your Datacenter/vm
# /Your Datacenter/network
# /Your Datacenter/host
# /Your Datacenter/datastore

govc find -h
#   a    VirtualApp
#   c    ClusterComputeResource
#   d    Datacenter
#   f    Folder
#   g    DistributedVirtualPortgroup
#   h    HostSystem
#   m    VirtualMachine
#   n    Network
#   o    OpaqueNetwork
#   p    ResourcePool
#   r    ComputeResource
#   s    Datastore
#   w    DistributedVirtualSwitch
# ...

# Store datacenter name
dc=$(govc ls /)
# /Your Datacenter

# List all VMs
govc ls /*/vm/*/*/*
# /Your Datacenter/vm/Foo/Bar/OCPLab_Templates/OCPLab-WS2022
# /Your Datacenter/vm/Foo/Bar/OCPLab_VMs/OCPLab-DEV-1
# /Your Datacenter/vm/Foo/Bar/OCPLab_VMs/OCPLab-DC1

# List network
govc ls /*/network
# /Your Datacenter/network/DataSvc PG VM Network PG (VLAN 106)

# List ClusterComputeResource
govc ls -t ClusterComputeResource host
# /Your Datacenter/host/ArcLab Workload Cluster

# Find templates in a specific folder
template_folder="ArcLab CL Templates"
govc find $dc/vm/$template_folder -type m 

# Get everything back as json
govc object.collect -json 
```

> `#TODO` - automate deployment of DC + DEV1 via Terraform or `govc`, bootstrap scripts and sequence etc

---

# Domain Controller/DNS/DHCP installation

## Re-imaging prep

```powershell
# Turn off firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Enable remote desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

## `OCPLab-DC1`

We do a straightforward deploy, no Customizations (we will rename in RDP just for this one):

![Deploy](_images/3.png)

### Rename machine
```powershell
$vmName = "OCPLab-DC1"
$password = ConvertTo-SecureString 'acntorPRESTO!' -AsPlainText -Force
$localhostAdminUser = New-Object System.Management.Automation.PSCredential ('Administrator', $password)
Rename-Computer -NewName $vmName -LocalCredential $localhostAdminUser -Restart
# Reboots
```

### Set Static IP Address

Make sure to **trigger this whole script from ISE**, because RDP will get booted:

```powershell
# In case we want to start with a DHCP assigned range
# $IP = (Get-NetIPAddress | Where-Object {$_.AddressState -eq "Preferred" -and $_.ValidLifetime -lt "24:00:00"}).IPAddress

# Start with an IP that we manually test is empty - i.e. ping $IP
$IP = "10.216.175.4"
$MaskBits = 24 # This means subnet mask = 255.255.255.0 - http://jodies.de/ipcalc?host=255.255.255.0&mask1=24&mask2=
$Gateway = (Get-NetIPConfiguration | Foreach IPv4DefaultGateway | Select NextHop)."NextHop"
$DNS = "127.0.0.1"
$IPType = "IPv4"

# Retrieve the network adapter that you want to configure
$adapter = Get-NetAdapter | ? {$_.Status -eq "up"}

# Remove any existing IP, gateway from our ipv4 adapter
If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
 $adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
}
If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
 $adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
}

 # Configure the IP address and default gateway
$adapter | New-NetIPAddress `
 -AddressFamily $IPType `
 -IPAddress $IP `
 -PrefixLength $MaskBits `
 -DefaultGateway $Gateway

# Configure the DNS client server IP addresses
$adapter | Set-DnsClientServerAddress -ServerAddresses $DNS

# Reconnect RDP from Laptop with MSFTVPN - should work at 10.216.175.4
```
For example - we see:
![Result](_images/1.png)

### Upgrade to a Domain Controller

```powershell
# Configure the Domain Controller
$domainName = 'fg.contoso.com'
$domainAdminPassword = "acntorPRESTO!"
$secureDomainAdminPassword = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Create Active Directory Forest
Install-ADDSForest `
    -DomainName "$domainName" `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "7" `
    -DomainNetbiosName $domainName.Split('.')[0].ToUpper() `
    -ForestMode "7" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true `
    -SafeModeAdministratorPassword $secureDomainAdminPassword

# Reboots - takes 2-3 mins at "Please wait for the Group Policy Client" - it's normal for GPO Policiy initialization
```

Now we can sign-in as Domain Admin `fg\Administrator` to RDP.

### Install DHCP on the Domain Controller

```powershell
$dnsServerIP = (Get-NetIPAddress | Where-Object {$_.AddressState -eq "Preferred" -and $_.PrefixLength -eq 24}).IPAddress
# The 24 filter above is because of our mask we set previously

$domainName = 'fg.contoso.com'
$gateway = (Get-NetIPConfiguration | Foreach IPv4DefaultGateway | Select NextHop)."NextHop"
$hostname = hostname

# Install DHCP
Install-WindowsFeature DHCP -IncludeManagementTools

# Add the DHCP scope to this DC server - from VLAN mapping
Add-DhcpServerv4Scope -Name 'VLAN-111' -StartRange 10.216.175.5 -Endrange 10.216.175.254 -SubnetMask 255.255.255.0 -State Active

# Observe the ScopeID just created
$scopeID = (Get-DHCPServerV4Scope)[0].ScopeId.IPAddressToString

# Set Options at the Scope level
Set-DhcpServerv4OptionValue -ScopeID $scopeID -DNSServer $dnsServerIP -DNSDomain $domainName -Router $gateway

# Authorize the DHCP server
Add-DhcpServerInDC -DnsName "$hostname.$domainName"

# Display info about the scope
Get-DhcpServerv4Scope | Select-Object -Property *

# Display leases before adding Client VM
Get-DhcpServerV4Reservation -ScopeID $scopeID

# Get 5 next IP Addresses that are free
Get-DhcpServerv4FreeIPAddress -ScopeID $scopeID -NumAddress 5
```

As expected, no leases yet:
![Result](_images/2.png)

### Configure DNS forwarder so we can browse the web

```powershell
# Forward to Redmond DNS
Add-DnsServerForwarder -IPAddress "10.50.10.50"

# Validate
Get-DnsServerForwarder

# Check curl to Google
curl google.com

# Forward queries for arclab.local to ArcLab-DC
Add-DnsServerConditionalForwarderZone -Name "arclab.local" -MasterServers "10.216.173.10" # ArcLab-DC.arclab.local
```
![Result](_images/4.png)

## `OCPLab-DEV-1`

Use the `VM Customization Specifications` to
* Use the vSphere machines name as the hostname
* Auto domain join to `fg.contoso.com`
* Since DHCP is configured above, should get an IP address automatically

![Result](_images/5.png)

![Result](_images/6.png)

The VM will go through it's reboot cycles to join the domain etc.

Post boot in `OCPLab-DEV1`:
![Result](_images/7.png)

![Result](_images/8.png)

Check leases again in Domain Controller:
![Result](_images/9.png)

Everything is up!

---

# OpenShift `IPI`-based install - Cluster Name: `arcci`

> `IPI` because we want horizontal scalability on our `MachineSets`

## Add a Reverse Lookup Zone on `OCPLab-DC1`
```powershell
# Add a reverse lookup zone - VLAN 111
Add-DnsServerPrimaryZone -NetworkId "10.216.175.0/24" -ReplicationScope Domain

# Get reverse zone name
$Zones = @(Get-DnsServerZone)
ForEach ($Zone in $Zones) {
    if ((-not $($Zone.IsAutoCreated)) -and ($Zone.IsReverseLookupZone) -and ($Zone.ZoneName.Split(".")[0] -eq "0")) {
       $Reverse = $Zone.ZoneName
    }
}
```

## DNS records for OpenShift in `OCPLab-DC1` - [from here](https://github.com/openshift/installer/blob/master/docs/user/vsphere/vips-dns.md#dns-records)

```PowerShell
$clusterName = 'arcci'
$baseDomain = 'fg.contoso.com'
$ip1 = '10.216.175.6'
$ip2 = '10.216.175.7'

Add-DnsServerResourceRecordA -Name "api.$clusterName" -ZoneName $baseDomain -AllowUpdateAny -IPv4Address $ip1 -TimeToLive 01:00:00 -createptr
Add-DnsServerResourceRecordA -Name "*.apps.$clusterName" -ZoneName $baseDomain -AllowUpdateAny -IPv4Address $ip2 -TimeToLive 01:00:00 -createptr
```

We see:
![Result](_images/10.png)

> We are now ready to deploy OpenShift from our container

---
# `devcontainer` prep

```bash
# = = = = = = = = = = = = = = = = = = = 
# DNS Hack for this VSCode Devcontainer
# = = = = = = = = = = = = = = = = = = = 

# We will point this container to use `OCPLab-DC.fg.contoso.com` as the DNS resolver
# Since `OCPLab-DC` has conditional forwarding for `arclab.local`, and the internet (via Redmond resolver), we should be covered
cat << EOF > /etc/resolv.conf
# DNS requests are forwarded to the host. DHCP DNS options are ignored.
nameserver 10.216.175.4                 # OCPLab-DC.fg.contoso.com
EOF

# DNS Tests
nslookup api.arcci.fg.contoso.com
# Address: 10.216.175.6
nslookup console-that-doesnt-exist-yet.apps.arcci.fg.contoso.com
# Address: 10.216.175.7
nslookup quay.io
# Address: 3.227.212.61
nslookup arclab-vc.arclab.local
# Address: 10.216.173.11
nslookup arclab-wl-esxi-02.arclab.local
# Address: 10.216.152.12

# = = = = = = = = = = = = = = = = = = = = = = = = =
# Generate SSH Key pair for Nodes - `DevContainer`
# = = = = = = = = = = = = = = = = = = = = = = = = =
export secretPath='/workspaces/openshift-vsphere-install/openshift-install/secrets'
rm -rf $secretPath
mkdir -p $secretPath/.ssh

# Generate Key Pair
ssh-keygen -t ed25519 -N '' -f $secretPath/.ssh/id_ed25519

# View public key
cat $secretPath/.ssh/id_ed25519.pub
# ssh-ed25519 AAAAC3NzaC...

# Add the SSH private key to `ssh-agent`
eval "$(ssh-agent -s)" # Ensure process is running
# Agent pid 30724

ssh-add $secretPath/.ssh/id_ed25519
# Identity added: /workspaces/openshift-vsphere-install/openshift-install/secrets/.ssh/id_ed25519 ...

# = = = = = = = = = = = = = = = = = = = = = =
# Pulling the OpenShift installation binary
# = = = = = = = = = = = = = = = = = = = = = =
export binaryPath='/workspaces/openshift-vsphere-install/openshift-install/binaries'
rm -rf $binaryPath
mkdir -p $binaryPath
cd $binaryPath

wget https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable/openshift-install-linux.tar.gz
tar -xvf openshift-install-linux.tar.gz
# README.md                 <- useless
# openshift-install         <- useful

mv openshift-install /usr/local/bin/
chmod +x /usr/local/bin/openshift-install
rm README.md

# = = = = = = = = = = = = = = = = = = = = = = = = = 
# Download vCenter root CA Cert into this container
# = = = = = = = = = = = = = = = = = = = = = = = = = 
cd $secretPath
rm -rf certs
wget https://arclab-vc.arclab.local/certs/download.zip --no-check-certificate
unzip download.zip
rm -rf download.zip

# Add certs to Container OS
cp certs/lin/* /usr/local/share/ca-certificates
cp certs/lin/* /etc/ssl/certs
update-ca-certificates --verbose --fresh
# ...
# link Trustwave_Global_Certification_Authority.pem -> f249de83.0
# 127 added, 0 removed; done.
# Running hooks in /etc/ca-certificates/update.d...
# done.
```

> Our devcontainer now has everything it needs to deploy OpenShift

---

## Deploy OCP on vSphere in IPI mode
```bash
export installationDir='/workspaces/openshift-vsphere-install/openshift-install/secrets/installation-assets'
rm -rf $installationDir
mkdir -p $installationDir
cd $installationDir

# Create config file
openshift-install create install-config
# ? Platform vsphere
# ? vCenter arclab-vc.arclab.local
# ? Username your-sa@arclab.local
# ? Password [? for help] **********
# INFO Connecting to vCenter arclab-vc.arclab.local 
# INFO Defaulting to only available datacenter: Your Datacenter 
# INFO Defaulting to only available cluster: ArcLab Workload Cluster 
# INFO Defaulting to only available datastore: ArcLab-NFS-01 
# ? Network DataSvc PG OCP VM Network (VLAN 111)
# ? Virtual IP Address for API 10.216.175.6
# ? Virtual IP Address for Ingress 10.216.175.7
# ? Base Domain fg.contoso.com
# ? Cluster Name arcci
# ? Pull Secret [? for help] ********************************
# INFO Install-Config created in: .

# Fire install
openshift-install create cluster --log-level=debug
# INFO Consuming Install Config from target directory 
# INFO Obtaining RHCOS image file from 'https://rhcos-redirector.apps.art.xq1c.p1.openshiftapps.com/art/storage/releases/rhcos-4.10/410.84.202205191234-0/x86_64/rhcos-410.84.202205191234-0-vmware.x86_64.ova?sha256=' 
# INFO Creating infrastructure resources...

# ....
# DEBUG Still waiting for the Kubernetes API: Get "https://api.arcci.fg.contoso.com:6443/version": dial tcp 10.216.175.6:6443: connect: connection refused 
# INFO API v1.23.5+3afdacb up                       
# INFO Waiting up to 30m0s (until 4:28AM) for bootstrapping to complete... 
#...
# INFO Waiting up to 10m0s (until 9:13PM) for the openshift-console route to be created... 
# DEBUG Route found in openshift-console namespace: console 
# DEBUG OpenShift console route is admitted          
# INFO Install complete!                            
# INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/workspaces/openshift-vsphere-install/openshift-install/secrets/installation-assets/auth/kubeconfig' 
# INFO Access the OpenShift web-console here: https://console-openshift-console.apps.arcci.fg.contoso.com 
# INFO Login to the console with user: "kubeadmin", and password: "..." 
# DEBUG Time elapsed per stage:                      
# DEBUG      pre-bootstrap: 1m18s                    
# DEBUG          bootstrap: 37s                      
# DEBUG             master: 53s                      
# DEBUG Bootstrap Complete: 9m58s                    
# DEBUG                API: 57s                      
# DEBUG  Bootstrap Destroy: 24s                      
# DEBUG  Cluster Operators: 14m22s                   
# INFO Time elapsed: 29m15s  
# 
```

Complete:

![Result](_images/11.png)

## Access `oc` and vSphere from `OCPLab-DEV-1`

```PowerShell
# Download oc cli
$chocoPath = "C:\ProgramData\chocolatey\bin"
$ocPath = "https://access.cdn.redhat.com/content/origin/files/sha256/b5/b5be74fba204c3c71f14ad9f20c4432215861b9e83008bd597445b77b7d71aec/oc-4.10.17-windows.zip?user=9f0797baa5932892e224995847e5b117&_auth_=1654762464_3d3e28adce1ce122828a13a5a48c87f4"
$downloadZip = "oc-4.10.17-windows.zip"

cd $chocoPath
Invoke-WebRequest $ocPath -OutFile "$chocoPath\$downloadZip"
Expand-Archive -Path $downloadZip -DestinationPath $chocoPath
rm README.md
```

## Clean destroy

```bash
openshift-install destroy cluster --dir $installationDir
# INFO Destroyed                                     VirtualMachine=arcci-7p7gn-rhcos
# INFO Destroyed                                     VirtualMachine=arcci-7p7gn-bootstrap
# INFO Destroyed                                     VirtualMachine=arcci-7p7gn-master-2
# INFO Destroyed                                     VirtualMachine=arcci-7p7gn-master-1
# INFO Destroyed                                     VirtualMachine=arcci-7p7gn-master-0
# INFO Destroyed                                     Folder=arcci-7p7gn
# INFO Destroyed                                     Tag=arcci-7p7gn
# INFO Destroyed                                     TagCategory=openshift-arcci-7p7gn
# INFO Time elapsed: 10s 
rm -rf $installationDir
```

## TO-DOs
- [ ] Automate DC install with Terraform or `govc`
- [ ] Integrate with Azure DevOps Build Agent
- [ ] Add in MetalLB Operator for `LoadBalancer`
- [ ] LDAP for sign-in
- [ ] SSL for ingress
- [ ] `RWX` StorageClass (Azure CSI?)
- [ ] VMWare CSI for StorageClass
- [ ] Maintenance jobs (etcd backup, garbage collection etc)
- [ ] Make master nodes unschedulable
- [ ] ⭐ Onboard Arc via a `job`
- [ ] Vault?
- [ ] Aqua?
- [ ] ArgoCD?
- [ ] Monitoring - Container Insights/Kusto
- [ ] Some Teams Webhook?