# Getting a quick `arcvlan` cluster up to test VLAN 106

## `ocplab-dc1`

```PowerShell
# Routes
$clusterName = 'arcvlan'
$baseDomain = 'fg.contoso.com'
$ip1 = '10.216.154.195'
$ip2 = '10.216.154.196'

Add-DnsServerResourceRecordA -Name "api.$clusterName" -ZoneName $baseDomain -AllowUpdateAny -IPv4Address $ip1 -TimeToLive 01:00:00
Add-DnsServerResourceRecordA -Name "*.apps.$clusterName" -ZoneName $baseDomain -AllowUpdateAny -IPv4Address $ip2 -TimeToLive 01:00:00

# Add a PTR record to the Reverse Lookup Zone (for some reason -createptr doesn't work in this zone)
$Reverse = '192.154.216.10.in-addr.arpa'
Add-DNSServerResourceRecordPTR -ZoneName $Reverse -Name 195 -PTRDomainName api.arcvlan.fg.contoso.com.
Add-DNSServerResourceRecordPTR -ZoneName $Reverse -Name 196 -PTRDomainName *.apps.arcvlan.fg.contoso.com.
```

## `devcontainer` prep

```bash
# = = = = = = = = = = = = = = = = = = = = = = = = =
# DNS tests
# = = = = = = = = = = = = = = = = = = = = = = = = =
nslookup api.arcvlan.fg.contoso.com
# Address: 10.216.154.195
nslookup console-that-doesnt-exist-yet.apps.arcvlan.fg.contoso.com
# Address: 10.216.154.196
nslookup quay.io
# Address: 3.227.212.61
nslookup arclab-vc.arclab.local
# Address: 10.216.173.11
nslookup arclab-wl-esxi-02.arclab.local
# Address: 10.216.152.12

# = = = = = = = = = = = = = = = = =
# Inject pre-existing SSH Key pair
# = = = = = = = = = = = = = = = = =
export secretPath='/workspaces/openshift-vsphere-install/openshift-install/secrets'

# View public key and add it
cat $secretPath/.ssh/id_ed25519.pub
ssh-add $secretPath/.ssh/id_ed25519

# = = = = = = = = = = = = = = = = = = = = = =
# Moving the OpenShift installation binary
# = = = = = = = = = = = = = = = = = = = = = =
export binaryPath='/workspaces/openshift-vsphere-install/openshift-install/binaries'
cd $binaryPath
tar -xvf openshift-install-linux.tar.gz
# README.md                 <- useless
# openshift-install         <- useful
rm README.md

cp openshift-install /usr/local/bin/
chmod +x /usr/local/bin/openshift-install

# = = = = = = = = = = = = = = = = = = = = = = = = = 
# Inject vCenter root CA Cert into this container
# = = = = = = = = = = = = = = = = = = = = = = = = = 
cd $secretPath
cp certs/lin/* /usr/local/share/ca-certificates
cp certs/lin/* /etc/ssl/certs
update-ca-certificates --verbose --fresh
# ...
# link Trustwave_Global_Certification_Authority.pem -> f249de83.0
# 127 added, 0 removed; done.
# Running hooks in /etc/ca-certificates/update.d...
# done.
```

## Deploy OpenShift

```bash
export installationDir='/workspaces/openshift-vsphere-install/openshift-install/secrets/arcvlan'
mkdir -p $installationDir
cd $installationDir

# Copy previous install config in here
cp ../install-config/install-config.yaml install-config.yaml

# Replace env specific values
export config='/workspaces/openshift-vsphere-install/openshift-install/secrets/arcvlan/install-config.yaml'
export apiVIP='10.216.154.195'
export ingressVIP='10.216.154.196'
export cluster='arcvlan'
export network='DataSvc Dev VM Network PG (VLAN 106)'
export defaultDatastore='ArcLab-NFS-02'
export workerCount=1

# Replace values for this env
yq e "(.compute.[0].replicas |= $workerCount)" -i $config
yq e "(.metadata.name |= \"$cluster\")" -i $config
yq e "(.platform.vsphere.apiVIP |= \"$apiVIP\")" -i $config
yq e "(.platform.vsphere.ingressVIP |= \"$ingressVIP\")" -i $config
yq e "(.platform.vsphere.network |= \"$network\")" -i $config
yq e "(.platform.vsphere.defaultDatastore |= \"$defaultDatastore\")" -i $config

# Fire install
openshift-install create cluster --log-level=debug

# Validate via kubeconfig
export KUBECONFIG=/workspaces/openshift-vsphere-install/openshift-install/secrets/arcvlan/auth/kubeconfig

oc get nodes
# NAME                        STATUS   ROLES    AGE   VERSION

```

## Destroy OpenShift

```bash
openshift-install destroy cluster --dir $installationDir
rm -rf $installationDir
```