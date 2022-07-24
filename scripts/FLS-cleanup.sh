# =======================
# Connect to 3 components
# =======================
# Connect to OCP cluster
export KUBECONFIG=/workspaces/openshift-vsphere-install/openshift-install/secrets/arcci/auth/kubeconfig

# Connect to Azure
az login --service-principal --username $spnClientId --password $spnClientSecret --tenant $spnTenantId
az account set --subscription $subscriptionId

# Connect to Terraform
cd /workspaces/openshift-vsphere-install/terraform
export storageAccountName=$(terraform output --raw storage_account_name)
export storageClassName=$(terraform output --raw storage_class_name)

echo "Cleaning up FLS resources on Storage Account: ${storageAccountName}..."

# =======================
# Cleanup FLS resources
# =======================

# Get all pvs that have status "Released" into an array - delete from ARM and K8s
kubectl get pv -o json | jq -r '.items[] | select(.spec.storageClassName == "'${storageClassName}'") | select(.status.phase == "Released") | .metadata.name' | while read pv; do
  echo "Cleaning up PV ${pv} in Kubernetes..."
  kubectl delete pv $pv

  echo "Cleaning up FLS ${pv} in ARM..."
  az storage share delete --name $pv --account-name $storageAccountName
done

# ==========================
# Reconcile with Terraform
# ==========================

# ---------------------
# ENVIRONMENT VARIABLES
# For Terraform
# ---------------------
# OCP
export kube_context="kubectl config view --minify --flatten --context=admin"
export infra_id=$(oc get -o jsonpath='{.status.infrastructureName}{"\n"}' infrastructure cluster)

export TF_VAR_host=$(eval "$kube_context" | yq .clusters[0].cluster.server)
export TF_VAR_client_certificate=$(eval "$kube_context" | yq .users[0].user.client-certificate-data)
export TF_VAR_client_key=$(eval "$kube_context" | yq .users[0].user.client-key-data)
export TF_VAR_cluster_ca_certificate=$(eval "$kube_context" | yq .clusters[0].cluster.certificate-authority-data)

# Azure
export TF_VAR_SPN_CLIENT_ID=$spnClientId
export TF_VAR_SPN_CLIENT_SECRET=$spnClientSecret
export TF_VAR_SPN_TENANT_ID=$spnTenantId
export TF_VAR_SPN_SUBSCRIPTION_ID=$subscriptionId
export TF_VAR_prefix="${infra_id}"
export TF_VAR_pvshare_size=10 # GB
export TF_VAR_pvshare_prefix="fls-"
export TF_VAR_pvshare_nums=25 # <---- Tweak this to increase number of PVs in Cluster

# Remote State in Azure Blob
export stateFileKeyName="openshift-vsphere-install/${infra_id}/terraform.tfstate"

export TF_CLI_ARGS_init="-backend-config='storage_account_name=${TFSTATE_STORAGE_ACCOUNT_NAME}'"
export TF_CLI_ARGS_init="$TF_CLI_ARGS_init -backend-config='container_name=${TFSTATE_STORAGE_ACCOUNT_CONTAINER_NAME}'"
export TF_CLI_ARGS_init="$TF_CLI_ARGS_init -backend-config='access_key=${TFSTATE_STORAGE_ACCOUNT_KEY}'"
export TF_CLI_ARGS_init="$TF_CLI_ARGS_init -backend-config='key=${stateFileKeyName}'"

# Check plan
terraform init && terraform plan

# Reconcile
terraform apply -auto-approve