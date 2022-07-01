# ---------------------------------------------------------------------------------------------------------------------
# STORAGE CLASS USING AZURE FILE PROVISIONER
# ---------------------------------------------------------------------------------------------------------------------
resource "kubernetes_storage_class" "storage" {
  metadata {
    name = var.storageclass_name
  }
  storage_provisioner = "kubernetes.io/azure-file"
  reclaim_policy      = "Delete"
  parameters = {
    storageAccount = var.storageaccount_name
  }
  volume_binding_mode = "Immediate"
}

# ---------------------------------------------------------------------------------------------------------------------
# SECRET WHERE STORAGE CLASS ACCESS KEY IS STORED - NEEDED FOR PV CREATION
# ---------------------------------------------------------------------------------------------------------------------
resource "kubernetes_secret" "secret" {
  metadata {
    namespace = "openshift-cluster-csi-drivers" # This is constant so we hardcode
    name = "${var.storageclass_name}-${var.storageaccount_name}-csi-driver-secret"
  }

  data = {
    azurestorageaccountname = var.storageaccount_name
    azurestorageaccountkey = var.storageaccount_key
  }

  type = "Opaque"
}