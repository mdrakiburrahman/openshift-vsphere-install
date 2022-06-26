resource "kubernetes_storage_class" "storage" {
  metadata {
    name = var.storageclass_name
  }
  # mount_options = var.mount_options
  storage_provisioner = "kubernetes.io/azure-file"
  reclaim_policy      = "Delete"
  parameters = {
    storageAccount = var.storageaccount_name
  }
  volume_binding_mode = "Immediate"
}

resource "kubernetes_secret" "secret" {
  metadata {
    namespace = "openshift-cluster-csi-drivers"
    name = "${var.storageclass_name}-${var.storageaccount_name}-csi-driver-secret"
  }

  data = {
    azurestorageaccountname = var.storageaccount_name
    azurestorageaccountkey = var.storageaccount_key
  }

  type = "Opaque"
}