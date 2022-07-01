# ---------------------------------------------------------------------------------------------------------------------
# STORAGE ACCOUNT FILE SHARE
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_storage_share" "share" {
  name                 = var.pvshare_name
  storage_account_name = var.storage_accnt_name
  quota                = var.pvshare_size
}

# ---------------------------------------------------------------------------------------------------------------------
# PERSISTENT VOLUME POINTING TO STORAGE ACCOUNT FILE SHARE
# ---------------------------------------------------------------------------------------------------------------------
resource "kubernetes_persistent_volume" "pv" {
  depends_on = [azurerm_storage_share.share]

  metadata {
    name = var.pvshare_name
  }
  spec {
    capacity = {
      storage = format("%d%s", var.pvshare_size, "Gi")
    }
    access_modes       = ["ReadWriteMany"]
    storage_class_name = var.storageclass_name
    persistent_volume_source {
      azure_file {
        share_name       = var.pvshare_name
        read_only        = false
        secret_namespace = var.storageclass_secret_namespace
        secret_name      = var.storageclass_secret_name
      }
    }
  }
}
