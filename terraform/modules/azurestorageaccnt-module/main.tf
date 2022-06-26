# Random ID generator
resource "random_id" "rand" {
  keepers = {
    group_name = var.resource_group_name
  }
  byte_length = 4
}

resource "azurerm_storage_account" "storage" {
  name                     = "${var.prefix}sa${random_id.rand.hex}"
  resource_group_name      = var.resource_group_name
  location                 = var.resource_group_location
  account_tier             = "Standard"
  account_replication_type = var.replication
  account_kind             = "StorageV2"
  network_rules {
    default_action             = "Allow"
  }

  tags = var.tags
}

resource "azurerm_storage_share" "example" {
  name                 = var.file_share_name
  storage_account_name = azurerm_storage_account.storage.name
  quota                = var.file_share_size
}