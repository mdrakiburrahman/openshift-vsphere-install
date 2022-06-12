# ---------------------------------------------------------------------------------------------------------------------
# AZURE RESOURCE GROUP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_resource_group" "ocp_vsphere_rg" {
  name     = "${var.prefix}rg"
  location = var.resource_group_location
  tags     = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# STORAGE ACCOUNT FOR RWX STORAGECLASS
# ---------------------------------------------------------------------------------------------------------------------
module "storageaccnt" {
  depends_on = [azurerm_resource_group.ocp_vsphere_rg]

  source                  = "./modules/azurestorageaccnt-module"
  prefix                  = var.prefix
  resource_group_location = azurerm_resource_group.ocp_vsphere_rg.location
  resource_group_name     = azurerm_resource_group.ocp_vsphere_rg.name
  tags = var.tags
  replication             = "LRS" 
}

# ---------------------------------------------------------------------------------------------------------------------
# OCP RWX STORAGECLASS
# ---------------------------------------------------------------------------------------------------------------------
module "storageclass" {
  depends_on = [module.storageaccnt]

  source                  = "./modules/k8s-azurestorageclass-module"
  storageclass_name       = "azure-file"
  storageaccount_name     = module.storageaccnt.storage_accnt_name
  storageaccount_key      = module.storageaccnt.storage_accnt_primary_key
  mount_options           = ["uid=1500", "gid=1500", "mfsymlinks"]
  
}