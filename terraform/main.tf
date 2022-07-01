# ---------------------------------------------------------------------------------------------------------------------
# CLEANSED CONSTANTS
# ---------------------------------------------------------------------------------------------------------------------
locals {
  # Replace any '-' characters in prefix with ''
  prefix = replace(var.prefix, "-", "")
  
}

# ---------------------------------------------------------------------------------------------------------------------
# AZURE RESOURCE GROUP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_resource_group" "ocp_vsphere_rg" {
  name     = "${local.prefix}rg"
  location = var.resource_group_location
  tags     = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# STORAGE ACCOUNT FOR FILE SHARES
# ---------------------------------------------------------------------------------------------------------------------
module "storageaccnt" {
  depends_on = [azurerm_resource_group.ocp_vsphere_rg]

  source                  = "./modules/azurestorageaccnt-module"
  prefix                  = local.prefix
  resource_group_location = azurerm_resource_group.ocp_vsphere_rg.location
  resource_group_name     = azurerm_resource_group.ocp_vsphere_rg.name
  tags                    = var.tags
  replication             = "LRS"
}

# ---------------------------------------------------------------------------------------------------------------------
# OCP RWX STORAGECLASS
# ---------------------------------------------------------------------------------------------------------------------
module "storageclass" {
  depends_on = [module.storageaccnt]

  source                  = "./modules/k8s-azurestorageclass-module"
  storageclass_name       = var.storageclass_name
  storageaccount_name     = module.storageaccnt.storage_accnt_name
  storageaccount_key      = module.storageaccnt.storage_accnt_primary_key
  
}

# ---------------------------------------------------------------------------------------------------------------------
# AZURE FLS + OCP RWX PVs - coupled lifecycle
# ---------------------------------------------------------------------------------------------------------------------
module "pvshare" {
  depends_on = [module.storageclass]

  count                          = var.pvshare_nums # Basically a for loop
  source                         = "./modules/azure-k8s-pvshare-module"
  pvshare_name                   = format("%s%d", var.pvshare_prefix, count.index)
  pvshare_size                   = var.pvshare_size
  storage_accnt_name             = module.storageaccnt.storage_accnt_name
  storageclass_name              = module.storageclass.storageclass_name
  storageclass_secret_namespace  = module.storageclass.storageclass_secret_namespace
  storageclass_secret_name       = module.storageclass.storageclass_secret_name
  
}