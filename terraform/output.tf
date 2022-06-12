# ----------------------------------------------------------------------------------------------------------------------
# OUTPUT DESIRED VALUES
# ----------------------------------------------------------------------------------------------------------------------
output "storage_account_name" {
  description = "Name of the storage account"
  value = module.storageaccnt.storage_accnt_name
}

output "storage_class_name" {
  description = "Name of the storage class"
  value = module.storageclass.storageclass_name
}

output "storage_class_secret_namespace" {
  description = "Namespace containing the storage class secret"
  value = module.storageclass.storageclass_secret_namespace
}

output "storage_class_secret_name" {
  description = "Name of the storage class secret"
  value = module.storageclass.storageclass_secret_name
}