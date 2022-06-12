output "storage_accnt_name" {
  value = azurerm_storage_account.storage.name
}

output "storage_accnt_primary_key" {
  value = azurerm_storage_account.storage.primary_access_key
}
