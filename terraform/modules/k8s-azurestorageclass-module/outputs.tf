output "storageclass_name" {
  value = kubernetes_storage_class.storage.metadata.0.name
}

output "storageclass_secret_namespace" {
  value = kubernetes_secret.secret.metadata.0.namespace
}

output "storageclass_secret_name" {
  value = kubernetes_secret.secret.metadata.0.name
}
