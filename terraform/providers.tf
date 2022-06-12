# ----------------------------------------------------------------------------------------------------------------------
# REQUIRE A SPECIFIC TERRAFORM VERSION OR HIGHER
# ----------------------------------------------------------------------------------------------------------------------
terraform {
  required_version = "~> 1.0"
  required_providers {
    azurerm = "~> 2.62.1"
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# AZURE PROVIDER
# ----------------------------------------------------------------------------------------------------------------------
provider "azurerm" {
  subscription_id = var.SPN_SUBSCRIPTION_ID
  client_id       = var.SPN_CLIENT_ID
  client_secret   = var.SPN_CLIENT_SECRET
  tenant_id       = var.SPN_TENANT_ID
  features {}
}

# ----------------------------------------------------------------------------------------------------------------------
# K8s PROVIDER
# ----------------------------------------------------------------------------------------------------------------------
provider "kubernetes" {
  host                   = var.host
  client_certificate     = base64decode(var.client_certificate)
  client_key             = base64decode(var.client_key)
  cluster_ca_certificate = base64decode(var.cluster_ca_certificate)
}
