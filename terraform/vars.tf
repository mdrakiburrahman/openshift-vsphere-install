# ---------------------------------------------------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# Define these secrets as environment variables
# ---------------------------------------------------------------------------------------------------------------------

# Azure
variable "SPN_SUBSCRIPTION_ID" {
  description = "Azure Subscription ID"
  type        = string
}

variable "SPN_CLIENT_ID" {
  description = "Azure service principal name"
  type        = string
}

variable "SPN_CLIENT_SECRET" {
  description = "Azure service principal password"
  type        = string
}

variable "SPN_TENANT_ID" {
  description = "Azure tenant ID"
  type        = string
}

# K8s
variable "host" {
  type = string
}

variable "client_certificate" {
  type = string
}

variable "client_key" {
  type = string
}

variable "cluster_ca_certificate" {
  type = string
}

# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

# TBD

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------

variable "prefix" {
  description = "Prefix to append to all resources"
  type        = string
  default     = "arcci-xxxxx"
}

variable "storageclass_name" {
  description = "The name of the K8s storageClass"
  type        = string
  default     = "azure-file"
}

variable "resource_group_location" {
  description = "The location in which the deployment is taking place"
  type        = string
  default     = "westus2" # Close to Redmond
}

variable "tags" {
  type        = map(string)
  description = "A map of the tags to use on the resources that are deployed with this module."

  default = {
    Source                                                                     = "terraform"
    Owner                                                                      = "Raki Rahman"
    Project                                                                    = "OCP vSphere environment for Arc CI"
    azsecpack                                                                  = "nonprod"
    "platformsettings.host_environment.service.platform_optedin_for_rootcerts" = "true"
  }
}

variable "pvshare_size" {
  description = "File share AKA pv size in GB"
  type        = number
  default     = 5
}

variable "pvshare_prefix" {
  description = "Prefix to append to file share names"
  type        = string
  default     = "fls-"
}

variable "pvshare_nums" {
  description = "Number of fileshare/pvs to allocate"
  type        = number
  default     = 10
}