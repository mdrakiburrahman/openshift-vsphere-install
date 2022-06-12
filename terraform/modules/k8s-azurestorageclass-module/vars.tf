# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

variable "storageclass_name" {
  description = "Name of Kubernetes StorageClass"
  type        = string
}

variable "storageaccount_name" {
  description = "Name of underlying Azure Storage Account"
  type        = string
}

variable "storageaccount_key" {
  description = "Access Key for underlying Azure Storage Account"
  type        = string
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------
variable "mount_options" {
  description = "An array of mount options"
  type        = list
  default     = ["uid=1500", "gid=1500", "mfsymlinks"]
}