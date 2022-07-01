# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------
variable "pvshare_name" {
  description = "Name of the File Share/PV to create"
  type        = string
}

variable "pvshare_size" {
  description = "Size of the File Share/PV to create"
  type        = number
}

variable "storage_accnt_name" {
  description = "Name of Storage Account to contain the File Share"
  type        = string
}

variable "storageclass_name" {
  description = "Name of the K8s storageClass to create"
  type        = string
}

variable "storageclass_secret_namespace" {
  description = "Namespace where the Storage Account Key is stored"
  type        = string
}

variable "storageclass_secret_name" {
  description = "Name of the secret where the Storage Account Key is stored"
  type        = string
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------
