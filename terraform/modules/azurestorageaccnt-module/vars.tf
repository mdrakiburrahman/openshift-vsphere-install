# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

variable "prefix" {
  description = "The prefix which should be used for all resources in this module"
  type        = string
}

variable "resource_group_location" {
  description = "The location in which the deployment is taking place"
  type        = string
}

variable "resource_group_name" {
  description = "Deployment RG name"
  type        = string
}

variable "tags" {
  type        = map(string)
  description = "A map of the tags to use on the resources that are deployed with this module."
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------

variable "replication" {
  description = "Type of replication to use for the storage account"
  type        = string
  default     = "LRS"
}

variable "file_share_name" {
  description = "Name of one file share to create PVC"
  type        = string
  default     = "fls-1"
}

variable "file_share_size" {
  description = "File share size in GB"
  type        = number
  default     = 100
}