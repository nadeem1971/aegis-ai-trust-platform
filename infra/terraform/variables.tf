variable "project" {
  description = "Project short name, used in resource naming."
  type        = string
  default     = "aegis"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be one of: dev, test, prod."
  }
}

variable "location" {
  description = "Azure region. UAE North for GCC data residency (ADR-001)."
  type        = string
  default     = "uaenorth"
}

variable "postgres_admin_login" {
  description = "PostgreSQL administrator login name."
  type        = string
  default     = "aegisadmin"
}

variable "postgres_sku" {
  description = "PostgreSQL Flexible Server SKU. B1ms keeps dev cost < $15/month."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "allowed_admin_object_ids" {
  description = "Entra ID object IDs granted Key Vault admin during development."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default = {
    project    = "aegis-ai-trust-platform"
    owner      = "nadeem-ahmad"
    managed_by = "terraform"
  }
}
