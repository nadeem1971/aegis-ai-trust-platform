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

variable "openai_private_only" {
  description = "Production posture: disable public access and use a private endpoint. Keep false during local gateway development (ADR-003)."
  type        = bool
  default     = false
}

variable "openai_capacity_tpm" {
  description = "Deployment capacity in thousands of tokens per minute. 10 is ample for dev and red-team runs while keeping cost predictable."
  type        = number
  default     = 10
}

# ── Model pinning (ADR-004) ──────────────────────────────────────────
# Verify lifecycle status before changing these. A model in `Deprecating`
# state cannot be deployed new, even if it is listed for the region.
variable "openai_deployment_name" {
  description = "Deployment name used by the gateway. Must match OPENAI_DEPLOYMENT in the gateway config."
  type        = string
  default     = "gpt-5-4-mini"
}

variable "openai_model_name" {
  description = "Azure OpenAI model name. Verified GA in UAE North as of 2026-07."
  type        = string
  default     = "gpt-5.4-mini"
}

variable "openai_model_version" {
  description = "Pinned model version. gpt-5.4-mini 2026-03-17 retires 2027-03-18."
  type        = string
  default     = "2026-03-17"
}

variable "openai_sku_name" {
  description = "Deployment SKU. All current GA models in UAE North are GlobalStandard; see ADR-004 for the data-residency implication."
  type        = string
  default     = "GlobalStandard"
}

# ── Shared OpenAI account (ADR-005) ──────────────────────────────────
variable "shared_openai_account_name" {
  description = "Name of the existing shared Azure OpenAI account AEGIS deploys its model onto."
  type        = string
  default     = "safewatch-openai"
}

variable "shared_openai_resource_group" {
  description = "Resource group of the shared Azure OpenAI account."
  type        = string
  default     = "rg-safewatch-ai"
}
