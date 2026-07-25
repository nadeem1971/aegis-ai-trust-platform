# ─────────────────────────────────────────────────────────────────────
# Azure OpenAI — model plane for the AEGIS gateway
#
# Shared-account model (ADR-005): this subscription permits a single S0
# OpenAI account (OpenAI.S0.AccountCount limit = 1), already used by a
# sibling project. Rather than request a quota increase, AEGIS consumes
# the existing account as a shared model plane and adds its OWN model
# deployment onto it. Model TPM quota is per-deployment and ample.
#
# This mirrors a realistic enterprise pattern: a shared, centrally-governed
# model plane with per-application deployments and per-application access
# control — which is itself the posture AEGIS is designed to govern.
#
# Threat model refs: T-16 (no stored keys — the gateway authenticates with
# its own identity via the role assignment below), T-17 (endpoint abuse).
#
# Model pinning (ADR-004): verify lifecycle before changing the version.
#   az cognitiveservices model list --location uaenorth \
#     --query "[?model.lifecycleStatus=='GenerallyAvailable' && starts_with(model.name,'gpt')].{Name:model.name,Version:model.version}" -o table
# ─────────────────────────────────────────────────────────────────────

# Reference the existing shared OpenAI account (not managed by AEGIS).
data "azurerm_cognitive_account" "shared_openai" {
  name                = var.shared_openai_account_name
  resource_group_name = var.shared_openai_resource_group
}

# AEGIS's own model deployment on the shared account.
resource "azurerm_cognitive_deployment" "chat" {
  name                 = var.openai_deployment_name
  cognitive_account_id = data.azurerm_cognitive_account.shared_openai.id

  model {
    format  = "OpenAI"
    name    = var.openai_model_name
    version = var.openai_model_version
  }

  sku {
    name     = var.openai_sku_name
    capacity = var.openai_capacity_tpm
  }
}

# The AEGIS operator/identity gets OpenAI User on the shared account —
# scoped access, keyless (T-16). In production this would be the gateway's
# managed identity rather than the developer principal.
resource "azurerm_role_assignment" "openai_user_self" {
  scope                = data.azurerm_cognitive_account.shared_openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = data.azurerm_client_config.current.object_id
}
