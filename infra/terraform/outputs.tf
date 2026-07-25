output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "key_vault_uri" {
  value = azurerm_key_vault.main.vault_uri
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.main.fqdn
}

output "container_app_environment_id" {
  value = azurerm_container_app_environment.main.id
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.main.id
}

output "openai_endpoint" {
  value = data.azurerm_cognitive_account.shared_openai.endpoint
}

output "openai_deployment_name" {
  value = azurerm_cognitive_deployment.chat.name
}

output "openai_model_pinned" {
  value = "${var.openai_model_name}:${var.openai_model_version} (${var.openai_sku_name})"
}
