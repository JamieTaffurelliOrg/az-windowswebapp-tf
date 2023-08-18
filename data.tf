data "azurerm_service_plan" "service_plan" {
  name                = var.service_plan_name
  resource_group_name = var.service_plan_resource_group_name
}

data "azurerm_log_analytics_workspace" "logs" {
  provider            = azurerm.logs
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_workspace_resource_group_name
}
