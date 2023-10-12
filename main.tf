resource "azurerm_windows_web_app" "web_app" {
  #checkov:skip=CKV_AZURE_17:Requiring client certs for all apps is too much
  #checkov:skip=CKV_AZURE_88:This is not a requirement
  #checkov:skip=CKV_AZURE_80:This is parameterised
  name                               = var.web_app_name
  resource_group_name                = var.resource_group_name
  location                           = data.azurerm_service_plan.service_plan.location
  service_plan_id                    = data.azurerm_service_plan.service_plan.id
  enabled                            = var.enabled
  client_affinity_enabled            = var.client_affinity_enabled
  client_certificate_enabled         = var.client_certificate_enabled
  client_certificate_mode            = var.client_certificate_mode
  client_certificate_exclusion_paths = var.client_certificate_exclusion_paths
  https_only                         = var.https_only
  public_network_access_enabled      = false
  zip_deploy_file                    = var.zip_deploy_file
  app_settings                       = var.app_settings

  site_config {
    always_on                                     = var.always_on
    api_definition_url                            = var.api_definition_url
    api_management_api_id                         = var.api_management_api_id
    app_command_line                              = var.app_command_line
    auto_heal_enabled                             = var.auto_heal_enabled
    container_registry_use_managed_identity       = var.container_registry_use_managed_identity
    container_registry_managed_identity_client_id = var.container_registry_managed_identity_client_id
    default_documents                             = var.default_documents
    ftps_state                                    = "Disabled"
    health_check_path                             = var.health_check_path
    health_check_eviction_time_in_min             = var.health_check_eviction_time_in_min
    http2_enabled                                 = true
    load_balancing_mode                           = var.load_balancing_mode
    local_mysql_enabled                           = var.local_mysql_enabled
    managed_pipeline_mode                         = "Integrated"
    minimum_tls_version                           = "1.2"
    remote_debugging_enabled                      = false
    scm_minimum_tls_version                       = "1.2"
    scm_use_main_ip_restriction                   = var.scm_use_main_ip_restriction
    use_32_bit_worker                             = var.use_32_bit_worker
    vnet_route_all_enabled                        = var.vnet_route_all_enabled
    websockets_enabled                            = var.websockets_enabled
    worker_count                                  = var.worker_count

    application_stack {
      current_stack                = var.application_stack.current_stack
      docker_image_name            = var.application_stack.docker_image
      dotnet_version               = var.application_stack.dotnet_version
      dotnet_core_version          = var.application_stack.dotnet_core_version
      tomcat_version               = var.application_stack.tomcat_version
      java_embedded_server_enabled = var.application_stack.java_embedded_server_enabled
      java_version                 = var.application_stack.java_version
      node_version                 = var.application_stack.node_version
      python                       = var.application_stack.python_enabled
    }

    dynamic "auto_heal_setting" {
      for_each = var.auto_heal_enabled != null ? [var.auto_heal_setting] : []

      content {
        action {
          action_type                    = "Recycle"
          minimum_process_execution_time = auto_heal_setting.value["minimum_process_execution_time"]
        }

        trigger {

          dynamic "requests" {
            for_each = var.auto_heal_setting.requests

            content {
              count    = requests.value["count"]
              interval = requests.value["interval"]
            }
          }

          dynamic "slow_request" {
            for_each = var.auto_heal_setting.slow_requests

            content {
              count      = slow_request.value["count"]
              interval   = slow_request.value["interval"]
              time_taken = slow_request.value["time_taken"]
              path       = slow_request.value["path"]
            }
          }

          dynamic "status_code" {
            for_each = var.auto_heal_setting.status_codes

            content {
              count             = status_code.value["count"]
              interval          = status_code.value["interval"]
              status_code_range = status_code.value["status_code_range"]
              path              = status_code.value["path"]
              sub_status        = status_code.value["sub_status"]
              win32_status      = status_code.value["win32_status"]
            }
          }
        }
      }
    }

    dynamic "ip_restriction" {
      for_each = { for k in var.ip_restrictions : k.name => k if k != null }

      content {
        name                      = ip_restriction.key
        action                    = ip_restriction.value["action"]
        ip_address                = ip_restriction.value["ip_address"]
        priority                  = ip_restriction.value["priority"]
        service_tag               = ip_restriction.value["service_tag"]
        virtual_network_subnet_id = ip_restriction.value["virtual_network_subnet_id"]

        dynamic "headers" {
          for_each = [ip_restriction.value["headers"]]
          content {
            x_azure_fdid      = var.headers[(headers.value["x_azure_fdid_reference"])].x_azure_fdid
            x_fd_health_probe = var.headers[(headers.value["x_fd_health_probe_reference"])].x_fd_health_probe
            x_forwarded_for   = var.headers[(headers.value["x_forwarded_for_reference"])].x_forwarded_for
            x_forwarded_host  = var.headers[(headers.value["x_forwarded_host_reference"])].x_forwarded_host
          }
        }
      }
    }

    dynamic "scm_ip_restriction" {
      for_each = { for k in var.scm_ip_restrictions : k.name => k if k != null }

      content {
        name                      = scm_ip_restriction.key
        action                    = scm_ip_restriction.value["action"]
        ip_address                = scm_ip_restriction.value["ip_address"]
        priority                  = scm_ip_restriction.value["priority"]
        service_tag               = scm_ip_restriction.value["service_tag"]
        virtual_network_subnet_id = scm_ip_restriction.value["virtual_network_subnet_id"]

        dynamic "headers" {
          for_each = [scm_ip_restriction.value["headers"]]
          content {
            x_azure_fdid      = var.headers[(headers.value["x_azure_fdid_reference"])].x_azure_fdid
            x_fd_health_probe = var.headers[(headers.value["x_fd_health_probe_reference"])].x_fd_health_probe
            x_forwarded_for   = var.headers[(headers.value["x_forwarded_for_reference"])].x_forwarded_for
            x_forwarded_host  = var.headers[(headers.value["x_forwarded_host_reference"])].x_forwarded_host
          }
        }
      }
    }

    dynamic "cors" {
      for_each = var.cors == null ? [] : [var.cors]

      content {
        allowed_origins     = cors.value["allowed_origins"]
        support_credentials = cors.value["support_credentials"]
      }
    }
  }

  dynamic "auth_settings_v2" {
    for_each = var.auth_settings_v2 == null ? [] : [var.auth_settings_v2]

    content {
      auth_enabled                            = auth_settings_v2.value["auth_enabled"]
      runtime_version                         = auth_settings_v2.value["runtime_version"]
      config_file_path                        = auth_settings_v2.value["config_file_path"]
      require_authentication                  = auth_settings_v2.value["require_authentication"]
      unauthenticated_action                  = auth_settings_v2.value["unauthenticated_action"]
      default_provider                        = auth_settings_v2.value["default_provider"]
      excluded_paths                          = auth_settings_v2.value["excluded_paths"]
      require_https                           = true
      http_route_api_prefix                   = auth_settings_v2.value["http_route_api_prefix"]
      forward_proxy_convention                = auth_settings_v2.value["forward_proxy_convention"]
      forward_proxy_custom_host_header_name   = auth_settings_v2.value["forward_proxy_custom_host_header_name"]
      forward_proxy_custom_scheme_header_name = auth_settings_v2.value["forward_proxy_custom_scheme_header_name"]

      dynamic "apple_v2" {
        for_each = auth_settings_v2.value["apple_v2"] ? [auth_settings_v2.value["apple_v2"]] : []

        content {
          client_id                  = apple_v2.value["client_id"]
          client_secret_setting_name = apple_v2.value["client_secret_setting_name"]
        }
      }

      dynamic "active_directory_v2" {
        for_each = auth_settings_v2.value["active_directory_v2"] ? [auth_settings_v2.value["active_directory_v2"]] : []

        content {
          tenant_auth_endpoint                 = active_directory_v2.value["tenant_auth_endpoint"]
          client_id                            = active_directory_v2.value["client_id"]
          client_secret_setting_name           = active_directory_v2.value["client_secret_setting_name"]
          client_secret_certificate_thumbprint = active_directory_v2.value["client_secret_certificate_thumbprint"]
          jwt_allowed_groups                   = active_directory_v2.value["jwt_allowed_groups"]
          jwt_allowed_client_applications      = active_directory_v2.value["jwt_allowed_client_applications"]
          www_authentication_disabled          = active_directory_v2.value["www_authentication_disabled"]
          allowed_groups                       = active_directory_v2.value["allowed_groups"]
          allowed_identities                   = active_directory_v2.value["allowed_identities"]
          allowed_applications                 = active_directory_v2.value["allowed_applications"]
          login_parameters                     = active_directory_v2.value["login_parameters"]
          allowed_audiences                    = active_directory_v2.value["allowed_audiences"]
        }
      }

      dynamic "azure_static_web_app_v2" {
        for_each = auth_settings_v2.value["azure_static_web_app_v2"] ? [auth_settings_v2.value["azure_static_web_app_v2"]] : []

        content {
          client_id = azure_static_web_app_v2.value["client_id"]
        }
      }

      dynamic "custom_oidc_v2" {
        for_each = { for k in auth_settings_v2.value["custom_oidc_v2"] : k.name => k if k != null }

        content {
          name                          = custom_oidc_v2.value["name"]
          client_id                     = custom_oidc_v2.value["client_id"]
          openid_configuration_endpoint = custom_oidc_v2.value["openid_configuration_endpoint"]
          name_claim_type               = custom_oidc_v2.value["name_claim_type"]
          scopes                        = custom_oidc_v2.value["scopes"]
          client_credential_method      = custom_oidc_v2.value["client_credential_method"]
          client_secret_setting_name    = custom_oidc_v2.value["client_secret_setting_name"]
          authorisation_endpoint        = custom_oidc_v2.value["authorisation_endpoint"]
          token_endpoint                = custom_oidc_v2.value["token_endpoint"]
          issuer_endpoint               = custom_oidc_v2.value["issuer_endpoint"]
          certification_uri             = custom_oidc_v2.value["certification_uri"]
        }
      }

      dynamic "facebook_v2" {
        for_each = auth_settings_v2.value["facebook_v2"] ? [auth_settings_v2.value["facebook_v2"]] : []

        content {
          app_id                  = facebook_v2.value["app_id"]
          app_secret_setting_name = facebook_v2.value["app_secret_setting_name"]
          graph_api_version       = facebook_v2.value["graph_api_version"]
          login_scopes            = facebook_v2.value["login_scopes"]
        }
      }

      dynamic "github_v2" {
        for_each = auth_settings_v2.value["github_v2"] ? [auth_settings_v2.value["github_v2"]] : []

        content {
          client_id                  = github_v2.value["client_id"]
          client_secret_setting_name = github_v2.value["client_secret_setting_name"]
          login_scopes               = github_v2.value["login_scopes"]
        }
      }

      dynamic "google_v2" {
        for_each = auth_settings_v2.value["google_v2"] ? [auth_settings_v2.value["google_v2"]] : []

        content {
          client_id                  = google_v2.value["client_id"]
          client_secret_setting_name = google_v2.value["client_secret_setting_name"]
          allowed_audiences          = google_v2.value["allowed_audiences"]
          login_scopes               = google_v2.value["login_scopes"]
        }
      }

      dynamic "microsoft_v2" {
        for_each = auth_settings_v2.value["microsoft_v2"] ? [auth_settings_v2.value["microsoft_v2"]] : []

        content {
          client_id                  = microsoft_v2.value["client_id"]
          client_secret_setting_name = microsoft_v2.value["client_secret_setting_name"]
          allowed_audiences          = microsoft_v2.value["allowed_audiences"]
          login_scopes               = microsoft_v2.value["login_scopes"]
        }
      }

      dynamic "twitter_v2" {
        for_each = auth_settings_v2.value["twitter_v2"] ? [auth_settings_v2.value["twitter_v2"]] : []

        content {
          consumer_key                 = twitter_v2.value["consumer_key"]
          consumer_secret_setting_name = twitter_v2.value["consumer_secret_setting_name"]
        }
      }

      login {
        logout_endpoint                   = auth_settings_v2.login.logout_endpoint
        token_store_enabled               = auth_settings_v2.login.token_store_enabled
        token_refresh_extension_time      = auth_settings_v2.login.token_refresh_extension_time
        token_store_path                  = auth_settings_v2.login.token_store_path
        token_store_sas_setting_name      = auth_settings_v2.login.token_store_sas_setting_name
        preserve_url_fragments_for_logins = auth_settings_v2.login.preserve_url_fragments_for_logins
        allowed_external_redirect_urls    = auth_settings_v2.login.allowed_external_redirect_urls
        cookie_expiration_convention      = auth_settings_v2.login.cookie_expiration_convention
        cookie_expiration_time            = auth_settings_v2.login.cookie_expiration_time
        validate_nonce                    = auth_settings_v2.login.validate_nonce
        nonce_expiration_time             = auth_settings_v2.login.nonce_expiration_time
      }
    }

  }

  dynamic "backup" {
    for_each = var.backup == null ? [] : [var.backup]

    content {
      name                = backup.value["name"]
      storage_account_url = var.sas_urls[(backup.value["sas_reference"])]
      enabled             = backup.value["enabled"]

      schedule {
        frequency_interval       = backup.value["frequency_interval"]
        frequency_unit           = backup.value["frequency_unit"]
        keep_at_least_one_backup = backup.value["keep_at_least_one_backup"]
        retention_period_days    = backup.value["retention_period_days"]
      }
    }
  }

  dynamic "connection_string" {
    for_each = { for k in var.connection_strings : k.name => k if k != null }

    content {
      name  = connection_string.key
      type  = connection_string.value["type"]
      value = var.connection_string_values[(connection_string.value["value_reference"])]
    }
  }

  identity {
    type = "SystemAssigned"
  }

  logs {
    detailed_error_messages = var.logs.detailed_error_messages
    failed_request_tracing  = var.logs.failed_request_tracing

    application_logs {
      file_system_level = var.logs.application_logs.file_system_level

      azure_blob_storage {
        level             = var.logs.application_logs.azure_blob_storage.level
        retention_in_days = var.logs.application_logs.azure_blob_storage.retention_in_days
        sas_url           = var.sas_urls[(var.logs.application_logs.azure_blob_storage.sas_url_reference)]
      }
    }

    http_logs {

      azure_blob_storage {
        retention_in_days = var.logs.http_logs.azure_blob_storage_http.retention_in_days
        sas_url           = var.sas_urls[(var.logs.http_logs.azure_blob_storage_http.sas_url_reference)]
      }
    }
  }

  dynamic "sticky_settings" {
    for_each = var.sticky_settings == null ? [] : [var.sticky_settings]

    content {
      app_setting_names       = sticky_settings.value["app_setting_names"]
      connection_string_names = sticky_settings.value["connection_string_names"]
    }
  }

  tags = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "app_diagnostics" {
  name                       = "${var.log_analytics_workspace_name}-security-logging"
  target_resource_id         = azurerm_windows_web_app.web_app.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.logs.id

  log {
    category = "AppServiceHttpLogs"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }

  log {
    category = "AppServiceConsoleLogs"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }

  log {
    category = "AppServiceAppLogs"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }

  log {
    category = "AppServiceFileAuditLogs"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }

  log {
    category = "AppServiceAuditLogs"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }

  metric {
    category = "AllMetrics"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }
}
