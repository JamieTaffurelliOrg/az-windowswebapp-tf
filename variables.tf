variable "web_app_name" {
  type        = string
  description = "The name of the web app to deploy"
}

variable "resource_group_name" {
  type        = string
  description = "The name of the resource group to deploy the web app to"
}

variable "service_plan_name" {
  type        = string
  description = "The name of the service plan to deploy the web app to"
}

variable "service_plan_resource_group_name" {
  type        = string
  description = "The name of the resource group of the service plan to deploy the web app to"
}

variable "enabled" {
  type        = bool
  default     = true
  description = "Enable web app"
}

variable "client_affinity_enabled" {
  type        = bool
  default     = false
  description = "Enable cookie affinity"
}

variable "client_certificate_enabled" {
  type        = bool
  default     = false
  description = "Enable client certificate"
}

variable "client_certificate_mode" {
  type        = string
  default     = "Required"
  description = "Access settings for client certificate"
}

variable "client_certificate_exclusion_paths" {
  type        = string
  default     = null
  description = "Exclude URL paths from client certificate check"
}

variable "https_only" {
  type        = bool
  default     = true
  description = "Force HTTPS connections"
}

variable "zip_deploy_file" {
  type        = string
  default     = null
  description = "Local path of zip file to deploy"
}

variable "always_on" {
  type        = bool
  default     = true
  description = "Force HTTPS connections"
}

variable "api_definition_url" {
  type        = string
  default     = null
  description = "URL to API definition"
}

variable "api_management_api_id" {
  type        = string
  default     = null
  description = "Associated API Management ID"
}

variable "app_command_line" {
  type        = string
  default     = null
  description = "App command line to launch app"
}

variable "auto_heal_enabled" {
  type        = bool
  default     = true
  description = "Enable auto-heal"
}

variable "container_registry_use_managed_identity" {
  type        = bool
  default     = false
  description = "Should connections for Azure Container Registry use Managed Identity."
}

variable "container_registry_managed_identity_client_id" {
  type        = string
  default     = null
  description = "The Client ID of the Managed Service Identity to use for connections to the Azure Container Registry."
}

variable "default_documents" {
  type        = list(string)
  default     = null
  description = "Specifies a list of Default Documents for the Linux Web App."
}

variable "health_check_path" {
  type        = string
  description = "The path to the Health Check."
}

variable "health_check_eviction_time_in_min" {
  type        = number
  default     = 2
  description = "The amount of time in minutes that a node can be unhealthy before being removed from the load balancer. Possible values are between 2 and 10. Only valid in conjunction with health_check_path."
}

variable "load_balancing_mode" {
  type        = string
  default     = "LeastRequests"
  description = "The Site load balancing. Possible values include: WeightedRoundRobin, LeastRequests, LeastResponseTime, WeightedTotalTraffic, RequestHash, PerSiteRoundRobin."
}

variable "local_mysql_enabled" {
  type        = bool
  default     = false
  description = "Use Local MySQL"
}

variable "scm_use_main_ip_restriction" {
  type        = bool
  default     = true
  description = "Should the Linux Web App ip_restriction configuration be used for the SCM also."
}

variable "use_32_bit_worker" {
  type        = bool
  default     = false
  description = "Run on 32-bit worker"
}

variable "vnet_route_all_enabled" {
  type        = bool
  default     = true
  description = "Apply NAT Gateways, Network Security Groups and User Defined Routes to all outbound traffic "
}

variable "websockets_enabled" {
  type        = bool
  default     = false
  description = "Enable web sockets"
}

variable "worker_count" {
  type        = number
  default     = null
  description = "The number of Workers"
}

variable "app_settings" {
  type        = map(string)
  default     = {}
  sensitive   = true
  description = "Key-Value pairs of app settings"
}

variable "auto_heal_setting" {
  type = object({
    minimum_process_execution_time = string
    requests = optional(list(object({
      count    = number
      interval = string
    })), [])
    slow_requests = optional(list(object({
      count      = number
      interval   = string
      time_taken = string
      path       = optional(string)
    })), [])
    status_codes = optional(list(object({
      count             = number
      interval          = string
      status_code_range = string
      path              = optional(string)
      sub_status        = optional(number)
      win32_status      = optional(number)
    })), [])
  })
  description = "Auto heal settings"
}

variable "ip_restrictions" {
  type = list(object({
    name                      = string
    action                    = optional(string, "Allow")
    ip_address                = optional(string)
    priority                  = number
    service_tag               = optional(string)
    virtual_network_subnet_id = optional(string)
    headers = optional(object({
      x_azure_fdid_reference      = optional(string)
      x_fd_health_probe_reference = optional(string)
      x_forwarded_for_reference   = optional(string)
      x_forwarded_host_reference  = optional(string)
    }))
  }))
  default     = []
  description = "IP restrictions for the app"
}

variable "scm_ip_restrictions" {
  type = list(object({
    name                      = string
    action                    = optional(string, "Allow")
    ip_address                = optional(string)
    priority                  = number
    service_tag               = optional(string)
    virtual_network_subnet_id = optional(string)
    headers = optional(object({
      x_azure_fdid_reference      = optional(string)
      x_fd_health_probe_reference = optional(string)
      x_forwarded_for_reference   = optional(string)
      x_forwarded_host_reference  = optional(string)
    }))
  }))
  default     = []
  description = "SCM IP restrictions for the app"
}

variable "headers" {
  type = map(object({
    x_azure_fdid      = optional(string)
    x_fd_health_probe = optional(string)
    x_forwarded_for   = optional(string)
    x_forwarded_host  = optional(string)
  }))
  default     = {}
  sensitive   = true
  description = "Headers to use for IP restrictions"
}

variable "cors" {
  type = object({
    allowed_origins     = list(string)
    support_credentials = optional(bool, false)
  })
  default     = null
  description = "Cross Origin Resource Sharing settings"
}

variable "auth_settings_v2" {
  type = object({
    auth_enabled                            = optional(bool, true)
    runtime_version                         = optional(string, "~1")
    config_file_path                        = optional(string)
    require_authentication                  = optional(bool, true)
    unauthenticated_action                  = optional(string, "RedirectToLoginPage")
    default_provider                        = optional(string)
    excluded_paths                          = optional(list(string))
    http_route_api_prefix                   = optional(string, "/.auth")
    forward_proxy_convention                = optional(string, "ForwardProxyConventionNoProxy")
    forward_proxy_custom_host_header_name   = optional(string)
    forward_proxy_custom_scheme_header_name = optional(string)
    apple_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
    }))
    active_directory_v2 = optional(object({
      tenant_auth_endpoint                 = string
      client_id                            = string
      client_secret_setting_name           = optional(string)
      client_secret_certificate_thumbprint = optional(string)
      jwt_allowed_groups                   = optional(list(string))
      jwt_allowed_client_applications      = optional(list(string))
      www_authentication_disabled          = optional(bool, false)
      allowed_groups                       = optional(list(string))
      allowed_identities                   = optional(list(string))
      allowed_applications                 = optional(list(string))
      login_parameters                     = optional(map(string))
      allowed_audiences                    = optional(list(string))
    }))
    azure_static_web_app_v2 = optional(object({
      client_id = string
    }))
    custom_oidc_v2 = optional(list(object({
      name                          = string
      client_id                     = string
      openid_configuration_endpoint = string
      name_claim_type               = optional(string)
      scopes                        = optional(list(string))
      client_credential_method      = string
      client_secret_setting_name    = string
      authorisation_endpoint        = string
      token_endpoint                = string
      issuer_endpoint               = string
      certification_uri             = string
    })))
    facebook_v2 = optional(object({
      app_id                  = string
      app_secret_setting_name = string
      graph_api_version       = optional(string)
      login_scopes            = optional(list(string))
    }))
    github_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      login_scopes               = optional(list(string))
    }))
    google_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      allowed_audiences          = optional(list(string))
      login_scopes               = optional(list(string))
    }))
    microsoft_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      allowed_audiences          = optional(list(string))
      login_scopes               = optional(list(string))
    }))
    twitter_v2 = optional(object({
      consumer_key                 = string
      consumer_secret_setting_name = string
    }))
    login = object({
      logout_endpoint                   = optional(string)
      token_store_enabled               = optional(bool, false)
      token_refresh_extension_time      = optional(number, 72)
      token_store_path                  = optional(string)
      token_store_sas_setting_name      = optional(string)
      preserve_url_fragments_for_logins = optional(bool, false)
      allowed_external_redirect_urls    = optional(list(string))
      cookie_expiration_convention      = optional(string, "FixedTime")
      cookie_expiration_time            = optional(string, "08:00:00")
      validate_nonce                    = optional(bool, true)
      nonce_expiration_time             = optional(string, "05:00:00")
    })
  })
  default     = null
  description = "Authentication settings"
}

variable "backup" {
  type = object({
    name                     = string
    sas_reference            = string
    enabled                  = optional(bool, true)
    frequency_interval       = number
    frequency_unit           = string
    keep_at_least_one_backup = optional(bool, false)
    retention_period_days    = number
  })
  default     = null
  description = "Backup settings"
}

variable "sas_urls" {
  type        = map(string)
  default     = {}
  sensitive   = true
  description = "Storage Account SAS urls"
}

variable "connection_strings" {
  type = list(object({
    name            = string
    type            = string
    value_reference = string
  }))
  default     = []
  description = "Connection strings for the app"
}

variable "connection_string_values" {
  type        = map(string)
  default     = {}
  sensitive   = true
  description = "Connection string values for the app"
}

variable "logs" {
  type = object({
    detailed_error_messages = optional(bool, true)
    failed_request_tracing  = optional(bool, true)
    application_logs = object({
      file_system_level = optional(string, "Information")
      azure_blob_storage = object({
        level             = optional(string, "Information")
        retention_in_days = optional(number, 365)
        sas_url_reference = string
      })
    })
    http_logs = object({
      azure_blob_storage_http = object({
        retention_in_days = optional(number, 365)
        sas_url_reference = string
      })
    })
  })
  description = "Logging settings"
}

variable "sticky_settings" {
  type = object({
    app_setting_names       = optional(list(string))
    connection_string_names = optional(list(string))
  })
  default     = null
  description = "Settings that dont change on slot swap"
}

variable "application_stack" {
  type = object({
    current_stack                = optional(string)
    docker_image                 = optional(string)
    dotnet_version               = optional(string)
    dotnet_core_version          = optional(string)
    tomcat_version               = optional(string)
    java_embedded_server_enabled = optional(bool, false)
    java_version                 = optional(string)
    node_version                 = optional(string)
    python_enabled               = optional(bool, false)
  })
  description = "Application stack settings"
}

variable "log_analytics_workspace_name" {
  type        = string
  description = "Name of Log Analytics Workspace to send diagnostics"
}

variable "log_analytics_workspace_resource_group_name" {
  type        = string
  description = "Resource Group of Log Analytics Workspace to send diagnostics"
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply"
}
