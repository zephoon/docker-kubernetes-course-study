resource "azurerm_kubernetes_cluster" "aks" {
  name                    = "aks-cluster-01"
  location                = azurerm_resource_group.rg.location
  resource_group_name     = azurerm_resource_group.rg.name
  dns_prefix              = "aks"
  kubernetes_version      = "1.30.0"
  private_cluster_enabled = false
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  network_profile {
    network_plugin      = "azure"
  }

  default_node_pool {
    name                  = "mainpool"
    node_count            = 1
    vm_size               = "Standard_A4_v2"
    os_sku                = "AzureLinux"
    vnet_subnet_id        = azurerm_subnet.snet-aks.id
    enable_node_public_ip = false
  }

  identity {
    type = "SystemAssigned"
  }

  lifecycle {
    ignore_changes = [
      default_node_pool.0.upgrade_settings
    ]
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
    secret_rotation_interval = "2m"
  }
  
  role_based_access_control_enabled = true
  
  azure_active_directory_role_based_access_control {
    managed = true
    tenant_id = data.azurerm_client_config.current.tenant_id
    admin_group_object_ids = ["ec0b1339-db05-4fd9-ae72-f64c223aa401", "91fc859d-2740-4ca5-b84e-0ac36172dedf"] # Optional: Specify AAD group for admin access
    azure_rbac_enabled = true
  }

}

# Required to create internal Load Balancer for Nginx Ingress Controller
resource "azurerm_role_assignment" "network-contributor" {
  scope                = azurerm_subnet.snet-aks.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_kubernetes_cluster.aks.identity.0.principal_id
}

resource "terraform_data" "aks-get-credentials" {
  triggers_replace = [
    azurerm_kubernetes_cluster.aks.id
  ]

  provisioner "local-exec" {
    command = "az aks get-credentials -n ${azurerm_kubernetes_cluster.aks.name} -g ${azurerm_kubernetes_cluster.aks.resource_group_name} --overwrite-existing"
  }
}
