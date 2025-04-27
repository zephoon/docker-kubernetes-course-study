# docker-kubernetes-course

https://www.youtube.com/watch?v=HJ6F05Pm5mQ&list=PLpbcUe4chE79sB7Jg7B4z3HytqUUEwcNE

<a href="https://www.youtube.com/watch?v=HJ6F05Pm5mQ&list=PLpbcUe4chE79sB7Jg7B4z3HytqUUEwcNE) 
  ![](https://github.com/HoussemDellai/docker-kubernetes-course/blob/main/videos.jpg?raw=true)
</a>


# Secure Ingress with TLS certificate using Secret Store CSI for Keyvault and Workload Identity

## Introduction

This lab aims to provide a guide on how to secure Ingress traffic using TLS certificate stored in Azure Keyvault.
The certificate will be retrieved using Secret Store CSI and Workload Identity.

The flow will be the following:
1. Operator creates TLS certificate and stores it in Keyvault.
2. Secret Store CSI provider pull TLS certificate from Keyvault.
3. Secret Store CSI driver sync TLS certificate into k8s Secret.
4. Ingress controller uses the TLS cert from the k8s secret.
5. Operator can rotate the TLS certificate in Keyvault.
6. Secret Store CSI driver sync TLS certificate into k8s Secret.
7. Ingress controller will ‘hot reload’ the cert (no reboot).

![](images/31_https_ingress_pods_kv_oidc__tls-ingress-keyvault-oidc.png)

The lab steps:
1. Create an AKS cluster with Secret Store CSI and Workload Identity enabled
2. Create tls certificate for ingress
3. Create a Keyvault instance
4. Import the TLS certificate into a keyvault certificate
5. Create a user managed Identity
6. Create Service Account for the app that need federated credential
7. Configure federated credential
8. Configure SecretProviderClass to retrieve keyvault secret and save it into kubernetes secret
9. Create deployment that uses the service account and secret store CSI driver
10. Install Nginx Ingress Controller with custom name into a dedicated namespace
11. Configure Ingress' Public IP with DNS Name
12. Deploy Ingress resource taht will retrieve TLS certificate from secret
13. Check app is working with HTTPS

More details: https://azure.github.io/secrets-store-csi-driver-provider-azure/docs/configurations/ingress-tls/#deploy-an-ingress-resource-referencing-the-secret-created-by-the-csi-driver

## 1. Create an AKS cluster with Secret Store CSI and Workload Identity enabled

```shell
AKS_RG="rg-aks-apim-0420"
AKS_NAME="aks-cluster-01"

az group create -n $AKS_RG -l eastasia

az aks create -g $AKS_RG -n $AKS_NAME `
              --kubernetes-version "1.25.2" `
              --enable-managed-identity `
              --node-count 2 `
              --network-plugin azure `
              --enable-oidc-issuer `
              --enable-workload-identity `
              --enable-addons azure-keyvault-secrets-provider `
              --rotation-poll-interval 5m `
              --enable-secret-rotation
```

## 1.1. Verify connection to the cluster

```shell
az aks get-credentials --name $AKS_NAME -g $AKS_RG --overwrite-existing

kubectl get nodes
# NAME                                STATUS   ROLES   AGE     VERSION
# aks-nodepool1-42043316-vmss000000   Ready    agent   5m23s   v1.25.2
# aks-nodepool1-42043316-vmss000001   Ready    agent   5m26s   v1.25.2
```

Get issuer URL

```shell
AKS_OIDC_ISSUER=$(az aks show -n $AKS_NAME -g $AKS_RG --query "oidcIssuerProfile.issuerUrl" -o tsv)
echo $AKS_OIDC_ISSUER
# https://westeurope.oic.prod-aks.azure.com/16b3c013-d300-468d-ac64-7eda0820b6d3/842120d9-99dd-44dc-be68-91f78bdd41ed/
```

Check deloyment success for Secret Store CSI

```shell
kubectl get pods -n kube-system -l 'app in (secrets-store-csi-driver, secrets-store-provider-azure)'
# NAME                                     READY   STATUS    RESTARTS   AGE
# aks-secrets-store-csi-driver-knhnr       3/3     Running   0          24m
# aks-secrets-store-csi-driver-mpd6q       3/3     Running   0          24m
# aks-secrets-store-provider-azure-4ckgq   1/1     Running   0          24m
# aks-secrets-store-provider-azure-88snb   1/1     Running   0          24m

# Check the created Manageed Identity
az aks show -n $AKS_NAME -g $AKS_RG --query addonProfiles.azureKeyvaultSecretsProvider.identity.clientId
# 47744279-8b5e-4c77-9102-7c6c1874587a
# we won't use this (default) managed identity, we'll use our own
```

## 2. Create tls certificate for ingress

Later on, we'll set a domain name for the load balancer public IP. 
We'll use this URL: aks-app-07.westeurope.cloudapp.azure.com

```shell
DNS_NAME="webapi-dns"

CERT_NAME="aks-ingress-cert"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-out ./aks-ingress-tls.crt \
-keyout ./aks-ingress-tls.key \
-subj "/CN=$DNS_NAME.internal.webapi/O=aks-ingress-tls" \
-addext "subjectAltName = DNS:$DNS_NAME.internal.webapi"

openssl pkcs12 -export -in ./aks-ingress-tls.crt -inkey ./aks-ingress-tls.key -out "$CERT_NAME.pfx"
# skip Password prompt
# Enter Export Password:
# Verifying - Enter Export Password:
```

or https://learn.microsoft.com/en-us/azure/application-gateway/self-signed-certificates

# CA
openssl ecparam -out root.key -name prime256v1 -genkey
openssl req -new -sha256 -key root.key -out root.csr
openssl x509 -req -sha256 -days 365 -in root.csr -signkey root.key -out root.crt
openssl pkcs12 -export -in ./root.crt -inkey ./root.key -out root.pfx
# server cert
openssl ecparam -out aks-ingress-tls.key -name prime256v1 -genkey
openssl req -new -sha256 -key aks-ingress-tls.key -out aks-ingress-tls.csr
openssl x509 -req -in aks-ingress-tls.csr -CA root.crt -CAkey root.key -CAcreateserial -out aks-ingress-tls.crt -days 365 -sha256
# pfx
openssl pkcs12 -export -in ./aks-ingress-tls.crt -inkey ./aks-ingress-tls.key -out aks-ingress-cert.pfx
```
root.crt
root.key
aks-ingress-tls.crt
aks-ingress-tls.key
aks-ingress-cert.pfx
```


# Generate the CA Key and Certificate
# https://awkwardferny.medium.com/configuring-certificate-based-mutual-authentication-with-kubernetes-ingress-nginx-20e7e38fdfca
```
<!-- $ openssl req -x509 -sha256 -newkey rsa:4096 -keyout ca.key.pem -out ca.cert.pem -days 356 -nodes -config rootCA.cnf -->
$ openssl req -x509 -sha256 -newkey rsa:4096 -keyout ca.key.pem -out ca.cert.pem -days 356 -nodes
# varify the root certificate
# CN=Zephoon
openssl x509 -noout -text -in ca.cert.pem

# Generate the Server Key, and Certificate and Sign with the CA Certificate
$ openssl req -new -newkey rsa:2048 -keyout aks-ingress-tls.key -out aks-ingress-tls.csr -nodes -subj "/CN=$DNS_NAME.internal.webapi/O=aks-ingress-tls" -addext "subjectAltName = DNS:$DNS_NAME.internal.webapi"
$ openssl x509 -req -sha256 -days 365 -in aks-ingress-tls.csr -CA ca.cert.pem -CAkey ca.key.pem -set_serial 01 -out aks-ingress-tls.crt

openssl x509 -noout -text -in aks-ingress-tls.crt

# Generate the Client Key, and Certificate and Sign with the CA Certificate
$ openssl req -new -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=Zephoon"
$ openssl x509 -req -sha256 -days 365 -in client.csr -CA ca.cert.pem -CAkey ca.key.pem -set_serial 02 -out client.crt

openssl x509 -noout -text -in client.crt

# pfx
openssl pkcs12 -export -in ./ca.cert.pem -inkey ./ca.key.pem -out ca.pfx 
openssl pkcs12 -export -in ./aks-ingress-tls.crt -inkey ./aks-ingress-tls.key -out aks-ingress-cert.pfx
openssl pkcs12 -export -in ./client.crt -inkey ./client.key -out client.pfx

# pem
openssl x509 -in ca.cert.pem -out ca.cert.pem -outform PEM

openssl x509 -in ca.crt -out ca.crt.pem -outform PEM

openssl verify -CAfile ca.cert.pem aks-ingress-cert.pfx
openssl verify -CAfile ca.cert.pem client.pfx
``` 

# disable certificate chain validation if using self-signed certificates
# https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates
```
$context = New-AzApiManagementContext -resourcegroup 'rg-aks-apim-2302' -servicename 'apim-external-aks-2302'

New-AzApiManagementBackend -Context $context -Url 'https://flask-app.pri01.dnszone.com/api/v1/hello' -Protocol http -SkipCertificateChainValidation $true -SkipCertificateNameValidation $true

Set-AzApiManagementBackend -Context $context -BackendId 03f8b7f0c7274e8395b55832d3895e9d -Description "updated description" -Url 'https://flask-app.pri01.dnszone.com' -SkipCertificateChainValidation $true -SkipCertificateNameValidation $true

```

```

az apim api list --resource-group rg-aks-apim-2302 --service-name apim-external-aks-2302

az rest --method get --uri https://management.azure.com/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-2302/providers/Microsoft.ApiManagement/service/apim-external-aks-2302/backends?api-version=2024-05-01 --headers "Authorization: Bearer $azureAccessToken" "Content-Type: application/json"

az rest --method patch --url https://management.azure.com/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-2302/providers/Microsoft.ApiManagement/service/apim-external-aks-2302/backends/api-albums?api-version=2024-05-01 --body "{'properties': {'description': 'description5308','tls': {'validateCertificateChain': false,'validateCertificateName': true}}}"

PATCH https://management.azure.com/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-2302/providers/Microsoft.ApiManagement/service/apim-external-aks-2302/backends/api-albums?api-version=2024-05-01

Request Body:
{
  "properties": {
    "description": "description5308",
    "tls": {
      "validateCertificateChain": false,
      "validateCertificateName": true
    }
  }
}
```
## 3. Create a Keyvault instance

```shell
AKV_NAME="kv4aks0420"

# az keyvault create -n $AKV_NAME -g $AKS_RG --enable-rbac-authorization

AKV_ID=$(az keyvault show -n $AKV_NAME -g $AKS_RG --query id -o tsv)
echo $AKV_ID
# /subscriptions/82f6d75e-85f4-xxxx-xxxx-5dddd9fa8910/resourceGroups/rg-aks-dev/providers/Microsoft.KeyVault/vaults/akvaksapp0137

CURRENT_USER_ID=$(az ad signed-in-user show --query id -o tsv)
echo $CURRENT_USER_ID
```

Assign admin role to my self

```shell
az role assignment create --assignee $CURRENT_USER_ID \
--role "Key Vault Administrator" \
--scope $AKV_ID
```

## 4. Import the TLS certificate into a keyvault certificate

```shell
az keyvault certificate import --vault-name $AKV_NAME -n $CERT_NAME -f "$CERT_NAME.pfx"
```

![](images/31_https_ingress_pods_kv_oidc__keyvault-cert.png)

## 5. Create a user managed Identity

```shell
IDENTITY_NAME="keyvault-identity"

az identity create -g $AKS_RG -n $IDENTITY_NAME

IDENTITY_ID=$(az identity show -g $AKS_RG -n $IDENTITY_NAME --query "id" -o tsv)
echo $IDENTITY_ID
# /subscriptions/82f6d75e-85f4-434a-ab74-5dddd9fa8910/resourcegroups/rg-aks-we/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvault-identity

IDENTITY_CLIENT_ID=$(az identity show -g $AKS_RG -n $IDENTITY_NAME --query "clientId" -o tsv)
echo $IDENTITY_CLIENT_ID
# 75d8e078-d9a7-4a4c-b75e-d18225377711
```

Assign role "Key Vault Secrets User" on Keyvault to managed identity

```shell
az role assignment create --assignee $IDENTITY_CLIENT_ID `
        --role "Key Vault Secrets User" `
        --scope $AKV_ID
```

![](images/31_https_ingress_pods_kv_oidc__identity-role-assignment.png)

## 6. Create Service Account for the app that need federated credential

```shell
NAMESPACE_APP="app-07" # can be changed to namespace of your workload

kubectl create namespace $NAMESPACE_APP
## namespace/app-07 created

SERVICE_ACCOUNT_NAME="workload-identity-sa"

cat <<EOT >> service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: $IDENTITY_CLIENT_ID
  labels:
    azure.workload.identity/use: "true"
  name: $SERVICE_ACCOUNT_NAME
EOT

kubectl apply -f service-account.yaml --namespace $NAMESPACE_APP
# serviceaccount/workload-identity-sa created
```

## 7. Configure federated credential

```shell
FEDERATED_IDENTITY_NAME="aksfederatedidentity"

az identity federated-credential create --name $FEDERATED_IDENTITY_NAME \
--resource-group $AKS_RG \
--identity-name $IDENTITY_NAME \
--issuer $AKS_OIDC_ISSUER \
--subject system:serviceaccount:${NAMESPACE_APP}:${SERVICE_ACCOUNT_NAME}

# {
#   "audiences": [
#     "api://AzureADTokenExchange"
#   ],
#   "id": "/subscriptions/82f6d75e-85f4-434a-ab74-5dddd9fa8910/resourcegroups/rg-aks-we/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvault-identity/federatedIdentityCredentials/aksfederatedidentity",
#   "issuer": "https://westeurope.oic.prod-aks.azure.com/16b3c013-d300-468d-ac64-7eda0820b6d3/842120d9-99dd-44dc-be68-91f78bdd41ed/",
#   "name": "aksfederatedidentity",
#   "resourceGroup": "rg-aks-we",
#   "subject": "system:serviceaccount:ingress-nginx-app-07:workload-identity-sa",
#   "type": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"
# }

```

![](images/31_https_ingress_pods_kv_oidc__federated-cred.png)

## 8. Configure SecretProviderClass to retrieve keyvault secret and save it into kubernetes secret

```shell
TLS_SECRET="tls-secret-csi-app-07"

TENANT_ID=$(az account list --query "[?isDefault].tenantId" -o tsv)
echo $TENANT_ID
# 9d427af2-14f5-4a21-ad29-9bf8683da155

SECRET_PROVIDER_CLASS="azure-tls-spc-app-07"


cat <<EOT >> secretProviderClass.yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: $SECRET_PROVIDER_CLASS
spec:
  provider: azure
  secretObjects: # k8s secret
  - secretName: $TLS_SECRET
    type: kubernetes.io/tls
    data: 
    - objectName: $CERT_NAME
      key: tls.key
    - objectName: $CERT_NAME
      key: tls.crt
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "false"
    userAssignedIdentityID: ""
    clientID: $IDENTITY_CLIENT_ID # Setting this to use workload identity
    keyvaultName: $AKV_NAME # the name of the AKV instance
    objects: |
      array:
        - |
          objectName: $CERT_NAME
          objectType: secret
    tenantId: $TENANT_ID # the tenant ID for KV
EOT

kubectl apply -f secretProviderClass.yaml -n $NAMESPACE_APP
# secretproviderclass.secrets-store.csi.x-k8s.io/azure-tls-spc-app-07 created

kubectl get secretProviderClass -n $NAMESPACE_APP
# NAME                   AGE
# azure-tls-spc-app-07   1s
```

## 9. Create deployment that uses the service account and secret store CSI driver

```shell
cat <<EOT >> app-deploy-svc.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-deploy
  template:
    metadata:
      labels:
        app: app-deploy
    spec:
      serviceAccountName: $SERVICE_ACCOUNT_NAME
      containers:
      - name: app-deploy
        image: acrdemo03022025.azurecr.io/applications/flask_app:v0.9-amd64
        ports:
        - containerPort: 6000
        volumeMounts:
        - name: secrets-store-inline
          mountPath: "/mnt/secrets-store"
          readOnly: true
      volumes:
        - name: secrets-store-inline
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: $SECRET_PROVIDER_CLASS
---
apiVersion: v1
kind: Service
metadata:
  name: app-svc
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 6000
    protocol: TCP
  selector:
    app: app-deploy
EOT

kubectl apply -f app-deploy-svc.yaml --namespace $NAMESPACE_APP
# deployment.apps/app-deploy created
# service/app-svc created
```

Check the app was deployed successfully

```shell
kubectl get pods,svc -n $NAMESPACE_APP
# NAME                                      READY   STATUS    RESTARTS   AGE
# pod/aks-helloworld-one-85bc95b4db-5phk6   1/1     Running   0          32s
# pod/aks-helloworld-two-5f89bff56-d47ft    1/1     Running   0          32s

# NAME                         TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)   AGE
# service/aks-helloworld-one   ClusterIP   10.0.206.22   <none>        80/TCP    32s
# service/aks-helloworld-two   ClusterIP   10.0.176.49   <none>        80/TCP    32s
```

Check the mounted Secret Store CSI volume with the secret file

```shell
POD_NAME=$(kubectl get pods -l app=app-deploy -n $NAMESPACE_APP -o jsonpath='{.items[0].metadata.name}')
echo $POD_NAME
# app-deploy-5bf5ddd8b5-chbk6

kubectl exec $POD_NAME -n $NAMESPACE_APP -it -- ls /mnt/secrets-store
aks-ingress-cert

kubectl exec $POD_NAME -n $NAMESPACE_APP -it -- cat /usr/local/share/ca-certificates/ca.cert.pem

kubectl exec $POD_NAME -n $NAMESPACE_APP -it -- cat /mnt/secrets-store/aks-ingress-cert
# -----BEGIN PRIVATE KEY-----
# MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRCLOabqmJwg+H
# yAQm9jLz0UBw09cdR9aqqsY+HCIy7PvpucrYn4qqW48HYP6S6CCUJEFvp8T3YyA0
# ...
# 8wP1JpXYTlgVnm6l4tFKZQ==
# -----END PRIVATE KEY-----
# -----BEGIN CERTIFICATE-----
# MIIDxzCCAq+gAwIBAgIUH3mg/xZQNa6i0j0Rdr8Y69tvKT8wDQYJKoZIhvcNAQEL
# BQAwVDE4MDYGA1UEAwwvYWtzLWFwcC0wNy1sb3JlYWwud2VzdGV1cm9wZS5jbG91
# ...
# 6RZTTToiRgfCXPU=
# -----END CERTIFICATE-----
```

Check the secret should have been created by the deployment

```shell
kubectl describe secret $TLS_SECRET -n $NAMESPACE_APP
# Name:         tls-secret-csi-app-07
# Namespace:    app-07
# Labels:       secrets-store.csi.k8s.io/managed=true
# Annotations:  <none>

# Type:  kubernetes.io/tls

# Data
# ====
# tls.crt:  1342 bytes
# tls.key:  1675 bytes
```

## 10. Install Nginx Ingress Controller with custom name into a dedicated namespace

```shell
NAMESPACE_INGRESS="ingress-nginx-internal"

kubectl create namespace $NAMESPACE_INGRESS
# namespace/ingress-nginx-app-07 created

# install Nginx ingress controller
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

INGRESS_CLASS_NAME="nginx-internal"

cat <<EOT >> ingress-controller-values.yaml
controller:
  ingressClassResource:
    name: $INGRESS_CLASS_NAME # default: nginx
    enabled: true
    default: false
    controllerValue: "k8s.io/ingress-$INGRESS_CLASS_NAME"
  service:
    external:
      enabled: false
    internal:
      enabled: true
      annotations:
        service.beta.kubernetes.io/azure-load-balancer-internal-subnet: "snet-aks"
EOT

helm upgrade --install ingress-nginx-app-08-internal ingress-nginx/ingress-nginx \
--create-namespace \
--namespace $NAMESPACE_INGRESS \
--set controller.replicaCount=2 \
--set controller.nodeSelector."kubernetes\.io/os"=linux \
--set defaultBackend.nodeSelector."kubernetes\.io/os"=linux \
--set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz \
-f ingress-controller-values.yaml

or

helm upgrade --install ingress-nginx-internal ./ingress-nginx-4.12.1.tgz \
--create-namespace \
--namespace $NAMESPACE_INGRESS \
--set controller.replicaCount=1 \
--set controller.nodeSelector."kubernetes\.io/os"=linux \
--set defaultBackend.nodeSelector."kubernetes\.io/os"=linux \
--set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz \
-f ingress-controller-values.yaml

```

helm upgrade --install ingress-nginx-app-07 ingress-nginx/ingress-nginx `
     --create-namespace `
     --namespace ingress-nginx-app-07 `
     --set controller.replicaCount=2 `
     --set controller.nodeSelector."kubernetes\.io/os"=linux `
     --set defaultBackend.nodeSelector."kubernetes\.io/os"=linux `
     --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz `
     —-set controller.service.annotations.”service\.beta\.kubernetes\.io/azure-load-balancer-internal"="true" `
     -f ingress-controller-values.yaml
```

Get the ingress class resources, note we already have one deployed in another demo

```shell
kubectl get ingressclass
# NAME           CONTROLLER                    PARAMETERS   AGE
# nginx-app-07   k8s.io/ingress-nginx-app-07   <none>       50s

kubectl get pods,svc -n $NAMESPACE_INGRESS
# NAME                                                   READY   STATUS    RESTARTS   AGE
# pod/ingress-nginx-app-07-controller-84754f8d77-4nk4s   1/1     Running   0          15m
# pod/ingress-nginx-app-07-controller-84754f8d77-745mr   1/1     Running   0          15m

# NAME                                                TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)                      AGE
# service/ingress-nginx-app-07-controller             LoadBalancer   10.0.93.183    20.101.208.164   80:32033/TCP,443:32039/TCP   15m
# service/ingress-nginx-app-07-controller-admission   ClusterIP      10.0.151.181   <none>           443/TCP                      15m
```

Capture ingress, public IP (Azure Public IP created)

```shell
INGRESS_PUPLIC_IP=$(kubectl get services ingress-$INGRESS_CLASS_NAME-controller-internal -n $NAMESPACE_INGRESS -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $INGRESS_PUPLIC_IP
# 20.101.208.164
```

## 11. Configure Ingress' Public IP with DNS Name

## 11.1. Option 1: Name to associate with Azure Public IP address

Get the resource-id of the public IP

```powershell
$NODE_RG=$(az aks show -g $AKS_RG -n $AKS_NAME --query nodeResourceGroup -o tsv)
echo $NODE_RG
# MC_rg-aks-demo_aks-cluster_westeurope

$AZURE_PUBLIC_IP_ID=$(az network public-ip list -g $NODE_RG --query "[?ipAddress!=null]|[?contains(ipAddress, '$INGRESS_PUPLIC_IP')].[id]" -o tsv)
echo $AZURE_PUBLIC_IP_ID
# /subscriptions/82f6d75e-85f4-xxxx-xxxx-5dddd9fa8910/resourceGroups/mc_rg-aks-demo_aks-cluster_westeurope/providers/Microsoft.Network/publicIPAddresses/kubernetes-a67a81403ec5e4ebca58049d0ebfda3c
```

Update public IP address with DNS name

```powershell
az network public-ip update --ids $AZURE_PUBLIC_IP_ID --dns-name $DNS_NAME
$DOMAIN_NAME_FQDN=$(az network public-ip show --ids $AZURE_PUBLIC_IP_ID --query='dnsSettings.fqdn' -o tsv)
# DOMAIN_NAME_FQDN=$(az network public-ip show -g MC_rg-aks-we_aks-cluster_westeurope -n kubernetes-af54fcf50c6b24d7fbb9ed6aa62bdc77 --query='dnsSettings.fqdn')
echo $DOMAIN_NAME_FQDN
# "aks-app-07.westeurope.cloudapp.azure.com"
```

![](images/31_https_ingress_pods_kv_oidc__public-ip.png)

## 11.2. Option 2: Name to associate with Azure DNS Zone

Add an A record to your DNS zone

```shell
INGRESS_PRIVATE_IP=$(kubectl get services ingress-$INGRESS_CLASS_NAME-controller-internal -n $NAMESPACE_INGRESS -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $INGRESS_PRIVATE_IP
az network private-dns record-set a add-record \
--resource-group rg-aks-apim-0420 \
--zone-name "internal.webapi" \
--record-set-name $DNS_NAME \
--ipv4-address $INGRESS_PRIVATE_IP

# az network public-ip update -g MC_rg-aks-we_aks-cluster_westeurope -n kubernetes-af54fcf50c6b24d7fbb9ed6aa62bdc77 --dns-name $DNS_NAME
DOMAIN_NAME_FQDN=$DNS_NAME.internal.webapi
echo $DOMAIN_NAME_FQDN
# aks-app-03.houssem.cloud
```

## 12. Deploy Ingress resource taht will retrieve TLS certificate from secret

```shell
cat <<EOT >> app-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: $INGRESS_CLASS_NAME # nginx
  tls:
  - hosts:
    - $DOMAIN_NAME_FQDN
    secretName: $TLS_SECRET
  rules:
  - host: $DOMAIN_NAME_FQDN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-svc
            port:
              number: 80
EOT

kubectl apply -f app-ingress.yaml --namespace $NAMESPACE_APP
```

Check Ingress created

```shell
kubectl get ingress --namespace $NAMESPACE_APP
# NAME                         CLASS          HOSTS                                      ADDRESS   PORTS     AGE
# hello-world-ingress          nginx-app-07   aks-app-07.westeurope.cloudapp.azure.com             80, 443   12s
# hello-world-ingress-static   nginx-app-07   aks-app-07.westeurope.cloudapp.azure.com             80, 443   11s
```

## 13. Check app is working with HTTPS

## check tls certificate

Open the app in the browser and check the link.

![](images/31_https_ingress_pods_kv_oidc__app-browser.png)

```shell

kubectl run -it --rm aks-ingress-test --image=mcr.microsoft.com/dotnet/runtime-deps:6.0 --namespace $NAMESPACE_APP
apt-get update && apt-get install -y curl && \
apt-get install -y iputils-ping && \
apt-get install -y vim && \
apt-get install -y openssl

# curl -v -k --resolve $DOMAIN_NAME_FQDN:443:$INGRESS_PRIVATE_IP https://$DOMAIN_NAME_FQDN
curl -v -k --resolve webapi-dns.internal.webapi:443:10.10.0.112 https://webapi-dns.internal.webapi/api/v1/hello

kubectl create secret generic ca-secret --from-file=ca.crt=./cert/ca.cert.pem -n $NAMESPACE_APP


curl -v -k --insecure https://webapi-dns.internal.webapi
curl -v -k https://webapi-dns.internal.webapi/api/v1/hello
curl -v https://webapi-dns.internal.webapi/api/v1/hello
curl https://webapi-dns.internal.webapi/api/v1/hello --cert client.crt --key client.key --cacert ca.cert.pem -k -v
openssl x509 -in ca.crt -out ca.pem -outform PEM
openssl s_client -CAfile ca.cert.pem -servername webapi-dns.internal.webapi -connect 10.10.0.112:443
openssl s_client -CAfile ca.cert.pem  -servername webapi-dns.internal.webapi -connect 10.10.0.112:443
openssl s_client -showcerts -connect 10.10.0.112:443
openssl s_client -showcerts -connect webapi-dns.internal.webapi:443 -servername webapi-dns.internal.webapi

openssl x509 -noout -text -in client.crt

kubectl exec -n $NAMESPACE_APP pod/app-deploy-5988466b69-jnfcq  -it -- /bin/sh

# MAIN_NAME_FQDN
# * Added aks-app-07.westeurope.cloudapp.azure.com:443:20.238.249.157 to DNS cache
# * Hostname aks-app-07.westeurope.cloudapp.azure.com was found in DNS cache
# *   Trying 20.238.249.157:443...
# * Connected to aks-app-07.westeurope.cloudapp.azure.com (20.238.249.157) port 443 (#0)
# * TLSv1.3 (IN), TLS handshake, CERT verify (15):
# * TLSv1.3 (OUT), TLS handshake, Finished (20):
# * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
# * ALPN, server accepted to use h2
# * Server certificate:
# *  subject: CN=aks-app-07.westeurope.cloudapp.azure.com; O=aks-ingress-tls
# *  start date: Nov 25 11:12:44 2022 GMT
# *  expire date: Nov 25 11:12:44 2023 GMT
# *  issuer: CN=aks-app-07.westeurope.cloudapp.azure.com; O=aks-ingress-tls
# *  SSL certificate verify result: self-signed certificate (18), continuing anyway.
# ...
```


------------
https://learn.microsoft.com/en-us/azure/application-gateway/self-signed-certificates

------------
Enable tracing for an API
https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-api-inspector#enable-tracing-for-an-api

az apim api list --resource-group 'rg-aks-apim-2302' --service-name 'apim-external-aks-2302' -o table

az rest --method post --url https://management.azure.com/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-2302/providers/Microsoft.ApiManagement/service/apim-external-aks-2302/gateways/managed/listDebugCredentials?api-version=2023-05-01-preview



a0ab50fffd6e41abae886f53de46f2e4

# Manually auto-rotation on an existing AKS cluster
# https://learn.microsoft.com/en-us/azure/aks/certificate-rotation
az aks rotate-certs --resource-group $RESOURCE_GROUP_NAME --name $CLUSTER_NAME
<!-- az aks addon update --resource-group rg-aks-apim-0420 --name aks-cluster-01 --enable-secret-rotation --rotation-poll-interval 5m -->


# Custom certificate authority (CA) in Azure Kubernetes Service (AKS)
# https://learn.microsoft.com/en-us/azure/aks/custom-certificate-authority#install-cas-on-your-nodes-trust-store
```
az rest --method get --url "/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-0420/providers/Microsoft.ContainerService/managedClusters/aks-cluster-01?api-version=2025-01-01" > body.json

cat ca.cert.pem | base64

 "securityProfile": {
    "customCaTrustCertificates": [
        "value"

az rest --method put --url "/subscriptions/edccbd3e-fb14-444d-92ae-e43da2008c69/resourceGroups/rg-aks-apim-0420/providers/Microsoft.ContainerService/managedClusters/aks-cluster-01?api-version=2025-01-01" --body @body.json

az aks show -g rg-aks-apim-0420 -n aks-cluster-01 | grep securityProfile -A 4

kubectl get nodes -o wide
kubectl debug node/aks-mainpool-15193716-vmss00000b -it --image=mcr.microsoft.com/cbl-mariner/busybox:2.0
```

REGISTRY_NAME=<REGISTRY_NAME>
CERT_MANAGER_REGISTRY=quay.io
CERT_MANAGER_TAG=v1.8.0
CERT_MANAGER_IMAGE_CONTROLLER=jetstack/cert-manager-controller
CERT_MANAGER_IMAGE_WEBHOOK=jetstack/cert-manager-webhook
CERT_MANAGER_IMAGE_CAINJECTOR=jetstack/cert-manager-cainjector


# import cert manager
az acr import --name $REGISTRY_NAME --source $CERT_MANAGER_REGISTRY/$CERT_MANAGER_IMAGE_CONTROLLER:$CERT_MANAGER_TAG --image $CERT_MANAGER_IMAGE_CONTROLLER:$CERT_MANAGER_TAG
az acr import --name $REGISTRY_NAME --source $CERT_MANAGER_REGISTRY/$CERT_MANAGER_IMAGE_WEBHOOK:$CERT_MANAGER_TAG --image $CERT_MANAGER_IMAGE_WEBHOOK:$CERT_MANAGER_TAG
az acr import --name $REGISTRY_NAME --source $CERT_MANAGER_REGISTRY/$CERT_MANAGER_IMAGE_CAINJECTOR:$CERT_MANAGER_TAG --image $CERT_MANAGER_IMAGE_CAINJECTOR:$CERT_MANAGER_TAG


# secure-your-aks-ingress-with-letsencrypt-and-cert-manager
# https://mrdevops.medium.com/secure-your-aks-ingress-with-letsencrypt-and-cert-manager-97a698418cf3

# https://medium.com/@badawekoo/apply-mutual-tls-over-kubernetes-nginx-ingress-controller-4ea203bce3e0