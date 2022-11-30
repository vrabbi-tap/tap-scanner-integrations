# trivy-scanner-integration

## Install Repository
```bash
tanzu package repository add tap-scanner-integrations --url ghcr.io/vrabbi-tap/tap-scanning-examples-repo:0.1.1 --namespace tap-install --create-namespace
```  
  
## Install Packages
```bash
kubectl create namespace trivy-test
kubectl apply -f https://raw.githubusercontent.com/vrabbi-tap/tap-scanner-integrations/main/examples/pkgis.yaml
```
