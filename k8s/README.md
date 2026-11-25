Kubernetes manifests for Hickory DNS

Apply the production manifests (creates namespace, secrets, postgres, control-api, ui, ingress):

kubectl apply -f namespace.yaml
cp secret.example.yaml secret.yaml
# Edit secret.yaml with newly issued credentials and certificates before applying.
kubectl apply -f secret.yaml -n hickory
kubectl apply -f postgres-statefulset.yaml -n hickory
kubectl apply -f control-api-deployment.yaml -n hickory
kubectl apply -f ui-deployment.yaml -n hickory
kubectl apply -f ingress.yaml -n hickory

Notes:
- Never commit `secret.yaml`; it is ignored by Git. Create it from `secret.example.yaml` and replace every placeholder before applying.
- Update image names in `control-api-deployment.yaml` and `ui-deployment.yaml` to point to your registry.
- Ensure you have an Ingress controller (nginx) and DNS entries pointing to it for `hickory.local`.
