Kubernetes manifests for Hickory DNS

Apply the production manifests (creates namespace, secrets, postgres, control-api, ui, ingress):

kubectl apply -f namespace.yaml
kubectl apply -f secret.yaml -n hickory
kubectl apply -f postgres-statefulset.yaml -n hickory
kubectl apply -f control-api-deployment.yaml -n hickory
kubectl apply -f ui-deployment.yaml -n hickory
kubectl apply -f ingress.yaml -n hickory

Notes:
- Replace secret values in `secret.yaml` before applying.
- Update image names in `control-api-deployment.yaml` and `ui-deployment.yaml` to point to your registry.
- Ensure you have an Ingress controller (nginx) and DNS entries pointing to it for `hickory.local`.
