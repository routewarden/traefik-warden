# Example 05: Kubernetes IngressRoute (Traefik CRD)

Deploy RouteWarden natively within Kubernetes clusters managed by the Traefik Ingress Controller.

## Prerequisites

1. Kubernetes cluster with Traefik Ingress Controller installed.
2. Static plugin enabled in Traefik's Helm values or command args:
```yaml
additionalArguments:
  - "--experimental.plugins.routewarden.modulename=github.com/routewarden/traefik-warden"
  - "--experimental.plugins.routewarden.version=v1.0.0"
```

## Applying the CRD

```bash
kubectl apply -f ingressroute.yaml
```

Inspect middleware state:
```bash
kubectl get middleware routewarden-k8s-shield -o yaml
```
