# Deployment Guide

This guide covers building, containerizing, and deploying ESCANORR to Kubernetes via Helm.

---

## Prerequisites

- Docker 24+
- Kubernetes 1.27+ cluster (EKS, GKE, AKS, or local with minikube/kind)
- Helm 3.12+
- `kubectl` configured for your cluster

---

## 1. Build the Docker Image

```bash
# From the repository root
docker build -t ghcr.io/soul-research-labs/escanorr:0.1.0 .

# Verify
docker run --rm ghcr.io/soul-research-labs/escanorr:0.1.0 --version
```

The multi-stage Dockerfile compiles a release binary and produces a minimal Debian image (~80 MB) running as a non-root user.

### Push to Registry

```bash
docker push ghcr.io/soul-research-labs/escanorr:0.1.0
```

---

## 2. Helm Chart Overview

The chart is at `deploy/helm/escanorr/` and creates:

| Resource | Description |
|----------|-------------|
| Deployment | Runs the escanorr RPC server pod(s) |
| Service | ClusterIP service exposing port 3000 |
| ServiceAccount | Dedicated SA with optional IAM annotations |

---

## 3. Install with Helm

```bash
# Install with defaults (1 replica, ClusterIP, port 3000)
helm install escanorr deploy/helm/escanorr/

# Install with custom values
helm install escanorr deploy/helm/escanorr/ \
  --set replicaCount=2 \
  --set image.tag=0.1.0 \
  --set service.type=LoadBalancer \
  --set env.RUST_LOG="info"
```

### Verify

```bash
kubectl get pods -l app.kubernetes.io/name=escanorr
kubectl logs -l app.kubernetes.io/name=escanorr --tail=20

# Port-forward for local access
kubectl port-forward svc/escanorr 3000:3000
curl http://localhost:3000/health
```

---

## 4. Configuration Reference

All values are in `deploy/helm/escanorr/values.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | 1 | Number of pod replicas |
| `image.repository` | `ghcr.io/soul-research-labs/escanorr` | Container image |
| `image.tag` | `""` (uses appVersion) | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `service.type` | `ClusterIP` | Service type |
| `service.port` | `3000` | Service port |
| `env.RUST_LOG` | `info,escanorr=debug` | Log filter |
| `env.ESCANORR_HOST` | `0.0.0.0` | Bind address |
| `env.ESCANORR_PORT` | `3000` | RPC port |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.requests.cpu` | `250m` | CPU request |
| `resources.limits.memory` | `1Gi` | Memory limit |
| `resources.limits.cpu` | `2000m` | CPU limit |

---

## 5. Health Checks

The container has a built-in Docker `HEALTHCHECK` and the Helm chart configures Kubernetes probes:

- **Liveness**: `GET /health` every 30s (restarts pod on failure)
- **Readiness**: `GET /health` every 10s (removes pod from service on failure)

---

## 6. Resource Tuning

### Prover Nodes

Halo2 proof generation is CPU-intensive. For nodes that generate proofs:

```yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "2000m"
  limits:
    memory: "4Gi"
    cpu: "4000m"
```

### Relay-Only Nodes

For nodes that only relay proofs and track state:

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

---

## 7. Upgrade

```bash
helm upgrade escanorr deploy/helm/escanorr/ \
  --set image.tag=0.2.0
```

## 8. Uninstall

```bash
helm uninstall escanorr
```

---

## 9. Production Checklist

Before deploying with real funds:

- [ ] Replace placeholder Groth16 verification key in Solidity contracts
- [ ] Configure TLS termination (reverse proxy or Ingress)
- [ ] Set up Prometheus scraping on `/metrics`
- [ ] Enable persistent volume for sled state database
- [ ] Configure network policies to restrict pod-to-pod traffic
- [ ] Use `readOnlyRootFilesystem: true` in security context
- [ ] Run security audit on all ZK circuits and Solidity contracts
