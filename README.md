# Auto TLS Example

An application to demonstrate how to automate the creation/renovation of TLS using the `certificates.k8s.io` API.
This example tries to automate the process described on [this document.](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)

## How it works

1) Creates `CertificateSignRequests` objects on Kubernetes API and blocks until its approval
2) Runs a webserver using the approved certificate
3) Renew certificates calculating the certificate validity of `notBefore` and `notAfter`
4) Restart the web server using the new certificates when they are approved

## Quick Start

Start minikube changing the with the following parameters:

```bash
minikube start --vm-driver=<yourdriver> --extra-config=controller-manager.experimental-cluster-signing-duration=6m
# if your vm clock is not synchonized properly
# https://github.com/kubernetes/minikube/issues/1378
minikube ssh -- docker run -i --rm --privileged --pid=host debian nsenter -t 1 -m -u -n -i date -u $(date -u +%m%d%H%M%Y.%S)
```

> `--experimental-cluster-signing-duration=6m` is used to test the renovation of certificates

```bash
dep ensure -v
# On first terminal start the server / cert manager
# [optional]
export KUBECONFIG=/path/to/kube/config
make server
```

```bash
# On an second terminal
make connect
```

```bash
# Wait for a pending CSR
kubectl get csr -l app=auto-tls -w
# Approve it!
kubectl certificate approve <csr>
```
