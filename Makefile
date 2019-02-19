SHELL := /bin/bash

server:
	POD_NAMESPACE=default CLUSTER_DNS=svc.cluster.local go run cmd/server/main.go --v=4

connect:
	go run cmd/client/main.go -ca ${HOME}/.minikube/ca.crt -crt /tmp/app.crt -key /tmp/app.key -connect localhost:8443

.PHONY: server connect
