#!/bin/bash
kubectl create configmap well-known-config --from-file=jwks.json=jwks.json --namespace=lsst-pdac
