#!/bin/bash

function build() {
  echo "Building citactl..."
  go build istio.io/istio/security/cmd/citactl

  echo "Get citadel signing key cert (only for development)..."
  output=$(kubectl get secret -n istio-system istio-ca-secret -o yaml)
  echo $output | awk '/ca-cert/ {print $2}' | base64 --decode > ca.cert
  echo $output | awk '/ca-key/ {print $2}' | base64 --decode > ca.key
  kubectl get secret -n istio-system istio.default -o yaml | awk '/root-cert/ {print $2}' | base64 --decode > root.cert
}

build
./citactl create  dnsname service-a.example.com