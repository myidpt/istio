#!/bin/bash

function build() {
  echo "Building citactl..."
  go build istio.io/istio/security/cmd/citactl

  # IMAGE="gcr.io/jianfeih-test/citactl:${TAG:-latest}"

  # echo "Building citactl docker, $IMAGE"
  # docker build -t $IMAGE .

  # echo "Push docker.citactl"
  # docker push ${IMAGE}

  echo "Get citadel signing key cert (only for development)..."
  output=$(kc get secret -n istio-system istio-ca-secret -o yaml)
  echo $output | awk '/ca-cert/ {print $2}' | base64 --decode > ca.cert
  echo $output | awk '/ca-key/ {print $2}' | base64 --decode > ca.key
  kc get secret -n istio-system istio.default -o yaml | awk '/root-cert/ {print $2}' | base64 --decode > root.cert
}

function run() {
  kc apply -f citactl.yaml  
  kc exec -it $(kc get po -l app=citactl -o jsonpath={.items..metadata.name}) $@
}
