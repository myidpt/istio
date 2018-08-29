#!/bin/bash

function build() {
  echo "Building citactl..."
  go build istio.io/istio/security/cmd/citactl

  IMAGE="gcr.io/jianfeih-test/citactl:${TAG:-latest}"

  echo "Building citactl docker, $IMAGE"
  docker build -t $IMAGE .

  echo "Push docker.citactl"
  docker push ${IMAGE}
}

function deploy() {
  kc apply -f citactl.yaml  
}

function citactl() {
  kc exec -it $(kc get po -l app=citactl -o jsonpath={.items..metadata.name}) $@
}
