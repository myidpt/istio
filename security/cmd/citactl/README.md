# Citadel Control Client

## Usage

Build citactl tool, `go build istio.io/istio/security/cmd/citadel_cli`

Starts citadel server,

```bash
go build istio.io/istio/security/cmd/istio_ca
istio_ca --some-args
```

Run citactl

```bash
citactl create dns service-a.example.com
```

You'll see generated key/cert pair and the root cert.