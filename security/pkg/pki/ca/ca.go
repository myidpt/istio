// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ca

import (
	"encoding/pem"
	"fmt"
	"time"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/probe"
	"istio.io/istio/security/pkg/pki/util"
)

const (
	// The size of a private key for a self-signed Istio CA.
	caKeySize = 2048
)

// cATypes is the enum for the CA type.
type cATypes int

const (
	// selfSignedCA means the Istio CA uses a self signed certificate.
	selfSignedCA cATypes = iota
	// pluggedCertCA means the Istio CA uses a operator-specified key/cert.
	pluggedCertCA
)

// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
	// Sign generates a certificate for a workload or CA, from the given CSR and TTL.
	Sign(csrPEM []byte, ttl time.Duration, forCA bool) ([]byte, error)
	// GetCAKeyCertBundle returns the KeyCertBundle used by CA.
	GetCAKeyCertBundle() util.KeyCertBundle
}

// SigningKeyCertStorage is the storage for storing Citadel signing key and cert.
type SigningKeyCertStorage interface {
	// GetSigningKeyCert returns the key and cert for Citadel in bytes
	GetSigningKeyCert() (keycert util.KeyCertBundle, err error)
	// PutSigningKeyCert updates the key and cert for Citadel in bytes
	PutSigningKeyCert(keycert util.KeyCertBundle) (err error)
}

// IstioCAOptions holds the configurations for creating an Istio CA.
// TODO(myidpt): remove IstioCAOptions.
type IstioCAOptions struct {
	CAType cATypes

	CertTTL    time.Duration
	MaxCertTTL time.Duration

	KeyCertBundle util.KeyCertBundle

	LivenessProbeOptions *probe.Options
	ProbeCheckInterval   time.Duration
}

// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
	certTTL    time.Duration
	maxCertTTL time.Duration

	keyCertBundle util.KeyCertBundle

	livenessProbe *probe.Probe
}

// NewSelfSignedIstioCAOptions returns a new IstioCAOptions instance using self-signed certificate.
func NewSelfSignedIstioCAOptions(caCertTTL, certTTL, maxCertTTL time.Duration, org string, dualUse bool,
	storage SigningKeyCertStorage) (caOpts *IstioCAOptions, err error) {
	// For the first time the CA is up, it generates a self-signed key/cert pair and write it to
	// storage. For subsequent restart, CA will reads key/cert from storage.
	caOpts = &IstioCAOptions{
		CAType:     selfSignedCA,
		CertTTL:    certTTL,
		MaxCertTTL: maxCertTTL,
	}

	keycert, sErr := storage.GetSigningKeyCert()
	if sErr != nil {
		log.Infof("Failed to get secret (error: %s), will create one", sErr)
		options := util.CertOptions{
			TTL:          caCertTTL,
			Org:          org,
			IsCA:         true,
			IsSelfSigned: true,
			RSAKeySize:   caKeySize,
			IsDualUse:    dualUse,
		}
		pemCert, pemKey, gErr := util.GenCertKeyFromOptions(options)
		if gErr != nil {
			return nil, fmt.Errorf("unable to generate CA cert and key for self-signed CA (%v)", gErr)
		}
		var bErr error
		keycert, bErr = util.NewVerifiedKeyCertBundleFromPem(pemCert, pemKey, nil, pemCert)
		if bErr != nil {
			return nil, fmt.Errorf("Failed to convert signing key and cert to KeyCertBundle (%v)", bErr)
		}
		if err = storage.PutSigningKeyCert(keycert); err != nil {
			log.Errorf("Failed to write secret to CA (error: %s). This CA will not persist when restart.", err)
		}
	}

	caOpts.KeyCertBundle = keycert

	return caOpts, nil
}

// NewPluggedCertIstioCAOptions returns a new IstioCAOptions instance using given certificate.
func NewPluggedCertIstioCAOptions(certChainFile, signingCertFile, signingKeyFile, rootCertFile string,
	certTTL, maxCertTTL time.Duration) (caOpts *IstioCAOptions, err error) {
	caOpts = &IstioCAOptions{
		CAType:     pluggedCertCA,
		CertTTL:    certTTL,
		MaxCertTTL: maxCertTTL,
	}
	if caOpts.KeyCertBundle, err = util.NewVerifiedKeyCertBundleFromFile(
		signingCertFile, signingKeyFile, certChainFile, rootCertFile); err != nil {
		return nil, fmt.Errorf("failed to create CA KeyCertBundle (%v)", err)
	}
	return caOpts, nil
}

// NewIstioCA returns a new IstioCA instance.
func NewIstioCA(opts *IstioCAOptions) (*IstioCA, error) {
	if opts.KeyCertBundle == nil {
		return nil, fmt.Errorf("failed to create Istio CA because KeyCertBundle is nil")
	}
	ca := &IstioCA{
		certTTL:       opts.CertTTL,
		maxCertTTL:    opts.MaxCertTTL,
		keyCertBundle: opts.KeyCertBundle,
		livenessProbe: probe.NewProbe(),
	}

	return ca, nil
}

// Sign takes a PEM-encoded CSR and ttl, and returns a signed certificate. If forCA is true,
// the signed certificate is a CA certificate, otherwise, it is a workload certificate.
// TODO(myidpt): Add error code to identify the Sign error types.
func (ca *IstioCA) Sign(csrPEM []byte, ttl time.Duration, forCA bool) ([]byte, error) {
	signingCert, signingKey, _, _ := ca.keyCertBundle.GetAll()
	if signingCert == nil {
		return nil, NewError(CANotReady, fmt.Errorf("Istio CA is not ready")) // nolint
	}

	csr, err := util.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, NewError(CSRError, err)
	}

	// If the requested TTL is greater than maxCertTTL, return an error
	if ttl.Seconds() > ca.maxCertTTL.Seconds() {
		return nil, NewError(TTLError, fmt.Errorf(
			"requested TTL %s is greater than the max allowed TTL %s", ttl, ca.maxCertTTL))
	}

	certBytes, err := util.GenCertFromCSR(csr, signingCert, csr.PublicKey, *signingKey, ttl, forCA)
	if err != nil {
		return nil, NewError(CertGenError, err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	cert := pem.EncodeToMemory(block)

	return cert, nil
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func (ca *IstioCA) GetCAKeyCertBundle() util.KeyCertBundle {
	return ca.keyCertBundle
}
