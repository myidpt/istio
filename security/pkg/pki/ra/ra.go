// Copyright 2020 Istio Authors
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

package ra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"istio.io/istio/security/pkg/nodeagent/caclient"
)

// backendCA is the enum for the upstream CA type.
type backendCA int

const (
	vault backendCA = iota
)

// BackendCAClient interface defines the clients to talk to the backend CA.
type BackendCAClient interface {
	CSRSign(ctx context.Context, reqID string, csrPEM []byte, jwt string,
		certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error)
	GetCACertPem() (string, error)
}

// IstioRA generates keys and certificates for Istio identities.
type IstioRA struct {
	client BackendCAClient
}

// NewIstioRA returns a new IstioRA instance.
func NewIstioRA(trustDomain, backendCAName, config string) (*IstioRA, error) {
	params := strings.Split(config, ";")
	if len(params) < 2 {
		return nil, fmt.Errorf("unexpected format of RA config. Expected format 'backend_ca_addr;token_path;...' but got %s", config)
	}
	caAddr := params[0]
	tls := strings.HasPrefix(caAddr, "https")

	client, err := caclient.NewCAClient(caAddr, backendCAName, tls, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for backend CA: %v", err)
	}
	ra := &IstioRA{
		client: client,
	}
	return ra, nil
}

// Sign takes a PEM-encoded CSR, subject IDs and lifetime, and returns a signed certificate.
func (ra *IstioRA) Sign(csrPEM []byte, subjectIDs []string, requestedLifetime time.Duration, forCA bool) ([]byte, error) {
	if forCA {
		return nil, fmt.Errorf("istio RA does not support issue certificates for CAs yet")
	}
	signedCertStrs, err := ra.client.CSRSign(context.Background(), "" /* reqID not used */, csrPEM, "" /* not used */, (int64)(requestedLifetime.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("Failed to sign CSR with the backend CA: %v", err)
	}
	// The first returned certificate is the leave certificate.
	return []byte(signedCertStrs[0]), nil
}

// SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
func (ra *IstioRA) SignWithCertChain(csrPEM []byte, subjectIDs []string, requestedLifetime time.Duration, forCA bool) ([]byte, error) {
	if forCA {
		return nil, fmt.Errorf("istio RA does not support issue certificates for CAs yet")
	}
	signedCertStrs, err := ra.client.CSRSign(context.Background(), "" /* reqID not used */, csrPEM, "" /* not used */, (int64)(requestedLifetime.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("Failed to sign CSR with the backend CA: %v", err)
	}
	var signedCertBytes []byte
	for _, cert := range signedCertStrs {
		signedCertBytes = append(signedCertBytes, []byte(cert)...)
	}
	return signedCertBytes, nil
}

// GetCACertPem returns the backend CA's certificate.
func (ra *IstioRA) GetCACertPem() ([]byte, error) {
	certStr, err := ra.client.GetCACertPem()
	if err != nil {
		return nil, err
	}
	return []byte(certStr), nil
}
