// Copyright 2018 Istio Authors
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

package caclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"

	"istio.io/istio/security/pkg/util"
	"istio.io/pkg/log"
)

var (
	vaultClientLog = log.RegisterScope("vault", "Vault client debugging", 0)
)

// VaultClient is a client for interaction with Vault.
type VaultClient struct {
	enableTLS       bool
	vaultAddr       string
	jwtPath         string
	tlsRootCertPath string
	loginRole       string
	loginPath       string
	signCsrPath     string
	caCertPath      string

	client    *api.Client
	jwtLoader *util.JwtLoader
}

// NewVaultClient create a CA client for the Vault PKI.
func NewVaultClient(vaultAddr, jwtPath, tlsRootCertPath, loginRole, loginPath,
	signCsrPath, caCertPath string) (*VaultClient, error) {
	c := &VaultClient{
		enableTLS:       true,
		vaultAddr:       vaultAddr,
		jwtPath:         jwtPath,
		tlsRootCertPath: tlsRootCertPath,
		loginRole:       loginRole,
		loginPath:       loginPath,
		signCsrPath:     signCsrPath,
		caCertPath:      caCertPath,
	}
	if strings.HasPrefix(c.vaultAddr, "http:") {
		c.enableTLS = false
	}

	jwtLoader, tlErr := util.NewJwtLoader(c.jwtPath)
	if tlErr != nil {
		return nil, fmt.Errorf("failed to create token loader to load the tokens: %v", tlErr)
	}
	c.jwtLoader = jwtLoader

	var client *api.Client
	var err error
	if c.enableTLS {
		client, err = createVaultTLSClient(c.vaultAddr, c.tlsRootCertPath)
	} else {
		client, err = createVaultClient(c.vaultAddr)
	}
	if err != nil {
		return nil, err
	}
	c.client = client

	token, err := loginVaultK8sAuthMethod(c.client, c.loginPath, c.loginRole, jwtLoader.Jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to login Vault at %s: %v", c.vaultAddr, err)
	}
	c.client.SetToken(token)

	vaultClientLog.Infof("created Vault client for Vault address: %s, TLS: %v", c.vaultAddr, c.enableTLS)
	return c, nil
}

// CSRSign calls Vault to sign a CSR.
func (c *VaultClient) CSRSign(ctx context.Context, reqID string, csrPEM []byte, jwt string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {
	if len(jwt) != 0 {
		token, err := loginVaultK8sAuthMethod(c.client, c.loginPath, c.loginRole, jwt)
		if err != nil {
			return nil, fmt.Errorf("failed to login Vault at %s: %v", c.vaultAddr, err)
		}
		c.client.SetToken(token)
	}
	certChain, err := signCsrByVault(c.client, c.signCsrPath, certValidTTLInSec, csrPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %v", err)
	}

	if len(certChain) <= 1 {
		vaultClientLog.Errorf("certificate chain length is %d, expected more than 1", len(certChain))
		return nil, fmt.Errorf("invalid certificate chain in the response")
	}

	return certChain, nil
}

// GetCACertPem returns the CA certificate in PEM format.
func (c *VaultClient) GetCACertPem() (string, error) {
	resp, err := c.client.Logical().Read(c.caCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve CA cert: %v", err)
	}
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("failed to retrieve CA cert: Got nil data")
	}
	certData, ok := resp.Data["certificate"]
	if !ok {
		return "", fmt.Errorf("no certificate in the CA cert response")
	}
	cert, ok := certData.(string)
	if !ok {
		return "", fmt.Errorf("the certificate in the CA cert response is not a string")
	}
	return cert, nil
}

// createVaultClient creates a client to a Vault server
// vaultAddr: the address of the Vault server (e.g., "http://127.0.0.1:8200").
func createVaultClient(vaultAddr string) (*api.Client, error) {
	config := api.DefaultConfig()
	config.Address = vaultAddr

	client, err := api.NewClient(config)
	if err != nil {
		vaultClientLog.Errorf("failed to create a Vault client: %v", err)
		return nil, err
	}

	return client, nil
}

// createVaultTLSClient creates a client to a Vault server
// vaultAddr: the address of the Vault server (e.g., "https://127.0.0.1:8200").
func createVaultTLSClient(vaultAddr string, tlsRootCertPath string) (*api.Client, error) {
	// Load the system default root certificates.
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not get SystemCertPool: %v", err)
	}
	if pool == nil {
		log.Info("system cert pool is nil, create a new cert pool")
		pool = x509.NewCertPool()
	}
	tlsRootCert, err := ioutil.ReadFile(tlsRootCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert from file [%s]: %v", tlsRootCertPath, err)
	}
	if len(tlsRootCert) > 0 {
		ok := pool.AppendCertsFromPEM(tlsRootCert)
		if !ok {
			return nil, fmt.Errorf("failed to append a certificate (%v) to the certificate pool", string(tlsRootCert))
		}
	}
	tlsConfig := &tls.Config{
		RootCAs: pool,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}

	config := api.DefaultConfig()
	config.Address = vaultAddr
	config.HttpClient = httpClient

	client, err := api.NewClient(config)
	if err != nil {
		vaultClientLog.Errorf("failed to create a Vault client: %v", err)
		return nil, err
	}

	return client, nil
}

// loginVaultK8sAuthMethod logs into the Vault k8s auth method with the service account and
// returns the auth client token.
// loginPath: the path of the login
// role: the login role
// jwt: the service account used for login
func loginVaultK8sAuthMethod(client *api.Client, loginPath, role, sa string) (string, error) {
	resp, err := client.Logical().Write(
		loginPath,
		map[string]interface{}{
			"jwt":  sa,
			"role": role,
		})

	if err != nil {
		vaultClientLog.Errorf("failed to login Vault: %v", err)
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("login response is nil")
	}
	if resp.Auth == nil {
		return "", fmt.Errorf("login response auth field is nil")
	}
	return resp.Auth.ClientToken, nil
}

// signCsrByVault signs the CSR and return the signed certificate and the CA certificate chain
// Return the signed certificate chain when succeed.
// client: the Vault client
// csrSigningPath: the path for signing a CSR
// csr: the CSR to be signed, in pem format
func signCsrByVault(client *api.Client, csrSigningPath string, certTTLInSec int64, csr []byte) ([]string, error) {
	m := map[string]interface{}{
		"format":               "pem",
		"csr":                  string(csr),
		"ttl":                  strconv.FormatInt(certTTLInSec, 10) + "s",
		"exclude_cn_from_sans": true,
	}
	resp, err := client.Logical().Write(csrSigningPath, m)
	if err != nil {
		return nil, fmt.Errorf("failed to post to %v: %v", csrSigningPath, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("sign response is nil")
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("sign response has a nil Data field")
	}
	//Extract the certificate and the certificate chain
	certificateData, certOK := resp.Data["certificate"]
	if !certOK {
		return nil, fmt.Errorf("no certificate in the CSR response")
	}
	cert, ok := certificateData.(string)
	if !ok {
		return nil, fmt.Errorf("the certificate in the CSR response is not a string")
	}
	var certChain []string
	certChain = append(certChain, cert+"\n")

	caChainData, caChainOK := resp.Data["ca_chain"]
	if caChainOK {
		chain, ok := caChainData.([]interface{})
		if !ok {
			return nil, fmt.Errorf("the certificate chain in the CSR response is of unexpected format")
		}
		for idx, c := range chain {
			_, ok := c.(string)
			if !ok {
				return nil, fmt.Errorf("the certificate in the certificate chain %v is not a string", idx)
			}
			certChain = append(certChain, c.(string)+"\n")
		}
	} else {
		// In case cert chain is empty, attach the issuing CA. [TODO] Add test.
		issuingCAData, issuingCAOK := resp.Data["issuing_ca"]
		if !issuingCAOK {
			return nil, fmt.Errorf("no issuing CA in the CSR response")
		}
		issuingCA, ok := issuingCAData.(string)
		if !ok {
			return nil, fmt.Errorf("the issuing CA cert in the CSR response is not a string")
		}
		certChain = append(certChain, issuingCA+"\n")
	}

	return certChain, nil
}
