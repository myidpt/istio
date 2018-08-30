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

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

const (
	// KeyFilePermission is the permission bits for private key file.
	KeyFilePermission = 0600

	// CertFilePermission is the permission bits for certificate file.
	CertFilePermission = 0644

	// CertFileName is the file name to store the certificate.
	CertFileName = "cert.pem"

	// KeyFileName is the file name to store the key.
	KeyFileName = "key.pem"

	// CertChainFileName is the file name to store the cert chain.
	CertChainFileName = "cert-chain.pem"

	// RootCertFileName is the file name to store the root cert.
	RootCertFileName = "root-cert.pem"
)

// SecretFile facilitates the access to key and certs in the file system.
type SecretFile struct {
	RootDir string
}

// PutSigningKeyCert writes the specified key and cert to the files.
func (sf *SecretFile) PutSigningKeyCert(keycert KeyCertBundle) error {
	return sf.Put("", keycert)
}

// Put writes the specified key and cert to the files correspond to the service account.
func (sf *SecretFile) Put(serviceAccount string, keycert KeyCertBundle) error {
	cert, priv, certchain, root := keycert.GetAllPem()
	dir := sf.RootDir
	if len(serviceAccount) != 0 {
		dir = path.Join(sf.RootDir, serviceAccount)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory for %v, err %v", serviceAccount, err)
		}
	}
	if len(cert) != 0 {
		cpath := path.Join(dir, CertFileName)
		if err := ioutil.WriteFile(cpath, cert, CertFilePermission); err != nil {
			return err
		}
	}
	if len(priv) != 0 {
		kpath := path.Join(dir, KeyFileName)
		if err := ioutil.WriteFile(kpath, priv, KeyFilePermission); err != nil {
			return err
		}
	}
	if len(certchain) != 0 {
		ccpath := path.Join(dir, CertChainFileName)
		if err := ioutil.WriteFile(ccpath, certchain, CertFilePermission); err != nil {
			return err
		}
	}
	if len(root) != 0 {
		rpath := path.Join(dir, RootCertFileName)
		if err := ioutil.WriteFile(rpath, root, CertFilePermission); err != nil {
			return err
		}
	}
	return nil
}

// GetSigningKeyCert reads the key and cert from specific files.
func (sf *SecretFile) GetSigningKeyCert() (keycert KeyCertBundle, err error) {
	return NewVerifiedKeyCertBundleFromFile(
		path.Join(sf.RootDir, CertFileName), path.Join(sf.RootDir, KeyFileName),
		path.Join(sf.RootDir, CertChainFileName), path.Join(sf.RootDir, RootCertFileName))
}
