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

package kube

import (
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"istio.io/istio/security/pkg/pki/util"
)

const (
	// CitadelSecretType is the Istio secret annotation type.
	CitadelSecretType = "istio.io/ca-root"

	// SigningCertID is the CA certificate chain file.
	SigningCertID = "ca-cert.pem"
	// SigningKeyID is the private key file of CA.
	SigningKeyID = "ca-key.pem"
	// CitadelSecretName stores the key/cert of self-signed CA for persistency purpose.
	CitadelSecretName = "istio-ca-secret"
)

// SigningKeyCertSecret is the manager for storing the Citadel key and cert in k8s.
type SigningKeyCertSecret struct {
	Core      corev1.SecretsGetter
	Namespace string
}

// Get returns the private key and cert from k8s secret.
func (s *SigningKeyCertSecret) Get() (keycert util.KeyCertBundle, err error) {
	caSecret, scrtErr := s.Core.Secrets(s.Namespace).Get(CitadelSecretName, metav1.GetOptions{})
	if scrtErr != nil {
		return nil, scrtErr
	}
	return util.NewVerifiedKeyCertBundleFromPem(
		caSecret.Data[SigningCertID], caSecret.Data[SigningKeyID], nil, caSecret.Data[SigningCertID])
}

// Put updates the cert and private key in k8s secret.
func (s *SigningKeyCertSecret) Put(keycert util.KeyCertBundle) (err error) {
	pemCert, pemKey, _, _ := keycert.GetAllPem()
	secret := &apiv1.Secret{
		Data: map[string][]byte{
			SigningCertID: pemCert,
			SigningKeyID:  pemKey,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CitadelSecretName,
			Namespace: s.Namespace,
		},
		Type: CitadelSecretType,
	}
	_, err = s.Core.Secrets(s.Namespace).Create(secret)
	return err
}
