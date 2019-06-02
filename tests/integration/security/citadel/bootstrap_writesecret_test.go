// Copyright 2019 Istio Authors
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

package citadel

import (
	"strings"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/environment/kube"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/util/file"
	"istio.io/istio/pkg/test/util/tmpl"
	"istio.io/istio/security/pkg/pki/ca"
)

const (
	rbacConfigTmpl = "testdata/citadel-noread-rbac.yaml.tmpl"
)

// TestCitadelBootstrapKubernetes verifies that Citadel exits if:
// It fails to read the CA-root secret due to network issue, etc. (this is simulated via RBAC policy),
// and then it tries to create a new CA-root secret and fails because the secret already exists.
func TestCitadelBootstrapKubernetes(t *testing.T) {
	framework.NewTest(t).Run(func(ctx framework.TestContext) {
		ns := namespace.ClaimOrFail(t, ctx, ist.Settings().IstioNamespace)
		namespaceTmpl := map[string]string{
			"Namespace": ns.Name(),
		}

		// Apply the RBAC policy to prevent Citadel to read the CA-root secret.
		policies := tmpl.EvaluateAllOrFail(t, namespaceTmpl,
			file.AsStringOrFail(t, rbacConfigTmpl))

		g.ApplyConfigOrFail(t, ns, policies...)
		defer g.DeleteConfigOrFail(t, ns, policies...)

		// Sleep 30 seconds for the policy to take effect.
		time.Sleep(30 * time.Second)

		// Retrieve Citadel CA-root secret. Keep it for later comparison.
		env := ctx.Environment().(*kube.Environment)
		secrets := env.GetSecret(ns.Name())
		citadelSecret, err := secrets.Get(ca.CASecret, metav1.GetOptions{})
		if err != nil {
			t.Fatal("Failed to retrieve Citadel CA-root secret.")
		}

		// Delete Citadel pod, a new pod will be started.
		pods, err := env.GetPods(ns.Name(), "istio=citadel")
		if err != nil {
			t.Fatal("Failed to get Citadel pods.")
		}
		env.DeletePod(ns.Name(), pods[0].GetName())

		// Sleep 30 seconds for the pod deletion and recreation to take effect.
		time.Sleep(30 * time.Second)

		pods, err = env.GetPods(ns.Name(), "istio=citadel")
		if err != nil {
			t.Fatalf("failed to get Citadel pod")
		}
		cl, err := env.Logs(ns.Name(), pods[0].Name, "citadel", false /* previousLog */)
		pl, err := env.Logs(ns.Name(), pods[0].Name, "citadel", true /* previousLog */)
		expectedErr := []string{"Failed to write secret to CA", "Failed to create a self-signed Citadel"}
		if cl != "" && err == nil {
			if !strings.Contains(cl, expectedErr[0]) {
				t.Errorf("log does not match, expected %s but got %s", expectedErr[0], cl)
			}
			if !strings.Contains(cl, expectedErr[1]) {
				t.Errorf("log does not match, expected %s but got %s", expectedErr[1], cl)
			}
		} else if pl != "" && err == nil {
			if !strings.Contains(pl, expectedErr[0]) {
				t.Errorf("log does not match, expected %s but got %s", expectedErr[0], pl)
			}
			if !strings.Contains(pl, expectedErr[1]) {
				t.Errorf("log does not match, expected %s but got %s", expectedErr[1], pl)
			}
		} else {
			t.Errorf("Expected error logs not found")
		}

		// Verify that the secret is untouched.
		currentSecret, err := secrets.Get(ca.CASecret, metav1.GetOptions{})
		if err != nil {
			t.Fatal("Failed to retrieve Citadel CA-root secret.")
		}
		if !reflect.DeepEqual(citadelSecret, currentSecret) {
			t.Fatal("Citadel CA-root secret is changed!")
		}
	})
}
