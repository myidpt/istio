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
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"testing"
)

// vaultAuthHeaderName is the name of the header containing the token.
const (
	vaultAuthHeaderName = "X-Vault-Token"
)

var (
	validJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNsQ282WGxzUmtUZFFlTlFjb3ZCaTI3RmpPTFRuS1NsMEdwS0luLVFMdlEifQ.eyJpc3MiO" +
		"iJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJpc3Rpby1zeXN0" +
		"ZW0iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiaXN0aW8tcGlsb3Qtc2VydmljZS1hY2NvdW50LXRva2V" +
		"uLXQ3NnJnIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImlzdGlvLXBpbG90LXNlcnZpY2" +
		"UtYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjBjNDYyNDZmLWRkZGItNDk2M" +
		"S05YjUxLTAyMzg3MGMxNjkzZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDppc3Rpby1zeXN0ZW06aXN0aW8tcGlsb3Qtc2Vydmlj" +
		"ZS1hY2NvdW50In0.xXm2vr1dR2qyrAdBqHJqa_VDuBV8mOe7jiRwG1rZl0aMRtYF--DOMd4hGfaK-I-GieYP6TNzFrkqrT0DLGUOMiBnzb6" +
		"0PM103xEfuuFFlkxA4IlJgN2_e-vB5QO2QhLghxSI7up4xFBxvfTN5TXGmTdnnlFw4XVKRrM1Vgl8YlVyL6xc9CC4ckfF0SMNNyMOQk3v5g" +
		"BwAzImdFw198YLDxrNzXMfAPQ_PnJYFBXnin-BrGVEd2HknamUuG9XNvBhIpI-o-oXgUEEEm_zTQd_qbpOCZd0utvKhknTzjb92kUVRjxG1" +
		"3vscVKNHqBVOYu1M69uHlx53Bt3o903oAB6rA"

	invalidJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNsQ282WGxzUmtUZFFlTlFjb3ZCaTI3RmpPTFRuS1NsMEdwS0luLVFMdlEifQ.eyJpc3M" +
		"iOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJpc3Rpby1zeX" +
		"N0ZW0iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiaXN0aW8taW5ncmVzc2dhdGV3YXktc2VydmljZS1hY" +
		"2NvdW50LXRva2VuLXp2cmhmIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImlzdGlvLWlu" +
		"Z3Jlc3NnYXRld2F5LXNlcnZpY2UtYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI" +
		"6IjkwNjVkZjVlLTcxNDQtNDg0YS05ZTdjLTQxNTFlMTM3MGVlNSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDppc3Rpby1zeXN0ZW" +
		"06aXN0aW8taW5ncmVzc2dhdGV3YXktc2VydmljZS1hY2NvdW50In0.YK_FVAfeW6x1khFt40_m_kXrdnp3VTLjLr8CckRBZMz7R12jHL7FU" +
		"E7l7oxM1YJGPs-jusM_1DnVEuJaA360EPhzAsEw2i_AEhnS5m1sZEsTFmPf3_86wH53p_F9ioAZESHyOwPiGSY9Y4N8ccMEO7lDZIWsps1-" +
		"3sMxhqwdU1iMf6zja5TilC_87aB99pcTtty6NMtcIqmgy3T9wj1HDEHZMyg-6rOKkMz-_8KSME-5a8WyfjqQY_3_uhXqvJvIenQdIG9p29k" +
		"aKq4UKYzHmhn9B6U5ZMeGXYQI2CsGxsXEJLrwRFlArIYggQhcJHlWyYgTLXmNuAWrpymXuWSsZQ"

	validCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICgjCCAWoCAQAwPTEcMBoGA1UEAwwTaHR0cGJpbi5leGFtcGxlLmNvbTEdMBsG
A1UECgwUaHR0cGJpbiBvcmdhbml6YXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDaHY9jIPD2S9EBmbItSlD0aZ3PPtK7yDmD0mDHTaD5lFT/GGu8
RFjGNI0WS7IJSr3uVsI/VljqU3J1icSBvzNGQFuPvXGLmmtYJ2cd+7ZUWja1qf2r
NNG9ZI034clbiENB4SnxK6DjTawLv8Wlm9rc8qCgjE6r1fIoE6LWerJjiNXpg1WP
KqD8x6KYDbjx3Wr8hrfJ6DNMKKNXkZ+he6eAy2aEAprqROQbioNRRsOAoioUeod+
LUVxjQxXWZHjDkYa6NBYX2MkiEV/nslm2UNDTO2WiAK/yJp2G2E+YzDTWMqnqdoh
r/bas93uTYHlcm8v6wDaGqHhLYkL5iXu01KXAgMBAAGgADANBgkqhkiG9w0BAQsF
AAOCAQEAhQygBjjG7vgfKWQgwurVujBEIBuwrRnIYqKfQA4FVDwL41/PsAhttbGm
YMSiFjxvn1cviEnYoEFz+XeJrxG4XG8Cdf1cd5cen6gop3FOFjBe1xSBnU/rflxP
mbEzEw++2gyV9lQ8G3rWSp+nGBxkO5JsvheTUvoPfWR1TKovSz29cOJYmSn3zii6
KrK/dw6NnVbYu69FJl1+v1jfzHBmXyvyL2KrcI3fFjR49DbJSqFHnBI/UXn5nFs+
QzE0aC0zLIY4vT7GfABTuaIoTpdzoiXZ0VxMQHsEV6Ad6P+kkJKRpgrDbZzlWgOa
B8e+lMJGkuDQRCKZo0qQMHTB7C8XCQ==
-----END CERTIFICATE REQUEST-----`

	loginResp = `
	{
	  "auth": {
		  "client_token": "fake-vault-token" 
	  }
	}
  `
	signResp = `
	{
	  "data": {
		  "certificate": "fake-certificate", 
		  "issuing_ca": "fake-ca2",
		  "ca_chain": ["fake-ca1", "fake-ca2"]
	  }
	}
  `
	signResp2 = `
  {
	"data": {
		"certificate": "fake-certificate", 
		"issuing_ca": "fake-ca1"
	}
  }
`
	caCertResp = `
	{
		"data": {
			"certificate": "fake-ca2"
		}
	}
`
	workloadCert  = []string{"fake-certificate\n", "fake-ca1\n", "fake-ca2\n"}
	workloadCert2 = []string{"fake-certificate\n", "fake-ca1\n"}
	caCert        = "fake-ca2"

	validLoginPath    = "auth/kubernetes/login"
	validCSRSignPath  = "pki/sign-verbatim/test"
	validCSRSignPath2 = "pki2/sign-verbatim/test"
	validCACertPath   = "pki/cert/ca"
)

type mockVaultServer struct {
	httpServer *httptest.Server
	loginRole  string
	token      string
	loginResp  string
	signResp   string
	signResp2  string
	caCertResp string
}

type loginRequest struct {
	Jwt  string `json:"jwt"`
	Role string `json:"testrole"`
}

type signRequest struct {
	Format string `json:"format"`
	Csr    string `json:"csr"`
}

func TestNewVaultClient(t *testing.T) {
	ch := make(chan *mockVaultServer)
	go func() {
		// create a test TLS Vault server
		server := newMockVaultServer(t, true, "", validJWT, loginResp, signResp, signResp2, caCertResp)
		ch <- server
	}()
	tlsServer := <-ch
	defer tlsServer.httpServer.Close()

	certFile, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("Failed to create tmp cert file: %v", err)
	}
	defer os.Remove(certFile.Name()) // clean up
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.httpServer.Certificate().Raw})

	if _, err := certFile.Write(content); err != nil {
		t.Fatalf("Failed to write server cert to tmp file: %v", err)
	}

	jwtFile, err := ioutil.TempFile("", "jwt")
	if err != nil {
		t.Fatalf("Failed to create tmp jwt file: %v", err)
	}
	defer os.Remove(jwtFile.Name()) // clean up

	if _, err := jwtFile.Write([]byte(validJWT)); err != nil {
		t.Fatalf("Failed to write jwt to tmp file: %v", err)
	}

	invalidJwtFile, err := ioutil.TempFile("", "invalidjwt")
	if err != nil {
		t.Fatalf("Failed to create tmp invalid jwt file: %v", err)
	}
	defer os.Remove(invalidJwtFile.Name()) // clean up

	if _, err := invalidJwtFile.Write([]byte(invalidJWT)); err != nil {
		t.Fatalf("Failed to write invalid jwt to tmp file: %v", err)
	}

	testCases := map[string]struct {
		vaultAddr        string
		jwtPath          string
		tlsRootCertPath  string
		loginRole        string
		loginPath        string
		expectedErrRegEx string
	}{
		"Valid login": {
			vaultAddr:        tlsServer.httpServer.URL,
			jwtPath:          jwtFile.Name(),
			tlsRootCertPath:  certFile.Name(),
			loginRole:        "testrole",
			loginPath:        validLoginPath,
			expectedErrRegEx: "",
		},
		"Wrong login path": {
			vaultAddr:        tlsServer.httpServer.URL,
			jwtPath:          jwtFile.Name(),
			tlsRootCertPath:  certFile.Name(),
			loginRole:        "testrole",
			loginPath:        "auth/wrongpath/login",
			expectedErrRegEx: "failed to login Vault at .+",
		},
		"Non-exist JWT file": {
			vaultAddr:        tlsServer.httpServer.URL,
			jwtPath:          "/non/exist/jwt/path",
			tlsRootCertPath:  certFile.Name(),
			loginRole:        "testrole",
			loginPath:        validLoginPath,
			expectedErrRegEx: "failed to create token loader to load the tokens.+",
		},
		"Invalid JWT": {
			vaultAddr:        tlsServer.httpServer.URL,
			jwtPath:          invalidJwtFile.Name(),
			tlsRootCertPath:  certFile.Name(),
			loginRole:        "testrole",
			loginPath:        validLoginPath,
			expectedErrRegEx: "failed to login Vault at .+",
		},
	}

	for id, tc := range testCases {
		_, err := NewVaultClient(tc.vaultAddr, tc.jwtPath, tc.tlsRootCertPath, tc.loginRole, tc.loginPath,
			validCSRSignPath, validCACertPath)
		if err != nil {
			if len(tc.expectedErrRegEx) == 0 {
				t.Errorf("Test case [%s]: received error while not expected: %v", id, err)
			}
			match, _ := regexp.MatchString(tc.expectedErrRegEx, err.Error())
			if !match {
				t.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErrRegEx)
			}
		} else if tc.expectedErrRegEx != "" {
			t.Errorf("Test case [%s]: expect error: %s but got no error", id, tc.expectedErrRegEx)
		}
	}
}

func TestCSRSign(t *testing.T) {
	ch := make(chan *mockVaultServer)
	go func() {
		// create a test TLS Vault server
		server := newMockVaultServer(t, true, "", validJWT, loginResp, signResp, signResp2, caCertResp)
		ch <- server
	}()
	tlsServer := <-ch
	defer tlsServer.httpServer.Close()

	certFile, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("Failed to create tmp cert file: %v", err)
	}
	defer os.Remove(certFile.Name()) // clean up
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.httpServer.Certificate().Raw})

	if _, err := certFile.Write(content); err != nil {
		t.Fatalf("Failed to write server cert to tmp file: %v", err)
	}

	jwtFile, err := ioutil.TempFile("", "jwt")
	if err != nil {
		t.Fatalf("Failed to create tmp jwt file: %v", err)
	}
	defer os.Remove(jwtFile.Name()) // clean up

	if _, err := jwtFile.Write([]byte(validJWT)); err != nil {
		t.Fatalf("Failed to write jwt to tmp file: %v", err)
	}

	testCases := map[string]struct {
		signCsrPath      string
		jwt              string
		csr              []byte
		expectedCert     []string
		expectedErrRegEx string
	}{
		"Valid request no custom JWT": {
			signCsrPath:      validCSRSignPath,
			jwt:              "",
			csr:              []byte(validCSR),
			expectedCert:     workloadCert,
			expectedErrRegEx: "",
		},
		"Valid request with custom JWT": {
			signCsrPath:      validCSRSignPath,
			jwt:              validJWT,
			csr:              []byte(validCSR),
			expectedCert:     workloadCert,
			expectedErrRegEx: "",
		},
		"Invalid request with custom JWT": {
			signCsrPath:      validCSRSignPath,
			jwt:              invalidJWT,
			csr:              []byte(validCSR),
			expectedCert:     workloadCert,
			expectedErrRegEx: "failed to login Vault at.+",
		},
		"Return no cert chain": {
			signCsrPath:      validCSRSignPath2,
			jwt:              validJWT,
			csr:              []byte(validCSR),
			expectedCert:     workloadCert2,
			expectedErrRegEx: "",
		},
		"Wrong CSR sign path": {
			signCsrPath:      "pki/wrongpath/test",
			csr:              []byte(validCSR),
			expectedErrRegEx: "failed to sign CSR.+",
		},
	}

	for id, tc := range testCases {
		cli, err := NewVaultClient(tlsServer.httpServer.URL, jwtFile.Name(), certFile.Name(), "testrole", validLoginPath,
			tc.signCsrPath, validCACertPath)
		if err != nil {
			t.Fatalf("Test case [%s]: failed to create ca client: %v", id, err)
		}

		resp, err := cli.CSRSign(context.Background(), "", tc.csr, tc.jwt, 3600)
		if err != nil {
			if len(tc.expectedErrRegEx) == 0 {
				t.Errorf("Test case [%s]: received error while not expected: %v", id, err)
			}
			match, _ := regexp.MatchString(tc.expectedErrRegEx, err.Error())
			if !match {
				t.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErrRegEx)
			}
		} else {
			if tc.expectedErrRegEx != "" {
				t.Errorf("Test case [%s]: expect error: %s but got no error", id, tc.expectedErrRegEx)
			} else if !reflect.DeepEqual(resp, tc.expectedCert) {
				t.Errorf("Test case [%s]: resp: got %+v, expected %v", id, resp, tc.expectedCert)
			}
		}
	}
}

func TestGetCACertPem(t *testing.T) {
	ch := make(chan *mockVaultServer)
	go func() {
		// create a test TLS Vault server
		server := newMockVaultServer(t, true, "", validJWT, loginResp, signResp, signResp2, caCertResp)
		ch <- server
	}()
	tlsServer := <-ch
	defer tlsServer.httpServer.Close()

	certFile, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("Failed to create tmp cert file: %v", err)
	}
	defer os.Remove(certFile.Name()) // clean up
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.httpServer.Certificate().Raw})

	if _, err := certFile.Write(content); err != nil {
		t.Fatalf("Failed to write server cert to tmp file: %v", err)
	}

	jwtFile, err := ioutil.TempFile("", "jwt")
	if err != nil {
		t.Fatalf("Failed to create tmp jwt file: %v", err)
	}
	defer os.Remove(jwtFile.Name()) // clean up

	if _, err := jwtFile.Write([]byte(validJWT)); err != nil {
		t.Fatalf("Failed to write jwt to tmp file: %v", err)
	}

	testCases := map[string]struct {
		caCertPath       string
		expectedCert     string
		expectedErrRegEx string
	}{
		"Valid": {
			caCertPath:       validCACertPath,
			expectedCert:     caCert,
			expectedErrRegEx: "",
		},
		"Wrong CA Cert path": {
			caCertPath:       "pki/wrongpath/ca",
			expectedErrRegEx: "failed to retrieve CA cert: Got nil data",
		},
	}

	for id, tc := range testCases {
		cli, err := NewVaultClient(tlsServer.httpServer.URL, jwtFile.Name(), certFile.Name(), "testrole", validLoginPath,
			"pki/wrongpath/test", tc.caCertPath)
		if err != nil {
			t.Fatalf("Test case [%s]: failed to create ca client: %v", id, err)
		}

		cert, err := cli.GetCACertPem()
		if err != nil {
			if len(tc.expectedErrRegEx) == 0 {
				t.Errorf("Test case [%s]: received error while not expected: %v", id, err)
			}
			match, _ := regexp.MatchString(tc.expectedErrRegEx, err.Error())
			if !match {
				t.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErrRegEx)
			}
		} else {
			if tc.expectedErrRegEx != "" {
				t.Errorf("Test case [%s]: expect error: %s but got no error", id, tc.expectedErrRegEx)
			} else if !reflect.DeepEqual(cert, tc.expectedCert) {
				t.Errorf("Test case [%s]: resp: got %+v, expected %v", id, cert, tc.expectedCert)
			}
		}
	}
}

// newMockVaultServer creates a mock Vault server for testing purpose.
// token: required access token
func newMockVaultServer(t *testing.T, tls bool, loginRole, token, loginResp, signResp, signResp2,
	caCertResp string) *mockVaultServer {
	vaultServer := &mockVaultServer{
		loginRole:  loginRole,
		token:      token,
		loginResp:  loginResp,
		signResp:   signResp,
		signResp2:  signResp2,
		caCertResp: caCertResp,
	}

	handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		t.Logf("request: %+v", *req)
		switch req.URL.Path {
		case "/v1/" + validLoginPath:
			t.Logf("%v", req.URL)
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Logf("failed to read the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			loginReq := loginRequest{}
			err = json.Unmarshal(body, &loginReq)
			if err != nil {
				t.Logf("failed to parse the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if vaultServer.loginRole != loginReq.Role {
				t.Logf("invalid login role: %v", loginReq.Role)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if vaultServer.token != loginReq.Jwt {
				t.Logf("invalid login token: %v", loginReq.Jwt)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Write([]byte(vaultServer.loginResp))

		case "/v1/" + validCACertPath:
			t.Logf("%v", req.URL)
			if req.Header.Get(vaultAuthHeaderName) != "fake-vault-token" {
				t.Logf("the vault token is invalid: %v", req.Header.Get(vaultAuthHeaderName))
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Write([]byte(vaultServer.caCertResp))

		case "/v1/" + validCSRSignPath:
			t.Logf("%v", req.URL)
			if req.Header.Get(vaultAuthHeaderName) != "fake-vault-token" {
				t.Logf("the vault token is invalid: %v", req.Header.Get(vaultAuthHeaderName))
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Logf("failed to read the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			signReq := signRequest{}
			err = json.Unmarshal(body, &signReq)
			if err != nil {
				t.Logf("failed to parse the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if signReq.Format != "pem" {
				t.Logf("invalid sign format: %v", signReq.Format)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(signReq.Csr) == 0 {
				t.Logf("empty CSR")
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Write([]byte(vaultServer.signResp))

		case "/v1/" + validCSRSignPath2:
			t.Logf("%v", req.URL)
			if req.Header.Get(vaultAuthHeaderName) != "fake-vault-token" {
				t.Logf("the vault token is invalid: %v", req.Header.Get(vaultAuthHeaderName))
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Logf("failed to read the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			signReq := signRequest{}
			err = json.Unmarshal(body, &signReq)
			if err != nil {
				t.Logf("failed to parse the request body: %v", err)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if signReq.Format != "pem" {
				t.Logf("invalid sign format: %v", signReq.Format)
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(signReq.Csr) == 0 {
				t.Logf("empty CSR")
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			resp.Header().Set("Content-Type", "application/json")
			resp.Write([]byte(vaultServer.signResp2))

		default:
			t.Logf("The request contains invalid path: %v", req.URL)
			resp.WriteHeader(http.StatusNotFound)
		}
	})

	if tls {
		vaultServer.httpServer = httptest.NewTLSServer(handler)
	} else {
		vaultServer.httpServer = httptest.NewServer(handler)
	}

	t.Logf("Serving Vault at: %v", vaultServer.httpServer.URL)

	return vaultServer
}
