// Program citadel_cli is used for the admin operator to register, bootstrap identity and credentials.
// Example:
// `citactl create service-a.example.com`, requests a key certificate pair signed by Citadel.
// TODO: security/tools/gencert can be merged as a subcommand here.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/spf13/cobra"
	"istio.io/istio/security/pkg/nodeagent/secrets"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/util"
)

var (
	citadel    string // citadelAddress
	signerKey  string
	signerCert string
	rootCert   string
)

var (
	rootCmd = &cobra.Command{
		Use:               "citactl",
		Short:             "Citadel control interface",
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Long: `
Citadel identity control management for admin operator.
`,
	}
	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Generates a certificate for a service.",
		Example: "citactl create dns www.service-a.example.com, obtains a key and certificate with " +
			"www.service-a.example.com as DNS SAN field.",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			format := args[0]
			subject := args[1]
			return Create(format, subject)
		},
	}
)

// Create fetches a key cert pairm, signed by Citadel.Create
// The returned ceritifcate with `subject` encoded in the field specified by `format`.
// TODO: remove hardcoded values and configurable.
// TODO: consider to use citadel's CSR API later.
func Create(format, subject string) error {
	csr, privKey, err := util.GenCSR(util.CertOptions{
		Host:       subject,
		Org:        "example.com",
		RSAKeySize: 2048,
	})
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	kb, err := util.NewVerifiedKeyCertBundleFromFile(signerCert, signerKey, signerCert, rootCert)
	if err != nil {
		return err
	}
	ca, err := ca.NewIstioCA(&ca.IstioCAOptions{
		CertTTL:       time.Hour * 24,
		MaxCertTTL:    time.Hour * 48,
		KeyCertBundle: kb,
	})
	cert, err := ca.Sign(csr, time.Hour*24, false)
	if err != nil {
		return err
	}
	fmt.Printf("Saving key cert for %v...\n", subject)
	if err := ioutil.WriteFile("service-key.pem", privKey, secrets.KeyFilePermission); err != nil {
		return err
	}
	if err := ioutil.WriteFile("service-cert.pem", cert, secrets.CertFilePermission); err != nil {
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&citadel, "citadel", "localhost:15000", "Citadel server address")
	rootCmd.PersistentFlags().StringVar(&rootCert, "root-cert", "root.cert", "The input path for the root cert.")
	rootCmd.PersistentFlags().StringVar(&signerKey, "signer-key", "ca.key", "input signer key path.")
	rootCmd.PersistentFlags().StringVar(&signerCert, "signer-cert", "ca.cert", "input signer cert path.")
	createCmd.PersistentFlags().Duration("duration", time.Hour*24,
		"The TTL of the generated certificate, default 24 hours.")
}

func main() {
	rootCmd.AddCommand(createCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
