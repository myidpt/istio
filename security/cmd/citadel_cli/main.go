// Program citadel_cli is used for the admin operator to register, bootstrap identity and credentials.
// Example:
// `citactl create service-a.example.com`, requests a key certificate pair signed by Citadel.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"istio.io/istio/security/pkg/pki/util"
	pb "istio.io/istio/security/proto"
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
		Args: func(cmd *cobra.Command, args []string) error {
			// TODO(incfly): args validation.
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return Create(args[0], args[1])
		},
	}
)

// Create fetches a key cert pairm, signed by Citadel.Create
// The returned ceritifcate with `subject` encoded in the field specified by `format`.
func Create(format, subject string) error {
	// TODO(incfly): this code is duplicated in several places, (vm node agent, caclient, citactl).
	// Need refactor for de-duplication.

	csr, privKey, err := util.GenCSR(util.CertOptions{
		Host: subject,
		// Org:        na.config.CAClientConfig.Org,
		// RSAKeySize: na.config.CAClientConfig.RSAKeySize,
		// IsDualUse:  na.config.DualUse,
	})
	if err != nil {
		return err
	}
	fmt.Println("private key remove me...", privKey)
	req := &pb.CsrRequest{
		CsrPem: csr,
		// NodeAgentCredential: cred,
		// CredentialType:      c.platformClient.GetCredentialType(),
		// RequestedTtlMinutes: int32(opts.TTL.Minutes()),
	}
	conn, err := grpc.Dial("localhost")
	if err != nil {
		return err
	}
	client := pb.NewIstioCAServiceClient(conn)
	resp, err := client.HandleCSR(context.Background(), req)
	if err == nil && resp != nil && resp.IsApproved {
		return nil
	}
	if resp == nil {
		return fmt.Errorf("CSR signing failed: response empty")
	}
	if !resp.IsApproved {
		return fmt.Errorf("CSR signing failed: request not approved")
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().String("citadel", "localhost:15000", "Citadel server address")
	rootCmd.PersistentFlags().String("root-cert", "root.cert", "The output path for the root cert.")
	createCmd.PersistentFlags().Duration("duration", time.Hour*24,
		"The TTL of the generated certificate, default 24 hours.")
}

func main() {
	rootCmd.AddCommand(createCmd)
}
