// Program citadel_cli is used for the admin operator to register, bootstrap identity and credentials.
package main

import (
	"github.com/spf13/cobra"
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
			// TODO(incfly): implement validation.
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
	return nil
}

func init() {
	rootCmd.PersistentFlags().String("citadel", "localhost:15000", "Citadel server address")
	rootCmd.PersistentFlags().String("root-cert", "root.cert", "The output path for the root cert.")
}

func main() {
	rootCmd.AddCommand(createCmd)
}
