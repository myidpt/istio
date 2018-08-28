// Program citadel_cli is used for the admin operator to register, bootstrap identity and credentials.
package main

import "github.com/spf13/cobra"

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
		Use:     "create",
		Short:   "Generates a certificate for a service.",
		Example: "citactl create dns www.service-a.example.com",
		RunE: func(c *cobra.Command, args []string) error {
			return nil
		},
	}
)

func main() {
	rootCmd.AddCommand(createCmd)
}
