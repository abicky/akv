package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/abicky/akv/internal/injector"
	"github.com/spf13/cobra"
)

var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Inject Azure Key Vault secrets into input data",
	Long: `This command injects Azure Key Vault secrets into input data
with secret references in the format "akv://<vault-name>/<secret-name>"`,
	Args: cobra.NoArgs,
	Example: `  $ az keyvault secret set --vault-name example --name password --value 'C@6LWQnuKDjQYHNE-*.h'
  $ echo 'password: akv://example/password' | akv inject
  password: C@6LWQnuKDjQYHNE-*.h
  $ cat secret.yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: password
  stringData:
    password: akv://example/password
  $ akv inject <secret.yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: password
  stringData:
    password: C@6LWQnuKDjQYHNE-*.h`,
	RunE: runInject,
}

func init() {
	rootCmd.AddCommand(injectCmd)
}

func runInject(cmd *cobra.Command, args []string) error {
	// cf. https://stackoverflow.com/a/26567513
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return errors.New("data from stdin is required")
	}

	// Prevent showing usage after validation
	cmd.SilenceUsage = true

	i, err := newInjector(injector.InjectionModeText)
	if err != nil {
		return fmt.Errorf("failed to create injector: %w", err)
	}

	b := bufio.NewWriter(os.Stdout)
	defer b.Flush()
	return i.Inject(cmd.Context(), os.Stdin, b)
}
