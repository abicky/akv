package cmd

import (
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/abicky/akv/internal/injector"
	"github.com/spf13/cobra"
)

const version = "0.1.1"

// This variable should be overwritten by -ldflags
var revision = "HEAD"

var rootCmd = &cobra.Command{
	Use:     "akv",
	Short:   "A CLI tool for injecting Azure Key Vault secrets",
	Long:    "A CLI tool for injecting Azure Key Vault secrets",
	Version: version,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf(
		`{{with .Name}}{{printf "%%s " .}}{{end}}{{printf "version %%s" .Version}} (revision %s)
`, revision))
}

func newInjector(mode int) (*injector.Injector, error) {
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		AdditionallyAllowedTenants: []string{"*"},
	})
	if err != nil {
		return nil, err
	}
	return injector.NewInjector(mode, injector.NewClientFactory(cred))
}
