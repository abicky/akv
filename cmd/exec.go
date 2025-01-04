package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/abicky/akv/internal/injector"
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- COMMAND [args...]",
	Short: "Execute a command with Azure Key Vault secrets injected into environment variables",
	Long: `This command executes a command with Azure Key Vault secrets injected into environment
variables whose value is a secret reference in the format "akv://<vault-name>/<secret-name>"`,
	Args: cobra.MinimumNArgs(1),
	Example: `  $ az keyvault secret set --vault-name example --name password --value 'C@6LWQnuKDjQYHNE'
  $ env PASSWORD=akv://example/password akv exec -- printenv PASSWORD
  C@6LWQnuKDjQYHNE`,
	RunE: runExec,
}

func init() {
	rootCmd.AddCommand(execCmd)
}

func runExec(cmd *cobra.Command, args []string) error {
	// Prevent showing usage after validation
	cmd.SilenceUsage = true

	i, err := newInjector(injector.InjectionModeValue)
	if err != nil {
		return fmt.Errorf("failed to create injector: %w", err)
	}

	env := os.Environ()
	for idx, e := range env {
		kv := strings.SplitN(e, "=", 2)

		var sb strings.Builder
		if err := i.Inject(cmd.Context(), strings.NewReader(kv[1]), &sb, false, false); err != nil {
			return err
		}
		env[idx] = kv[0] + "=" + sb.String()
	}

	command, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("failed to search for the executable %q: %w", args[0], err)
	}

	if err := syscall.Exec(command, args, env); err != nil {
		return fmt.Errorf("failed to execute %q: %w", command, err)
	}
	return nil
}
