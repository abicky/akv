package injector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

const (
	InjectionModeText = iota
	InjectionModeValue

	// Vault name and Managed HSM pool name must be a 3-24 character string, containing only 0-9, a-z, A-Z, and not consecutive -.
	// See: https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates
	keyVaultNamePattern = "[A-Za-z0-9-]{3,24}"
)

type Injector struct {
	cred    azcore.TokenCredential
	options *azsecrets.ClientOptions
	clients map[string]*azsecrets.Client
	re      *regexp.Regexp
}

const baseRegexp = `akv://` + keyVaultNamePattern + `/[-0-9A-Za-z]{1,127}`

func NewInjector(mode int, cred azcore.TokenCredential, options *azsecrets.ClientOptions) (*Injector, error) {
	var exp string
	switch mode {
	case InjectionModeText:
		exp = `\b` + baseRegexp + `\b`
	case InjectionModeValue:
		exp = `\A` + baseRegexp + `\z`
	}

	return &Injector{
		cred:    cred,
		options: options,
		clients: make(map[string]*azsecrets.Client),
		re:      regexp.MustCompile(exp),
	}, nil
}

func (i *Injector) Inject(ctx context.Context, input io.Reader, output io.Writer, escape, quote bool) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(scanLinesWithNewlines)
	for scanner.Scan() {
		var err error
		var client *azsecrets.Client
		injected := i.re.ReplaceAllStringFunc(scanner.Text(), func(s string) string {
			if err != nil {
				return ""
			}

			parts := strings.Split(strings.TrimPrefix(s, "akv://"), "/")
			client, err = i.client(parts[0])
			if err != nil {
				err = fmt.Errorf("failed to initialize client: %w", err)
				return ""
			}

			resp, e := client.GetSecret(ctx, parts[1], "", nil)
			if e != nil {
				err = fmt.Errorf("failed to get secret: %w", e)
				return ""
			}

			value := *resp.Value
			if quote || escape {
				value = fmt.Sprintf("%q", value)
			}
			if escape {
				value = value[1 : len(value)-1]
			}
			return value
		})
		if err != nil {
			return err
		}

		fmt.Fprint(output, injected)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	return nil
}

func (i *Injector) client(vaultName string) (*azsecrets.Client, error) {
	if client, ok := i.clients[vaultName]; ok {
		return client, nil
	}

	client, err := azsecrets.NewClient("https://"+vaultName+".vault.azure.net", i.cred, i.options)
	if err != nil {
		return nil, err
	}
	i.clients[vaultName] = client

	return client, nil
}

// This function is derived from bufio.ScanLines to keep newlines
func scanLinesWithNewlines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, data[0 : i+1], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
