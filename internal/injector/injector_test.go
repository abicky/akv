package injector_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	azsecretsfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets/fake"
	"github.com/abicky/akv/internal/injector"
)

type validatingTransport struct {
	next     policy.Transporter
	validate func(*http.Request)
}

func (t *validatingTransport) Do(req *http.Request) (*http.Response, error) {
	t.validate(req)
	return t.next.Do(req)
}

func TestInjector_Inject(t *testing.T) {
	type secret struct {
		vaultName string
		name      string
		value     string
	}

	tests := []struct {
		name      string
		input     string
		secrets   []secret
		escape    bool
		quote     bool
		want      string
		secretErr error
	}{
		{
			name:  "Simple reference",
			input: "akv://vaultname/secret-name",
			secrets: []secret{
				{
					vaultName: "vaultname",
					name:      "secret-name",
					value:     "foo",
				},
			},
			escape:    false,
			quote:     false,
			want:      "foo",
			secretErr: nil,
		},
		{
			name: "Multiple references",
			input: `secret1: akv://vaultname1/secret-name1, secret2: akv://vaultname2/secret-name2
secret3:akv://vaultname3/secret-name3
"secret4": "akv://vaultname4/secret-name4"`,
			secrets: []secret{
				{
					vaultName: "vaultname1",
					name:      "secret-name1",
					value:     "foo",
				},
				{
					vaultName: "vaultname2",
					name:      "secret-name2",
					value:     "bar",
				},
				{
					vaultName: "vaultname3",
					name:      "secret-name3",
					value:     "baz",
				},
				{
					vaultName: "vaultname4",
					name:      "secret-name4",
					value:     "qux",
				},
			},
			escape: false,
			quote:  false,
			want: `secret1: foo, secret2: bar
secret3:baz
"secret4": "qux"`,
			secretErr: nil,
		},
		{
			name:  "Multiline secret with quote true",
			input: `secret: akv://vaultname/secret-name`,
			secrets: []secret{
				{
					vaultName: "vaultname",
					name:      "secret-name",
					value:     "multiline\nsecret with \"quotes\"",
				},
			},
			escape:    false,
			quote:     true,
			want:      `secret: "multiline\nsecret with \"quotes\""`,
			secretErr: nil,
		},
		{
			name:  "Multiline secret with escape true",
			input: `{"secret": "akv://vaultname/secret-name"}`,
			secrets: []secret{
				{
					vaultName: "vaultname",
					name:      "secret-name",
					value:     "multiline\nsecret with \"quotes\"",
				},
			},
			escape:    true,
			quote:     false,
			want:      `{"secret": "multiline\nsecret with \"quotes\""}`,
			secretErr: nil,
		},
		{
			name:  "Secret error",
			input: "akv://vaultname/secret-name",
			secrets: []secret{
				{
					vaultName: "vaultname",
				},
			},
			escape:    false,
			quote:     false,
			want:      "",
			secretErr: errors.New("error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calledCount := 0
			server := azsecretsfake.Server{
				GetSecret: func(_ context.Context, name, _ string, _ *azsecrets.GetSecretOptions) (resp azfake.Responder[azsecrets.GetSecretResponse], errResp azfake.ErrorResponder) {
					if tt.secretErr != nil {
						errResp.SetError(tt.secretErr)
						return
					}
					if calledCount >= len(tt.secrets) {
						t.Errorf("unexpected request")
						errResp.SetError(errors.New("unexpected request"))
						return
					}

					secret := tt.secrets[calledCount]
					// The SDK passes "{secret_name}/{secret_version}" as the name argument.
					// When the version is empty, the name therefore has a trailing "/".
					// See: https://github.com/Azure/azure-sdk-for-go/issues/27393
					if strings.TrimSuffix(name, "/") != secret.name {
						t.Errorf("name = %v; want %v", name, secret.name)
					}
					calledCount++

					resp.SetResponse(http.StatusOK, azsecrets.GetSecretResponse{
						Secret: azsecrets.Secret{
							Value: &secret.value,
						},
					}, nil)
					return
				},
			}

			transport := &validatingTransport{
				next: azsecretsfake.NewServerTransport(&server),
				validate: func(req *http.Request) {
					if calledCount >= len(tt.secrets) {
						t.Errorf("unexpected request to %q", req.URL.Host)
						return
					}

					want := tt.secrets[calledCount].vaultName + ".vault.azure.net"
					if req.URL.Host != want {
						t.Errorf("request host = %q; want %q", req.URL.Host, want)
					}
				},
			}
			i, err := injector.NewInjector(injector.InjectionModeText, &azfake.TokenCredential{}, &azsecrets.ClientOptions{
				ClientOptions: azcore.ClientOptions{
					Transport: transport,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			var sb strings.Builder
			err = i.Inject(t.Context(), strings.NewReader(tt.input), &sb, tt.escape, tt.quote)
			if tt.secretErr == nil {
				if err != nil {
					t.Errorf("err = %#v; want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("err = nil; want non-nil")
				}
			}

			if sb.String() != tt.want {
				t.Errorf("sb.String() = %v; want %v", sb.String(), tt.want)
			}
			if tt.secretErr == nil && calledCount != len(tt.secrets) {
				t.Errorf("calledCount = %v; want %v", calledCount, len(tt.secrets))
			}
		})
	}
}
