package injector_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	azsecretsfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets/fake"
	"github.com/abicky/akv/internal/injector"
)

type clientFactoryFunc func(vaultName string) (injector.Client, error)

func (f clientFactoryFunc) NewClient(vaultName string) (injector.Client, error) {
	return f(vaultName)
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
		vaultName string
		secrets   []secret
		escape    bool
		quote     bool
		want      string
		clientErr error
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
			clientErr: nil,
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
			clientErr: nil,
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
			clientErr: nil,
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
			clientErr: nil,
			secretErr: nil,
		},
		{
			name:      "Client error",
			input:     "akv://vaultname/secret-name",
			secrets:   []secret{},
			escape:    false,
			quote:     false,
			want:      "",
			clientErr: errors.New("error"),
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
			clientErr: nil,
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

			// NOTE: The Azure SDK's fake Key Vault challenge requires the vault hostname to contain at least four labels.
			// See:
			//   https://github.com/Azure/azure-sdk-for-go/blob/sdk/security/keyvault/internal/v1.2.0/sdk/security/keyvault/internal/fake_challenge.go#L31-L33
			//   https://github.com/Azure/azure-sdk-for-go/blob/sdk/security/keyvault/internal/v1.2.0/sdk/security/keyvault/internal/challenge_policy.go#L142-L151
			client, err := azsecrets.NewClient("https://fake.vault.example.com", &azfake.TokenCredential{}, &azsecrets.ClientOptions{
				ClientOptions: azcore.ClientOptions{
					Transport: azsecretsfake.NewServerTransport(&server),
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			factory := clientFactoryFunc(func(vaultName string) (injector.Client, error) {
				if tt.clientErr != nil {
					return nil, tt.clientErr
				}
				if calledCount >= len(tt.secrets) {
					t.Errorf("unexpected new client request")
					return nil, errors.New("unexpected new client request")
				}

				secret := tt.secrets[calledCount]
				if vaultName != secret.vaultName {
					t.Errorf("vaultName = %v; want %v", vaultName, secret.vaultName)
				}
				return client, nil
			})

			i, err := injector.NewInjector(injector.InjectionModeText, factory)
			if err != nil {
				t.Fatal(err)
			}

			var sb strings.Builder
			err = i.Inject(t.Context(), strings.NewReader(tt.input), &sb, tt.escape, tt.quote)
			if tt.clientErr == nil && tt.secretErr == nil {
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
			if tt.clientErr == nil && tt.secretErr == nil && calledCount != len(tt.secrets) {
				t.Errorf("calledCount = %v; want %v", calledCount, len(tt.secrets))
			}
		})
	}
}
