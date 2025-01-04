package injector_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/abicky/akv/internal/injector"
	"github.com/abicky/akv/testing/mock"
	"go.uber.org/mock/gomock"
)

func TestInject(t *testing.T) {
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
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := context.Background()

			factory := mock.NewMockClientFactory(ctrl)
			client := mock.NewMockClient(ctrl)
			i, err := injector.NewInjector(injector.InjectionModeText, factory)
			if err != nil {
				t.Fatal(err)
			}

			calledCount := 0
			factory.EXPECT().NewClient(gomock.Any()).DoAndReturn(func(vaultName string) (injector.Client, error) {
				if tt.clientErr != nil {
					return nil, tt.clientErr
				}

				secret := tt.secrets[calledCount]
				if vaultName != secret.vaultName {
					t.Errorf("valutName = %v; want %v", vaultName, secret.vaultName)
				}
				return client, nil
			}).AnyTimes()

			client.EXPECT().GetSecret(ctx, gomock.Any(), "", nil).DoAndReturn(func(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
				if tt.secretErr != nil {
					return azsecrets.GetSecretResponse{}, tt.secretErr
				}

				secret := tt.secrets[calledCount]
				if name != secret.name {
					t.Errorf("name = %v; want %v", name, secret.name)
				}
				calledCount++

				return azsecrets.GetSecretResponse{
					Secret: azsecrets.Secret{
						Value: &secret.value,
					},
				}, tt.secretErr
			}).AnyTimes()

			var sb strings.Builder
			err = i.Inject(ctx, strings.NewReader(tt.input), &sb, tt.escape, tt.quote)
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
				t.Errorf("sb.String() = %v, want %v", sb.String(), tt.want)
			}
		})
	}
}
