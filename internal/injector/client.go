package injector

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type ClientFactory interface {
	NewClient(vaultURL string) (Client, error)
}

type clientFactory struct {
	cred    azcore.TokenCredential
	clients map[string]Client
}

var _ ClientFactory = (*clientFactory)(nil)

type Client interface {
	GetSecret(context.Context, string, string, *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

func NewClientFactory(cred azcore.TokenCredential) ClientFactory {
	return &clientFactory{cred: cred, clients: make(map[string]Client)}
}

func (cf *clientFactory) NewClient(vaultName string) (Client, error) {
	if client, ok := cf.clients[vaultName]; ok {
		return client, nil
	}

	client, err := azsecrets.NewClient("https://"+vaultName+".vault.azure.net", cf.cred, nil)
	if err != nil {
		return nil, err
	}
	cf.clients[vaultName] = client

	return client, nil
}
