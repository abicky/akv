// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/abicky/akv/internal/injector (interfaces: ClientFactory,Client)
//
// Generated by this command:
//
//	mockgen -package mock -destination mocks.go github.com/abicky/akv/internal/injector ClientFactory,Client
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	azsecrets "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	injector "github.com/abicky/akv/internal/injector"
	gomock "go.uber.org/mock/gomock"
)

// MockClientFactory is a mock of ClientFactory interface.
type MockClientFactory struct {
	ctrl     *gomock.Controller
	recorder *MockClientFactoryMockRecorder
	isgomock struct{}
}

// MockClientFactoryMockRecorder is the mock recorder for MockClientFactory.
type MockClientFactoryMockRecorder struct {
	mock *MockClientFactory
}

// NewMockClientFactory creates a new mock instance.
func NewMockClientFactory(ctrl *gomock.Controller) *MockClientFactory {
	mock := &MockClientFactory{ctrl: ctrl}
	mock.recorder = &MockClientFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientFactory) EXPECT() *MockClientFactoryMockRecorder {
	return m.recorder
}

// NewClient mocks base method.
func (m *MockClientFactory) NewClient(vaultURL string) (injector.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewClient", vaultURL)
	ret0, _ := ret[0].(injector.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewClient indicates an expected call of NewClient.
func (mr *MockClientFactoryMockRecorder) NewClient(vaultURL any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClient", reflect.TypeOf((*MockClientFactory)(nil).NewClient), vaultURL)
}

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
	isgomock struct{}
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// GetSecret mocks base method.
func (m *MockClient) GetSecret(arg0 context.Context, arg1, arg2 string, arg3 *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecret", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(azsecrets.GetSecretResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecret indicates an expected call of GetSecret.
func (mr *MockClientMockRecorder) GetSecret(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecret", reflect.TypeOf((*MockClient)(nil).GetSecret), arg0, arg1, arg2, arg3)
}
