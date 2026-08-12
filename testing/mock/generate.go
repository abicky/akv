package mock

//go:generate go tool mockgen -package mock -destination mocks.go github.com/abicky/akv/internal/injector ClientFactory,Client
