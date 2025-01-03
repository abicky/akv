package mock

//go:generate mockgen -package mock -destination mocks.go github.com/abicky/akv/internal/injector ClientFactory,Client
