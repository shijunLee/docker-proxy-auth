package userauth

import "context"

type Auth interface {
	AuthUser(ctx context.Context, username, password string) bool
}
