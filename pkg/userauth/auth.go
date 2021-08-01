package userauth

import "context"

type Auth interface {
	AuthUser(context context.Context, username, password string) bool
}
