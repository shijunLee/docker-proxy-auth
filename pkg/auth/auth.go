package auth

type Auth interface {
	AuthUser(username, password string) bool
}
