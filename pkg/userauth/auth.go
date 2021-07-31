package userauth

type Auth interface {
	AuthUser(username, password string) bool
}
