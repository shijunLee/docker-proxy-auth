package config

//DockerProxyAuthConfig the current proxy config
type DockerProxyAuthConfig struct {
	CurrentDomain string             `json:"currentDomain"`
	JWT           *JWTConfig         `json:"jwt"`
	AuthServer    *DockerAuthConfig  `json:"authServer"`
	Proxy         *DockerProxyConfig `json:"proxy"`
	UserAuth      *UserAuthConfig    `json:"userAuth"`
	Port          int                `json:"port"`
}

// JWTConfig the docker auth server jwt config
type JWTConfig struct {
	ExpirationTime  int    `json:"expirationTime"`
	JWTKey          string `json:"jwtKey"`
	PrivateKeyPath  string `json:"privateKeyPath"`
	PublicKeyPath   string `json:"publicKeyPath"`
	CertificatePath string `json:"certificatePath"`
	Algorithm       string `json:"algorithm"`
	Issuer          string `json:"issuer"`
}

//DockerAuthConfig docker auth server config
type DockerAuthConfig struct {
	RealIPHeader string `json:"realIPHeader"`
	RealIPPos    int    `json:"realIPPos"`
}

//DockerProxyConfig the docker proxy config
type DockerProxyConfig struct {
	ProxyAddress           string `json:"proxyAddress"`
	ForwardedProto         string `json:"forwardedProto"`
	ProxyAuthUsername      string `json:"proxyAuthUsername"`
	ProxyAuthPassword      string `json:"proxyAuthPassword"`
	AuthInsecureSkipVerify bool   `json:"authInsecureSkipVerify"`
	AuthPrivateKeyPath     string `json:"authPrivateKeyPath"`
	AuthPublicKeyPath      string `json:"authPublicKeyPath"`
}

//UserAuthConfig the user auth method config support ldap webhool oauth2 basicAuth
type UserAuthConfig struct {
	AuthType           string           `json:"authType"`
	Endpoint           string           `json:"endpoint"`
	InsecureSkipVerify bool             `json:"insecureSkipVerify"`
	PrivateKeyPath     string           `json:"privateKeyPath"`
	RootCAPath         string           `json:"rootCAPath"`
	CertificatePath    string           `json:"certificatePath"`
	LDAP               *LDAPConfig      `json:"ldap"`
	WebHook            *WebHookConfig   `json:"webhook"`
	OAuth2             *OAuth2Config    `json:"oauth2"`
	BasicAuth          *BasicAuthConfig `json:"basicAuth"`
}

//WebHookConfig web hook config the keyIn is Header or body ,and method is GET(only Header) or POST
type WebHookConfig struct {
	RequestMethod string            `json:"requestMethod"`
	KeyIn         string            `json:"keyIn"`
	CustomHeader  map[string]string `json:"customHeader"`
}

//LDAPConfig ldap client config
type LDAPConfig struct {
	BaseDN string `json:"baseDN"`
	Filter string `json:"filter"`
}

//OAuth2Config oauth2 config
type OAuth2Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	Scope        string `json:"scope"`
	// default use post
	RequestMethod string `json:"requestMethod"`
}

//BasicAuthConfig base auth config
type BasicAuthConfig struct {
	RequestMethod string            `json:"requestMethod"`
	CustomHeader  map[string]string `json:"customHeader"`
}

//PolicyConfig policy config
type PolicyConfig struct {
	UseWebHook   bool   `json:"useWebHook"`
	DataBaseType string `json:"dataBaseType"`
	DataBaseHost string `json:"dataBaseHost"`
	DataBasePort int    `json:"dataBasePort"`
	DataBaseName string `json:"databaseName"`
}
