package config

type DockerProxyAuthConfig struct {
	CurrentDomain string `json:"CurrentDomain"`
}

type JWTConfig struct {
	ExpirationTime int    `json:"expirationTime"`
	JWTKey         string `json:"jwtKey"`
	PrivateKeyPath string `json:"privateKeyPath"`
	PublicKeyPath  string `json:"publicKeyPath"`
	Algorithm      string `json:"algorithm"`
}

type DockerAuthConfig struct {
	RealIPHeader string `json:"realIPHeader"`
	RealIPPos    int    `json:"realIPPos"`
}

type DockerProxyConfig struct {
	ProxyAddress      string `json:"proxyAddress"`
	ForwardedProto    string `json:"forwardedProto"`
	ProxyAuthUsername string `json:"proxyAuthUsername"`
	ProxyAuthPassword string `json:"proxyAuthPassword"`
}

type UserAuthConfig struct {
	AuthType string `json:"authType"`
}

type WebHook struct {
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	KeyIn        string            `json:"keyIn"`
	CustomHeader map[string]string `json:"costomHeader"`
}
