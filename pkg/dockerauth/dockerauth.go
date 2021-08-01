package dockerauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"net"
	"regexp"

	"net/http"
	"sort"
	"strings"

	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/log"
	"github.com/shijunLee/docker-proxy-auth/pkg/userauth"
	"go.uber.org/zap"
)

var (
	scopeRegex    = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

type AuthType string

var (
	AuthTypeJWT   AuthType = "jwt"
	AuthTypeOAuth AuthType = "oauth"
	AuthTypeNone  AuthType = "none"
)

type DockerAuth struct {
	ProxyConfig          *ProxyConfig
	Auth                 userauth.Auth
	DockerPolicyAuth     DockerPolicyAuth
	JWT                  *JWTConfig
	CurrentServiceDomain string
	AuthPath             string
}

type ProxyConfig struct {
	RealIPHeader string
	RealIPPos    int
}

type AuthResult struct {
	Scope            common.AuthScope
	AutorizedActions []string
}
type JWTConfig struct {
	Issuer         string
	CertKeyPath    string
	PrivateKeyPath string
	Expiration     int
	publicKey      libtrust.PublicKey
	privateKey     libtrust.PrivateKey
}

func (r *DockerAuth) ParseRequest(req *http.Request) (*common.AuthRequest, error) {
	ar := &common.AuthRequest{RemoteConnAddr: req.RemoteAddr, RemoteAddr: req.RemoteAddr}
	if r.ProxyConfig.RealIPHeader != "" {
		hv := req.Header.Get(r.ProxyConfig.RealIPHeader)
		ips := strings.Split(hv, ",")
		realIPPos := r.ProxyConfig.RealIPPos
		if realIPPos < 0 {
			realIPPos = len(ips) + realIPPos
			if realIPPos < 0 {
				realIPPos = 0
			}
		}
		ar.RemoteAddr = strings.TrimSpace(ips[realIPPos])
		log.Logger.Info("conn info", zap.String("RemoteAddr", ar.RemoteAddr),
			zap.String("RealIPHeader", r.ProxyConfig.RealIPHeader),
			zap.String("RealIPHeaderValue", hv))
		if ar.RemoteAddr == "" {
			return nil, fmt.Errorf("client address not provided")
		}
	}
	ar.RemoteIP = parseRemoteAddr(ar.RemoteAddr)
	if ar.RemoteIP == nil {
		return nil, fmt.Errorf("unable to parse remote addr %s", ar.RemoteAddr)
	}
	user, password, haveBasicAuth := req.BasicAuth()
	if haveBasicAuth {
		ar.User = user
		ar.Password = password
	} else if req.Method == "POST" {
		// username and password could be part of form data
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username != "" && password != "" {
			ar.User = username
			ar.Password = password
		}
	}
	ar.Account = req.FormValue("account")
	if ar.Account == "" {
		ar.Account = ar.User
	} else if haveBasicAuth && ar.Account != ar.User {
		return nil, fmt.Errorf("user and account are not the same (%q vs %q)", ar.User, ar.Account)
	}
	ar.Service = req.FormValue("service")
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid form value")
	}
	//https://docs.docker.com/registry/spec/auth/token/
	// https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/scope.md#resource-scope-grammar
	if req.FormValue("scope") != "" {
		for _, scopeValue := range req.Form["scope"] {
			for _, scopeStr := range strings.Split(scopeValue, " ") {

				scope, err := r.ParseScope(scopeStr)
				if err != nil {
					log.Logger.Error("parse scope error", zap.Error(err))
					return nil, fmt.Errorf("invalid scope: %q", scopeStr)
				}
				sort.Strings(scope.Actions)
				ar.Scopes = append(ar.Scopes, *scope)
			}
		}
	}
	return ar, nil
}

//AuthClient do request Auth from this method
func (c *DockerAuth) AuthClient(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	errorMessage := `{"errors": [{"code": "UNAUTHORIZED", "message": "%v", "detail": null }]}`
	log.Logger.Debug(fmt.Sprintf("token is %v ,request url is %v", r.Header["Authorization"], r.RequestURI))
	ar, err := c.ParseRequest(r)
	if err != nil {
		log.Logger.Error("Bad request: %s", zap.Error(err))
		http.Error(w, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}
	if ar.Account == "" || ar.Password == "" {
		service := r.FormValue("service")
		scope := r.FormValue("scope")
		authenticateVaule := fmt.Sprintf(`Bearer realm="%s",service="%s""`, c.GetRealmUrl(), service)
		if scope != "" {
			authenticateVaule = fmt.Sprintf(`%s,scope="%s"`, authenticateVaule, scope)
		}
		w.Header()["WWW-Authenticate"] = []string{authenticateVaule}
		http.Error(w, fmt.Sprintf(errorMessage, "user name or password not set"), http.StatusUnauthorized)
		return
	}
	ares := []common.AuthResult{}
	ok := c.Auth.AuthUser(ctx, ar.Account, ar.Password)
	if !ok {
		log.Logger.Error(fmt.Sprintf("Auth failed: %v", *ar), zap.Error(err))
		http.Error(w, fmt.Sprintf(errorMessage, err), http.StatusUnauthorized)
		return
	}
	if !ok {
		log.Logger.Error(fmt.Sprintf("Auth failed:%v", *ar), zap.Error(errors.New("user name or account not exist")))
		w.Header()["WWW-Authenticate"] = []string{fmt.Sprintf(`Basic realm="%s"`, "tpaas")}
		http.Error(w, fmt.Sprintf(errorMessage, "authorized failed"), http.StatusUnauthorized)
		return
	}
	//ar.Labels = labels

	if len(ar.Scopes) > 0 {
		ares, err = c.Authorize(ar)
		if err != nil {
			http.Error(w, fmt.Sprintf(errorMessage, err), http.StatusUnauthorized)
			return
		}
	} else {
		// Authentication-only request ("docker login"), pass through.
	}

	token, err := c.CreateToken(ar, ares)
	if err != nil {
		msg := fmt.Sprintf("Failed to generate token %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		log.Logger.Error(fmt.Sprintf("%s: %s", ar, msg), zap.Error(err))
		return
	}
	expiresIn := time.Now().UTC().Unix() + int64((time.Duration(c.JWT.Expiration) * time.Second).Seconds())
	result, _ := json.Marshal(&map[string]interface{}{
		"access_token": token,
		"token":        token,
		"expires_in":   expiresIn,
		"issued_at":    time.Now(),
	})
	log.Logger.Info("获取token结果为", zap.Any("TokenResult", result))
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)

}

func (r *DockerAuth) Authorize(ar *common.AuthRequest) ([]common.AuthResult, error) {
	ares := []common.AuthResult{}
	for _, scope := range ar.Scopes {
		ai := &common.AuthRequestInfo{
			Account: ar.Account,
			Type:    scope.Type,
			Name:    scope.Name,
			Service: ar.Service,
			IP:      ar.RemoteIP,
			Actions: scope.Actions,
			Labels:  ar.Labels,
		}
		actions, err := r.DockerPolicyAuth.AuthorizeUserResourceScope(ai)
		if err != nil {
			return nil, err
		}
		ares = append(ares, common.AuthResult{Scope: scope, AutorizedActions: actions})
	}
	return ares, nil
}

func (t *DockerAuth) CreateToken(ar *common.AuthRequest, ares []common.AuthResult) (string, error) {
	now := time.Now().UTC().Unix()
	tc := t.JWT

	// Sign something dummy to find out which algorithm is used.
	_, sigAlg, err := tc.privateKey.Sign(strings.NewReader("dummy"), 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %s", err)
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: sigAlg,
		KeyID:      tc.publicKey.KeyID(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %s", err)
	}

	claims := token.ClaimSet{
		Issuer:     tc.Issuer,
		Subject:    ar.Account,
		Audience:   ar.Service,
		NotBefore:  now - 10,
		IssuedAt:   now,
		Expiration: now + int64((time.Duration(tc.Expiration) * time.Second).Seconds()),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	if len(ares) == 0 {
		ares = append(ares, common.AuthResult{
			Scope: common.AuthScope{
				Type: "registry", Name: "catalog",
				Actions: []string{"*"}},
			AutorizedActions: []string{"*"}})
	}
	for _, a := range ares {
		ra := &token.ResourceActions{
			Type:    a.Scope.Type,
			Name:    a.Scope.Name,
			Actions: a.AutorizedActions,
		}
		if ra.Actions == nil {
			ra.Actions = []string{}
		}
		sort.Strings(ra.Actions)
		claims.Access = append(claims.Access, ra)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %s", err)
	}

	payload := fmt.Sprintf("%s%s%s", common.JoseBase64UrlEncode(headerJSON), token.TokenSeparator, common.JoseBase64UrlEncode(claimsJSON))

	sig, sigAlg2, err := tc.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil || sigAlg2 != sigAlg {
		return "", fmt.Errorf("failed to sign token: %s", err)
	}
	//t.logger.Info(fmt.Sprintf("New token for %s %+v: %s", *ar, ar.Labels, claimsJSON))
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, common.JoseBase64UrlEncode(sig)), nil
}

func parseRemoteAddr(ra string) net.IP {
	hp := hostPortRegex.FindStringSubmatch(ra)
	if hp != nil {
		ra = string(hp[1])
	}
	res := net.ParseIP(ra)
	return res
}

func (t *DockerAuth) ParseScope(scopeStr string) (*common.AuthScope, error) {
	parts := strings.Split(scopeStr, ":")
	var scope common.AuthScope

	scopeType, scopeClass, err := parseScope(parts[0])
	if err != nil {
		return nil, err
	}
	switch len(parts) {
	case 3:
		scope = common.AuthScope{
			Type:    scopeType,
			Class:   scopeClass,
			Name:    parts[1],
			Actions: strings.Split(parts[2], ","),
		}
	case 4:
		scope = common.AuthScope{
			Type:    scopeType,
			Class:   scopeClass,
			Name:    parts[1] + ":" + parts[2],
			Actions: strings.Split(parts[3], ","),
		}
	default:
		return nil, fmt.Errorf("invalid scope: %q", scopeStr)
	}
	return &scope, nil
}

func parseScope(scope string) (string, string, error) {
	parts := scopeRegex.FindStringSubmatch(scope)
	if parts == nil {
		return "", "", fmt.Errorf("malformed scope request")
	}
	switch len(parts) {
	case 3:
		return parts[1], "", nil
	case 4:
		return parts[1], parts[3], nil
	default:
		return "", "", fmt.Errorf("malformed scope request")
	}
}
func (t *DockerAuth) GetRealmUrl() string {
	return fmt.Sprintf("%s%s", t.CurrentServiceDomain, t.AuthPath)
}
