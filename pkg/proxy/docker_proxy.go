package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shijunLee/docker-proxy-auth/pkg/log"
	"go.uber.org/zap"
)

type AuthType string

var (
	AuthTypeJWT   AuthType = "jwt"
	AuthTypeOAuth AuthType = "oauth"
	AuthTypeNone  AuthType = "none"
)

// https://github.com/cesanta/docker_auth.git
var (
	urlRegex      = regexp.MustCompile(`/v2/[A-Za-z0-9|\-|_|/|\.]+/blobs/`)
	urlGetRegex   = regexp.MustCompile(`/v2/[A-Za-z0-9|\-|_|/|\.]+/manifests/`)
	scopeRegex    = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
	hostPortRegex = regexp.MustCompile(`\[?(.+?)\]?:\d+$`)
)

type AuthRequest struct {
	RemoteConnAddr string
	RemoteAddr     string
	RemoteIP       net.IP
	User           string
	Password       string
	Account        string
	Service        string
	Scopes         []AuthScope
	Labels         map[string][]string
}

type AuthScope struct {
	Type    string
	Class   string
	Name    string
	Actions []string
}
type DockerAuthProxy struct {
	ProxyAddress        string
	CurrentSchema       string
	ForwardedProto      string
	ProxyLocationPrefix string
	proxy               *httputil.ReverseProxy
	AuthType            AuthType
	ProxyAuthUserName   string
	ProxyAuthPassword   string
	WebAuthURL          string
	WebAuthType         string
	ProxyConfig         ProxyConfig
}

type ProxyConfig struct {
	RealIPHeader string
	RealIPPos    int
}

func (p *DockerAuthProxy) InitReverseProxy(targetUrl string) error {
	dockerUrl, err := url.Parse(targetUrl)
	if err != nil {
		return err
	}
	p.proxy = httputil.NewSingleHostReverseProxy(dockerUrl)
	p.proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 20 * time.Minute,
		}).DialContext,
		DialTLSContext: (&net.Dialer{
			Timeout: 20 * time.Minute,
		}).DialContext,
	}
	p.proxy.Director = func(req *http.Request) {
		if p.ProxyHttps() {
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		req.URL.Scheme = dockerUrl.Scheme
		req.URL.Host = dockerUrl.Host
		//req.URL.Path = req.URL.Path
		log.Logger.Debug("------------------------------------------------------")
		log.Logger.Debug("RequestPath", zap.String("RequestPath", req.URL.Path))
		for key, value := range req.Header {
			log.Logger.Debug("request header", zap.Any(key, value))
		}
		log.Logger.Debug("------------------------------------------------------")
	}
	p.proxy.ModifyResponse = func(response *http.Response) error {
		for key, value := range response.Header {
			for _, v := range value {
				if key == "Location" {
					v = p.ReplaceResponseLocation(v, response.Request)
					response.Header.Set(key, v)
				}
				log.Logger.Debug(fmt.Sprintf("response HeaderKey = '%s' value = '%s'", key, v))
			}
		}
		return nil
	}
	return nil
}

func (p *DockerAuthProxy) DoProxy(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

func (p *DockerAuthProxy) ReplaceResponseLocation(location string, request *http.Request) string {
	if p.ProxyHttps() && strings.HasPrefix(location, p.ProxyLocationPrefix) {
		return strings.Replace(location, "http://", "https://", -1)
	}
	return location
}

func (p *DockerAuthProxy) ProcessRequestAuth(req *http.Request) {

}

func (p *DockerAuthProxy) ProcessRegistryAuth(req *http.Request) {

}

func (p *DockerAuthProxy) ProxyHttps() bool {
	proxyURL, err := url.Parse(p.ProxyAddress)
	if err != nil {
		log.Logger.Error("the config of docker proxy address", zap.Error(err))
		panic("the config of docker proxy address")
	}
	if proxyURL.Scheme == p.CurrentSchema {
		return true
	}
	return false
}

func parseRemoteAddr(ra string) net.IP {
	hp := hostPortRegex.FindStringSubmatch(ra)
	if hp != nil {
		ra = string(hp[1])
	}
	res := net.ParseIP(ra)
	return res
}

func (r *DockerAuthProxy) ParseRequest(req *http.Request) (*AuthRequest, error) {
	ar := &AuthRequest{RemoteConnAddr: req.RemoteAddr, RemoteAddr: req.RemoteAddr}
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

func (r *DockerAuthProxy) ParseRepoRequest(req *http.Request) *AuthScope {
	var resourceType = ""
	var class = ""
	var repoName = ""
	var actions []string
	if strings.HasPrefix(req.URL.Path, "/v2/_catalog") {
		resourceType = "registry"
		actions = append(actions, "*")
		return &AuthScope{
			Type:    resourceType,
			Actions: actions,
		}
	}
	repoName = parseRepo(req.URL.RawPath)
	resourceType = "repository"
	reqMethod := req.Method
	switch reqMethod {
	case "GET", "HEAD":
		actions = append(actions, "pull")
	case "PUT", "POST", "PATCH", "DELETE":
		actions = append(actions, "push")
	default:
		actions = append(actions, "pull")
	}
	class = "image"
	return &AuthScope{
		Type:    resourceType,
		Class:   class,
		Name:    repoName,
		Actions: actions,
	}
}

func parseRepo(requestPath string) string {
	if strings.Contains(requestPath, "/blobs/") {
		urlInfos := urlRegex.FindAllString(requestPath, -1)
		if len(urlInfos) > 0 {
			repoUrl := urlInfos[0]
			repoUrl = strings.TrimSuffix(strings.TrimPrefix(repoUrl, "/v2/"), "/blobs/")
			return repoUrl
		}
	} else if strings.Contains(requestPath, "/manifests/") {
		urlInfos := urlGetRegex.FindAllString(requestPath, -1)
		if len(urlInfos) > 0 {
			repoUrl := urlInfos[0]
			repoUrl = strings.TrimSuffix(strings.TrimPrefix(repoUrl, "/v2/"), "/manifests/")
			return repoUrl
		}
	}

	return ""
}

func (t *DockerAuthProxy) ParseScope(scopeStr string) (*AuthScope, error) {
	parts := strings.Split(scopeStr, ":")
	var scope AuthScope

	scopeType, scopeClass, err := parseScope(parts[0])
	if err != nil {
		return nil, err
	}
	switch len(parts) {
	case 3:
		scope = AuthScope{
			Type:    scopeType,
			Class:   scopeClass,
			Name:    parts[1],
			Actions: strings.Split(parts[2], ","),
		}
	case 4:
		scope = AuthScope{
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
