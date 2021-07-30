package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
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
	urlRegex    = regexp.MustCompile(`/v2/[A-Za-z0-9|\-|_|/|\.]+/blobs/`)
	urlGetRegex = regexp.MustCompile(`/v2/[A-Za-z0-9|\-|_|/|\.]+/manifests/`)
	scopeRegex  = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
)

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

//scope=repository:samalba/my-app:push
func (t *DockerAuthProxy) VerifyDockerPolicy(w http.ResponseWriter, r *http.Request) (bool, string) {
	var repo = ""
	var operator = ""
	// pull GET docker.tpaas.jd.com /v2/busybox/manifests/1.31.1-glibc
	//Received request GET docker.tpaas.jd.com /v2/busybox/manifests/1.31.1-glibc 10.127.0.87:42468
	//Received request GET docker.tpaas.jd.com /v2/ 10.127.0.87:42468
	//Received request GET docker.tpaas.jd.com /v2/busybox/manifests/1.31.1-glibc 10.127.0.87:42674
	//Received request GET docker.tpaas.jd.com /v2/busybox/blobs/sha256:0e3a2ba15eaabe8ccaa18c4613dc039bd42b1bb289e71ca8afcd5c99e8513bbb 10.127.0.87:42468
	//Received request GET docker.tpaas.jd.com /v2/busybox/blobs/sha256:cf961e78c7616cfe2db43da699ae046666186162f30933341bdf9bfb92f2aa67 10.127.0.87:42678
	// push
	requestUri := r.RequestURI
	repo = parseRepo(requestUri)
	if repo == "" {
		return true, ""
	}
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return false, repo
	}
	tokens := strings.Split(authorization, " ")
	if len(tokens) < 2 {
		return false, repo
	}
	ar, err := t.DecodeToken(tokens[1])
	if err != nil {
		return false, repo
	}

	if strings.ToUpper(r.Method) == "GET" {
		operator = "pull"
	} else if strings.ToUpper(r.Method) == "HEAD" ||
		strings.ToUpper(r.Method) == "POST" ||
		strings.ToUpper(r.Method) == "PUT" ||
		strings.ToUpper(r.Method) == "PATCH" {
		operator = "push"
	}
	ari := &auth.AuthRequestInfo{}
	ari.Service = ar.Service
	ari.Account = ar.User
	ari.Type = "repository"
	ari.Name = repo
	ari.Actions = []string{
		operator,
	}
	_, err = t.UserResourcePolicy.AuthorizeUserResourceScope(ari)
	if err != nil {
		t.Logger.Error(fmt.Sprintf("verify user docker repo policy error, repo is %s ,operator is %s", repo, operator), err)
		return false, repo
	}
	return true, repo
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

func (t *DockerAuthProxy) ParseScope(scopeStr string) (*auth.AuthScope, error) {
	parts := strings.Split(scopeStr, ":")
	var scope auth.AuthScope

	scopeType, scopeClass, err := parseScope(parts[0])
	if err != nil {
		return nil, err
	}
	switch len(parts) {
	case 3:
		scope = auth.AuthScope{
			Type:    scopeType,
			Class:   scopeClass,
			Name:    parts[1],
			Actions: strings.Split(parts[2], ","),
		}
	case 4:
		scope = auth.AuthScope{
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
