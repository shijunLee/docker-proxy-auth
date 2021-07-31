package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/log"
	"github.com/shijunLee/docker-proxy-auth/pkg/userauth"
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

	CurrentHost string
	UserAuth    userauth.Auth
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
	requestPath := r.URL.Path
	if strings.HasPrefix(requestPath, "/v2") {
		if ok, token := p.processRequest(r, w); ok && p.verifyToken(token) {
			p.proxy.ServeHTTP(w, r)
		}
	}

}

func (p *DockerAuthProxy) ReplaceResponseLocation(location string, request *http.Request) string {
	if p.ProxyHttps() && strings.HasPrefix(location, p.ProxyLocationPrefix) {
		return strings.Replace(location, "http://", "https://", -1)
	}
	return location
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

//processRequest do auth and token verify for request
// HTTP/1.1 401 Unauthorized
// Content-Type: application/json; charset=utf-8
// Docker-Distribution-Api-Version: registry/2.0
// Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"
// Date: Thu, 10 Sep 2015 19:32:31 GMT
// Content-Length: 235
// Strict-Transport-Security: max-age=31536000

// {"errors":[{"code":"UNAUTHORIZED","message":"access to the requested resource is not authorized","detail":[{"Type":"repository","Name":"samalba/my-app","Action":"pull"},{"Type":"repository","Name":"samalba/my-app","Action":"push"}]}]}

func (r *DockerAuthProxy) processRequest(req *http.Request, w http.ResponseWriter) (bool, string) {
	authScope := r.ParseRepoRequest(req)
	authorizationInfo := req.Header.Get("Authorization")
	isNotContainToken := false
	if authorizationInfo == "" {
		isNotContainToken = true
	}
	authorizationInfos := strings.Split(authorizationInfo, " ")
	if len(authorizationInfos) != 2 || authorizationInfos[0] != "Bearer" {
		isNotContainToken = true
	}
	if !r.verifyToken(authorizationInfos[1]) {
		isNotContainToken = true
	}
	if isNotContainToken {
		w.Header().Add("Content-Type", "application/json; charset=utf-8")
		w.Header().Add("Docker-Distribution-Api-Version", "registry/2.0")
		realm := fmt.Sprintf(`realm="%s/dockerauth,service="registry.docker.io",scope="%s:%s:%s"`, r.CurrentHost, authScope.Type, authScope.Name, strings.Join(authScope.Actions, ","))
		w.Header().Add("Www-Authenticate", fmt.Sprintf("Bearer %s", realm))
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(401)
		result := common.NewDockerUnauthorized(authScope)
		// do not need process err here
		data, _ := json.Marshal(result)
		w.Write(data)
		return false, ""
	}
	return true, authorizationInfos[1]
}
func (r *DockerAuthProxy) verifyToken(token string) bool {
	return false
}

func (r *DockerAuthProxy) ParseRepoRequest(req *http.Request) *common.AuthScope {
	var resourceType = ""
	var class = ""
	var repoName = ""
	var actions []string
	if strings.HasPrefix(req.URL.Path, "/v2/_catalog") {
		resourceType = "registry"
		actions = append(actions, "*")
		return &common.AuthScope{
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
	return &common.AuthScope{
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
