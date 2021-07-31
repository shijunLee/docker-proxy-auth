package dockerauth

import (
	"fmt"

	"net"
	"regexp"

	"net/http"
	"sort"
	"strings"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/log"
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
	ProxyConfig ProxyConfig
}

type ProxyConfig struct {
	RealIPHeader string
	RealIPPos    int
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
