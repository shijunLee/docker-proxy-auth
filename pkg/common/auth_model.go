package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
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

type AuthRequestInfo struct {
	Account string              `json:"account"`
	Type    string              `json:"type"`
	Name    string              `json:"name"`
	Service string              `json:"service"`
	IP      net.IP              `json:"ip"`
	Actions []string            `json:"actions"`
	Labels  map[string][]string `json:"-"`
}

func (a *AuthRequestInfo) BuildJsonBody() string {
	data, _ := json.Marshal(a)
	return string(data)
}

func (a *AuthRequestInfo) BuildFormBody() string {
	var values = &url.Values{}
	values.Set("name", a.Name)
	values.Set("type", a.Type)
	values.Set("account", a.Account)
	values.Set("ip", string(a.IP))
	values.Set("service", a.Service)
	for index, action := range a.Actions {
		values.Set(fmt.Sprintf("actions[%d]", index), action)
	}
	return values.Encode()
}

func (a *AuthRequestInfo) BuildQuery() string {
	var values = &url.Values{}
	values.Set("name", a.Name)
	values.Set("type", a.Type)
	values.Set("ip", string(a.IP))
	values.Set("service", a.Service)
	values.Set("account", a.Account)
	for _, action := range a.Actions {
		values.Add("actions", action)
	}
	return values.Encode()
}

type AuthScope struct {
	Type    string
	Class   string
	Name    string
	Actions []string
}

//String convert auth scope to `repository:samalba/my-app:pull,push` the docker auth scope
func (s *AuthScope) String() string {
	actionString := strings.Join(s.Actions, ",")
	return fmt.Sprintf("%s:%s:%s", s.Type, s.Name, actionString)
}

type AuthResult struct {
	Scope            AuthScope
	AutorizedActions []string
}

type DockerUnauthorized struct {
	Errors []DockerUnauthorizedError
}
type DockerUnauthorizedError struct {
	Code    string                          `json:"code"`
	Message string                          `json:"message"`
	Details []DockerUnauthorizedErrorDetail `json:"detail"`
}
type DockerUnauthorizedErrorDetail struct {
	Type   string `json:"Type"`
	Name   string `json:"Name"`
	Action string `json:"Action"`
}

func NewDockerUnauthorized(authScope *AuthScope) *DockerUnauthorized {
	if authScope == nil {
		return &DockerUnauthorized{
			Errors: []DockerUnauthorizedError{
				{
					Code:    "UNAUTHORIZED",
					Message: "access to the requested resource is not authorized",
				},
			},
		}
	}
	var details []DockerUnauthorizedErrorDetail
	for _, action := range authScope.Actions {
		details = append(details, DockerUnauthorizedErrorDetail{
			Type:   authScope.Type,
			Name:   authScope.Name,
			Action: action,
		})
	}
	return &DockerUnauthorized{
		Errors: []DockerUnauthorizedError{
			{
				Code:    "UNAUTHORIZED",
				Message: "access to the requested resource is not authorized",
				Details: details,
			},
		},
	}
}

// Copy-pasted from libtrust where it is private.
func JoseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// joseBase64UrlDecode decodes the given string using the standard base64 url
// decoder but first adds the appropriate number of trailing '=' characters in
// accordance with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func JoseBase64UrlDecode(s string) ([]byte, error) {
	s = strings.Replace(s, "\n", "", -1)
	s = strings.Replace(s, " ", "", -1)
	switch len(s) % 4 {
	case 0:
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, errors.New("illegal base64url string")
	}
	return base64.URLEncoding.DecodeString(s)
}
