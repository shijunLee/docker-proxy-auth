package common

import "net"

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
