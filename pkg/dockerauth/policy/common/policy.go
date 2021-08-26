package common

import (
	"context"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
)

type DockerPolicyAuth interface {
	AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error)
}

type Policy interface {
	GetPolicyRepo() string
	GetUsername() string
	GetOperation() string // start with or eq
	GetAction() []string  // pull or push
	GetType() string      // registry(get catalog) or repository
}

type PolicyInterface interface {
	DockerPolicyAuth
	AddPolicy(ctx context.Context, p Policy) (Policy, error)
	UpdatePolicy(ctx context.Context, p Policy) (Policy, error)
	DeletePolicy(ctx context.Context, p Policy) error
	ListPolicyForUser(ctx context.Context, username string) ([]Policy, error)
	// use like
	ListPolicyForRepo(ctx context.Context, repoName string) ([]Policy, error)
}

type NoneOpPolicy struct {
}

func (p *NoneOpPolicy) AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error) {
	return []string{"pull", "push", "*"}, nil
}
