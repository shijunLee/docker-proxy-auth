package policy

import (
	"context"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
)

type DockerPolicyAuth interface {
	AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error)
}

type Policy struct {
	PolicyRepo string
	Username   string
	Operation  string   // start with or eq
	Action     []string // pull or push
	Type       string   // registry(get catalog) or repository
}

type PolicyInterface interface {
	DockerPolicyAuth
	AddPolicy(ctx context.Context, p *Policy) (*Policy, error)
	UpdatePolicy(ctx context.Context, p *Policy) (*Policy, error)
	DeletePolicy(ctx context.Context, p *Policy) error
	ListPolicyForUser(ctx context.Context, username string)
	// use like
	ListPolicyForRepo(ctx context.Context, repoName string)
}

type NoneOpPolicy struct {
}

func (p *NoneOpPolicy) AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error) {
	return []string{"pull", "push", "*"}, nil
}
