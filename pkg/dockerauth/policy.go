package dockerauth

import "github.com/shijunLee/docker-proxy-auth/pkg/common"

type DockerPolicyAuth interface {
	AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error)
}
