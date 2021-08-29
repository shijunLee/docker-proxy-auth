package database

import (
	"context"

	"github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/common"
)

var globalUserPolicyClient *UserPolicyClient

type UserPolicyClient struct {
	DBUsername string
	DBPassword string
	DBName     string
	DBType     string
	DBHost     string
	DBPort     int
	OtherDSN   string
	rdbClient  *RDBClient
}

func NewUserPolicyClient(dbType, host, username, password, dbName, otherDSN string, port int) *UserPolicyClient {
	if globalUserPolicyClient != nil {
		return globalUserPolicyClient
	}
	var userPolicyClient = &UserPolicyClient{
		DBType:     dbType,
		DBUsername: username,
		DBPassword: password,
		DBName:     dbName,
		DBHost:     host,
		DBPort:     port,
		OtherDSN:   otherDSN,
	}
	userPolicyClient.rdbClient = NewRDBClient(dbType, host, username, password, dbName, port, true)
	globalUserPolicyClient = userPolicyClient
	return userPolicyClient
}

func (c *UserPolicyClient) AddPolicy(ctx context.Context, p common.Policy) (common.Policy, error) {
	return nil, nil
}
func (c *UserPolicyClient) UpdatePolicy(ctx context.Context, p common.Policy) (common.Policy, error) {
	return nil, nil
}
func (c *UserPolicyClient) DeletePolicy(ctx context.Context, p common.Policy) error {
	return nil
}
func (c *UserPolicyClient) ListPolicyForUser(ctx context.Context, username string) ([]common.Policy, error) {
	return nil, nil
}

// use like
func (c *UserPolicyClient) ListPolicyForRepo(ctx context.Context, repoName string) ([]common.Policy, error) {
	return nil, nil
}
