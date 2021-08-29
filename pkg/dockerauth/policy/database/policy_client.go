package database

import (
	"context"
	"fmt"
	"strings"

	dockerauthcommon "github.com/shijunLee/docker-proxy-auth/pkg/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/common"
	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
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

func (c *UserPolicyClient) GetPolicy(ctx context.Context, p common.Policy) (*Policy, error) {
	var policyList = []Policy{}
	err := c.rdbClient.db.Model(&Policy{}).Where("username = ? AND repoName = ? AND type = ?", p.GetUsername(), p.GetPolicyRepo(), p.GetType()).Find(&policyList).Error
	if err != nil {
		return nil, err
	}
	if len(policyList) > 1 {
		return nil, fmt.Errorf("has more then one policy")
	}
	if len(policyList) == 0 {
		return nil, nil
	}
	return &policyList[0], nil
}

func (c *UserPolicyClient) AddPolicy(ctx context.Context, p common.Policy) (common.Policy, error) {
	policyItems, err := c.GetPolicy(ctx, p)
	if err != nil {
		return nil, err
	}
	if policyItems != nil {
		return nil, fmt.Errorf("policy is exist,please update it")
	}
	var actions = p.GetAction()
	actionString := strings.Join(actions, ",")
	var policy = &Policy{
		Username:  p.GetUsername(),
		RepoName:  p.GetPolicyRepo(),
		Operation: p.GetOperation(),
		Actions:   actionString,
		Type:      p.GetType(),
	}
	err = c.rdbClient.db.Model(policy).Create(policy).Error
	if err != nil {
		return nil, err
	}
	return policy, nil
}
func (c *UserPolicyClient) UpdatePolicy(ctx context.Context, p common.Policy) (common.Policy, error) {

	policyItem, err := c.GetPolicy(ctx, p)
	if err != nil {
		return nil, err
	}
	if policyItem == nil {
		return nil, fmt.Errorf("policy is not exist,please add it")
	}
	policyItem.Operation = p.GetOperation()
	policyItem.Actions = strings.Join(p.GetAction(), ",")
	err = c.rdbClient.db.Model(policyItem).Updates(&policyItem).Error
	if err != nil {
		return nil, err
	}
	return policyItem, nil
}
func (c *UserPolicyClient) DeletePolicy(ctx context.Context, p common.Policy) error {
	policyItem, err := c.GetPolicy(ctx, p)
	if err != nil {
		return err
	}
	if policyItem == nil {
		return fmt.Errorf("policy is not exist,please add it")
	}
	return c.rdbClient.db.Model(&Policy{}).Delete(policyItem).Error
}
func (c *UserPolicyClient) ListPolicyForUser(ctx context.Context, username string) ([]common.Policy, error) {
	var policyList = []Policy{}
	err := c.rdbClient.db.Model(&Policy{}).Where("username = ?", username).Find(&policyList).Error
	if err != nil {
		return nil, err
	}
	var result []common.Policy
	for _, item := range policyList {
		result = append(result, &item)
	}
	return result, nil
}

// use like
func (c *UserPolicyClient) ListPolicyForRepo(ctx context.Context, repoName string) ([]common.Policy, error) {
	return nil, nil
}

func (c *UserPolicyClient) AuthorizeUserResourceScope(authRequest *dockerauthcommon.AuthRequestInfo) ([]string, error) {
	var policyList = []Policy{}
	err := c.rdbClient.db.Model(&Policy{}).Where("username = ?", authRequest.Account).Find(&policyList).Error
	if err != nil {
		return nil, err
	}
	for _, item := range policyList {
		var actions = strings.Split(item.Actions, ",")
		//TODO add operation logic
		if item.Type == authRequest.Type &&
			item.RepoName == authRequest.Name &&
			utils.IsStringSubSlice(actions, authRequest.Actions) {
			return actions, nil
		}

		if strings.ToLower(item.Operation) == "like" ||
			strings.HasSuffix(item.RepoName, "*") {
			repoName := strings.TrimSuffix(item.RepoName, "*")
			repoName = fmt.Sprintf("%s/", repoName)
			if item.Type == authRequest.Type &&
				strings.HasPrefix(authRequest.Name, repoName) &&
				utils.IsStringSubSlice(actions, authRequest.Actions) {

				return actions, nil
			}
		}
	}
	return nil, nil
}
