package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	policycommon "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/common"
	dockerauthclient "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/kubernetes/client"
	dockerauthv1alpha1 "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/kubernetes/v1alpha1"
	"github.com/shijunLee/docker-proxy-auth/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	currentNamespacePath string = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var _ policycommon.DockerPolicyAuth = &KubernetesPolicy{}
var _ policycommon.PolicyInterface = &KubernetesPolicy{}

// support kubernetes api

type KubernetesPolicy struct {
	userPolicyClient *dockerauthclient.UserPolicyClient
	store            cache.Store
}

func NewKubernetesPolicy() *KubernetesPolicy {

	utilruntime.Must(clientgoscheme.AddToScheme(dockerauthv1alpha1.Scheme))

	utilruntime.Must(dockerauthv1alpha1.AddToScheme(dockerauthv1alpha1.Scheme))
	var kubernetesPolicy = &KubernetesPolicy{}
	currentNamespace := getCurrentNameSpace()
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	var client = dockerauthclient.NewUserPolicyClientWithRestConfig(currentNamespace, config)
	kubernetesPolicy.userPolicyClient = client
	return kubernetesPolicy
}

func (k *KubernetesPolicy) Init(ctx context.Context) {

	var listFunc = func(options metav1.ListOptions) (runtime.Object, error) {
		return k.userPolicyClient.List(ctx, options)
	}
	var watchFunc = func(options metav1.ListOptions) (watch.Interface, error) {
		return k.userPolicyClient.Watch(ctx, options)
	}
	store, controller := cache.NewInformer(&cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc},
		&dockerauthv1alpha1.UserPolicy{},
		time.Second*0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {

			},
			DeleteFunc: func(obj interface{}) {

			},
			UpdateFunc: func(oldObj, newObj interface{}) {

			},
		})
	k.store = store
	go controller.Run(ctx.Done())
	<-ctx.Done()
}

func (k *KubernetesPolicy) AddPolicy(ctx context.Context, p policycommon.Policy) (policycommon.Policy, error) {
	var cacheObject = &dockerauthv1alpha1.UserPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.GetUsername(),
			Namespace: getCurrentNameSpace(),
		},
	}
	var isExist = false
	key, err := cache.MetaNamespaceKeyFunc(cacheObject)
	if err == nil {
		var cacheItem interface{}
		cacheItem, isExist, err = k.store.GetByKey(key)
		if err == nil && isExist {
			cacheObject = cacheItem.(*dockerauthv1alpha1.UserPolicy)
		}
	}

	//TODO add log for this

	var policies []dockerauthv1alpha1.PolicyInfo
	var policy = dockerauthv1alpha1.PolicyInfo{
		RepoName:  p.GetPolicyRepo(),
		Operation: p.GetOperation(),
		Actions:   p.GetAction(),
		Type:      p.GetType(),
	}
	policies = append(policies, policy)
	if isExist {
		cacheObject.Spec.Policies = append(cacheObject.Spec.Policies, policies...)
		_, err := k.userPolicyClient.Update(ctx, cacheObject, metav1.UpdateOptions{})
		return p, err
	} else {
		kUserPolicy := &dockerauthv1alpha1.UserPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.GetUsername(),
			}, Spec: dockerauthv1alpha1.UserPolicySpec{
				Policies: policies,
			},
		}
		_, err = k.userPolicyClient.Create(ctx, kUserPolicy, metav1.CreateOptions{})
		return p, err
	}

}
func (k *KubernetesPolicy) UpdatePolicy(ctx context.Context, p policycommon.Policy) (policycommon.Policy, error) {
	var cacheObject = &dockerauthv1alpha1.UserPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.GetUsername(),
			Namespace: getCurrentNameSpace(),
		},
	}
	var isExist = false
	key, err := cache.MetaNamespaceKeyFunc(cacheObject)
	if err == nil {
		var cacheItem interface{}
		cacheItem, isExist, err = k.store.GetByKey(key)
		if err == nil && isExist {
			cacheObject = cacheItem.(*dockerauthv1alpha1.UserPolicy)
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
	if !isExist {
		return nil, fmt.Errorf("policy for user %s repo %s not found", p.GetUsername(), p.GetPolicyRepo())
	}
	var repoObjects []dockerauthv1alpha1.PolicyInfo
	var policiesInfos = cacheObject.Spec.Policies
	for _, item := range policiesInfos {
		if item.RepoName == p.GetPolicyRepo() && item.Type == p.GetType() {
			item.Actions = p.GetAction()
			item.Operation = p.GetOperation()
		}
		repoObjects = append(repoObjects, item)
	}
	cacheObject.Spec.Policies = repoObjects
	_, err = k.userPolicyClient.Update(ctx, cacheObject, metav1.UpdateOptions{})
	return p, err
}

func (k *KubernetesPolicy) DeletePolicy(ctx context.Context, p policycommon.Policy) error {
	var cacheObject = &dockerauthv1alpha1.UserPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.GetUsername(),
			Namespace: getCurrentNameSpace(),
		},
	}
	var isExist = false
	key, err := cache.MetaNamespaceKeyFunc(cacheObject)
	if err == nil {
		var cacheItem interface{}
		cacheItem, isExist, err = k.store.GetByKey(key)
		if err == nil && isExist {
			cacheObject = cacheItem.(*dockerauthv1alpha1.UserPolicy)
		} else {
			return err
		}
	} else {
		return err
	}
	if !isExist {
		return nil
	}
	var repoObjects []dockerauthv1alpha1.PolicyInfo
	var policiesInfos = cacheObject.Spec.Policies
	for _, item := range policiesInfos {
		if item.RepoName != p.GetPolicyRepo() || item.Type != p.GetType() {
			repoObjects = append(repoObjects, item)
		}
	}
	cacheObject.Spec.Policies = repoObjects
	_, err = k.userPolicyClient.Update(ctx, cacheObject, metav1.UpdateOptions{})
	return err
}

func (k *KubernetesPolicy) ListPolicyForUser(ctx context.Context, username string) ([]policycommon.Policy, error) {
	var cacheObject = &dockerauthv1alpha1.UserPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      username,
			Namespace: getCurrentNameSpace(),
		},
	}
	var isExist = false
	key, err := cache.MetaNamespaceKeyFunc(cacheObject)
	if err == nil {
		var cacheItem interface{}
		cacheItem, isExist, err = k.store.GetByKey(key)
		if err == nil && isExist {
			cacheObject = cacheItem.(*dockerauthv1alpha1.UserPolicy)
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
	if !isExist {
		return nil, nil
	}
	kubeDockerPolicyList := cacheObject.Spec.Policies
	var result []policycommon.Policy
	for _, item := range kubeDockerPolicyList {
		item.Username = username
		result = append(result, &item)
	}
	return result, nil
}

// use like
func (k *KubernetesPolicy) ListPolicyForRepo(ctx context.Context, repoName string) ([]policycommon.Policy, error) {
	return nil, nil
}

func (k *KubernetesPolicy) AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error) {
	var cacheObject = &dockerauthv1alpha1.UserPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      authRequest.Account,
			Namespace: getCurrentNameSpace(),
		},
	}
	var isExist = false
	key, err := cache.MetaNamespaceKeyFunc(cacheObject)
	if err == nil {
		var cacheItem interface{}
		cacheItem, isExist, err = k.store.GetByKey(key)
		if err == nil && isExist {
			cacheObject = cacheItem.(*dockerauthv1alpha1.UserPolicy)
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
	if !isExist {
		return nil, nil
	}
	var policies = cacheObject.Spec.Policies
	for _, item := range policies {
		//TODO add operation logic
		if item.Type == authRequest.Type &&
			item.RepoName == authRequest.Name &&
			utils.IsStringSubSlice(item.Actions, authRequest.Actions) {
			return item.Actions, nil
		}

		if strings.ToLower(item.Operation) == "like" ||
			strings.HasSuffix(item.RepoName, "*") {
			repoName := strings.TrimSuffix(item.RepoName, "*")
			repoName = fmt.Sprintf("%s/", repoName)
			if item.Type == authRequest.Type &&
				strings.HasPrefix(authRequest.Name, repoName) &&
				utils.IsStringSubSlice(item.Actions, authRequest.Actions) {

				return item.Actions, nil
			}
		}
	}
	return nil, nil
}

func getCurrentNameSpace() string {
	currentNameSpace := os.Getenv("CURRENT_NAMESPEACE")
	if currentNameSpace != "" {
		return currentNameSpace
	} else {
		_, err := os.Stat(currentNamespacePath)
		if err != nil {
			return currentNameSpace
		} else {
			data, err := ioutil.ReadFile(currentNamespacePath)
			if err != nil {
				return currentNameSpace
			} else {
				return string(data)
			}
		}
	}
}
