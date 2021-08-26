package kubernetes

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	"github.com/shijunLee/docker-proxy-auth/pkg/common"
	policycommon "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/common"
	dockerauthclient "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/kubernetes/client"
	dockerauthv1alpha1 "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/kubernetes/v1alpha1"
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
	return nil, nil
}
func (k *KubernetesPolicy) UpdatePolicy(ctx context.Context, p policycommon.Policy) (policycommon.Policy, error) {
	return nil, nil
}
func (k *KubernetesPolicy) DeletePolicy(ctx context.Context, p policycommon.Policy) error {
	return nil
}
func (k *KubernetesPolicy) ListPolicyForUser(ctx context.Context, username string) ([]policycommon.Policy, error) {
	return nil, nil
}

// use like
func (k *KubernetesPolicy) ListPolicyForRepo(ctx context.Context, repoName string) ([]policycommon.Policy, error) {
	return nil, nil
}

func (k *KubernetesPolicy) AuthorizeUserResourceScope(authRequest *common.AuthRequestInfo) ([]string, error) {
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
