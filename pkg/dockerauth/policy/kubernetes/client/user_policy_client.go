package client

import (
	"context"
	"time"

	dockerauthv1alpha1 "github.com/shijunLee/docker-proxy-auth/pkg/dockerauth/policy/kubernetes/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

const resourceName = "userpolicies"

type UserPolicyClient struct {
	client *rest.RESTClient
	ns     string
}

func NewUserPolicyClient(namespace string, client *rest.RESTClient) *UserPolicyClient {
	userPolicyClient := &UserPolicyClient{
		client: client,
		ns:     namespace,
	}
	return userPolicyClient
}

func NewUserPolicyClientWithRestConfig(namespace string, restConfig *rest.Config) *UserPolicyClient {
	userPolicyClient := &UserPolicyClient{
		ns: namespace,
	}
	setConfigDefaults(restConfig)
	client, err := rest.RESTClientFor(restConfig)
	if err != nil {
		panic(err)
	}
	userPolicyClient.client = client
	return userPolicyClient
}

func setConfigDefaults(config *rest.Config) {
	gv := dockerauthv1alpha1.GroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.NewCodecFactory(dockerauthv1alpha1.Scheme)
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
}

// Get takes name of the userPolicy, and returns the corresponding userPolicy object, and an error if there is any.
func (c *UserPolicyClient) Get(ctx context.Context, name string, options metav1.GetOptions) (result *dockerauthv1alpha1.UserPolicy, err error) {
	result = &dockerauthv1alpha1.UserPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource(resourceName).
		Name(name).
		VersionedParams(&options, dockerauthv1alpha1.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of userPolicys that match those selectors.
func (c *UserPolicyClient) List(ctx context.Context, opts metav1.ListOptions) (result *dockerauthv1alpha1.UserPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &dockerauthv1alpha1.UserPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource(resourceName).
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested userPolicys.
func (c *UserPolicyClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource(resourceName).
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a userPolicy and creates it.  Returns the server's representation of the userPolicy, and an error, if there is any.
func (c *UserPolicyClient) Create(ctx context.Context, userPolicy *dockerauthv1alpha1.UserPolicy, opts metav1.CreateOptions) (result *dockerauthv1alpha1.UserPolicy, err error) {
	result = &dockerauthv1alpha1.UserPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource(resourceName).
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Body(userPolicy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a userPolicy and updates it. Returns the server's representation of the userPolicy, and an error, if there is any.
func (c *UserPolicyClient) Update(ctx context.Context, userPolicy *dockerauthv1alpha1.UserPolicy, opts metav1.UpdateOptions) (result *dockerauthv1alpha1.UserPolicy, err error) {
	result = &dockerauthv1alpha1.UserPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource(resourceName).
		Name(userPolicy.Name).
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Body(userPolicy).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *UserPolicyClient) UpdateStatus(ctx context.Context, userPolicy *dockerauthv1alpha1.UserPolicy, opts metav1.UpdateOptions) (result *dockerauthv1alpha1.UserPolicy, err error) {
	result = &dockerauthv1alpha1.UserPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource(resourceName).
		Name(userPolicy.Name).
		SubResource("status").
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Body(userPolicy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the userPolicy and deletes it. Returns an error if one occurs.
func (c *UserPolicyClient) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource(resourceName).
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *UserPolicyClient) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource(resourceName).
		VersionedParams(&listOpts, dockerauthv1alpha1.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched userPolicy.
func (c *UserPolicyClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *dockerauthv1alpha1.UserPolicy, err error) {
	result = &dockerauthv1alpha1.UserPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource(resourceName).
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, dockerauthv1alpha1.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
// 	optionsModifier(&options)
// 	return c.client.Get().
// 		Namespace(c.Namespace).
// 		Resource(c.resourceName).
// 		VersionedParams(&options, tpaasv1scheme.ParameterCodec).
// 		Do(context.TODO()).
// 		Get()
// }
// watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
// 	options.Watch = true
// 	optionsModifier(&options)
// 	return c.client.Get().
// 		Namespace(c.Namespace).
// 		Resource(c.resourceName).
// 		VersionedParams(&options, tpaasv1scheme.ParameterCodec).
// 		Watch(context.TODO())
// }
