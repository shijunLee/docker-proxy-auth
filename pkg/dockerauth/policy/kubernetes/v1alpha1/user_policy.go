package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type UserPolicySpec struct {
	Policies []PolicyInfo `json:"policies,omitempty"`
}

type PolicyInfo struct {
	RepoName  string   `json:"repoName,omitempty"`
	Operation string   `json:"operation,omitempty"`
	Actions   []string `json:"actions,omitempty"`
	Type      string   `json:"type,omitempty"`
	//+nullable
	Username string `json:"username,omitempty"`
}

type UserPolicyStatus struct {
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespace

// UserPolicy is the Schema for the userpolicy API
type UserPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserPolicySpec   `json:"spec,omitempty"`
	Status UserPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// UserPolicyList contains a list of HelmRepo
type UserPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UserPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&UserPolicy{}, &UserPolicyList{})
}

func (c *PolicyInfo) GetPolicyRepo() string {
	return c.RepoName
}

func (c *PolicyInfo) GetUsername() string {
	return ""
}

func (c *PolicyInfo) GetOperation() string { // start with or eq
	return c.Operation
}

func (c *PolicyInfo) GetAction() []string { // pull or push
	return c.Actions
}
func (c *PolicyInfo) GetType() string { // registry(get catalog) or repository
	return c.Type
}
