package crd

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type CustomRoleWatcher struct {
	Informer cache.SharedIndexInformer
}

type CustomRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CustomRoleSpec   `json:"spec,omitempty"`
	Status CustomRoleStatus `json:"status,omitempty"`
}

// CustomRoleSpec defines the desired state of CustomRole.
type CustomRoleSpec struct {
	Roles        []RoleSpec        `json:"roles"`
	RoleBindings []RoleBindingSpec `json:"roleBindings"`
}

type RoleSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Name       string       `json:"name"`
	Type       RoleType     `json:"type"`
	Clusters   []string     `json:"clusters,omitempty"`
	Namespaces []string     `json:"namespaces,omitempty"`
	BaseRoles  []string     `json:"baseRoles,omitempty"`
	Rules      []PolicyRule `json:"rules,omitempty"`
}
type PolicyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type RoleType string

const (
	GlobalRole    RoleType = "Global"
	ClusterRole   RoleType = "Cluster"
	NamespaceRole RoleType = "Namespace"
)

type RoleBindingSpec struct {
	Name       string       `json:"name"`
	RoleRef    string       `json:"roleRef"`
	Subjects   []Subject    `json:"subjects"`
	Expiration *metav1.Time `json:"expiration,omitempty"`
}

type Subject struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	APIGroup string `json:"apiGroup,omitempty"`
}

// CustomRoleStatus defines the observed state of CustomRole.
type CustomRoleStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
