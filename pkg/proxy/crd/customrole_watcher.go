package crd

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
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

func NewCustomRoleWatcher() (*CustomRoleWatcher, error) {
	clusterConfig, err := buildConfiguration()
	if err != nil {
		return &CustomRoleWatcher{}, err
	}

	clusterClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return &CustomRoleWatcher{}, err
	}
	crdGVR := schema.GroupVersionResource{
		Group:    "custom-rbac.improwised.com",
		Version:  "v1",
		Resource: "customroles", // Plural name of your CRD
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(clusterClient,
		time.Minute, "", nil)
	informer := factory.ForResource(crdGVR).Informer()

	return &CustomRoleWatcher{
		Informer: informer,
	}, nil
}

func buildConfiguration() (*rest.Config, error) {
	kubeconfig := "/home/husen.kureshi/.kube/config"
	var clusterConfig *rest.Config
	var err error
	if kubeconfig != "" {
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		clusterConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	return clusterConfig, nil
}

func (ctrl *CustomRoleWatcher) AddEventHandler() {
	ctrl.Informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {

		},
		UpdateFunc: func(oldObj, newObj interface{}) {

		},
		DeleteFunc: func(obj interface{}) {
		},
	})
}
