// Copyright Jetstack Ltd. See LICENSE for details.

package crd

import (
	"fmt"
	"os"
	"time"

	"github.com/Improwised/kube-oidc-proxy/constants"
	"github.com/Improwised/kube-oidc-proxy/pkg/proxy"
	"github.com/Improwised/kube-oidc-proxy/pkg/util"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type CustomRoleWatcher struct {
	Informer cache.SharedIndexInformer
	clusters []*proxy.ClusterConfig
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

// NewCustomRoleWatcher initializes a watcher with clusters and event handlers.
func NewCustomRoleWatcher(clusters []*proxy.ClusterConfig) (*CustomRoleWatcher, error) {
	clusterConfig, err := buildConfiguration()
	if err != nil {
		return &CustomRoleWatcher{}, err
	}

	clusterClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return &CustomRoleWatcher{}, err
	}
	crdGVR := schema.GroupVersionResource{
		Group:    constants.CRDGroup,
		Version:  constants.CRDVersion,
		Resource: constants.CRDResource,
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(clusterClient,
		time.Minute, "", nil)
	informer := factory.ForResource(crdGVR).Informer()

	watcher := &CustomRoleWatcher{
		Informer: informer,
		clusters: clusters,
	}
	watcher.AddEventHandler()
	return watcher, nil
}

func buildConfiguration() (*rest.Config, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
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

// AddEventHandler attaches Add/Update/Delete handlers.
func (ctrl *CustomRoleWatcher) AddEventHandler() {
	ctrl.Informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ctrl.onAdd,
		UpdateFunc: ctrl.onUpdate,
		DeleteFunc: ctrl.onDelete,
	})
}

// onAdd handles creation of CustomRole resources.
func (ctrl *CustomRoleWatcher) onAdd(obj interface{}) {
	customRole, err := ctrl.ConvertUnstructuredToCustomRole(obj)
	if err != nil {
		klog.Errorf("Failed to convert unstructured object to CustomRole: %v", err)
	}
	ctrl.ProcessClusterRoles(customRole)
	ctrl.ProcessBindings(customRole)
	ctrl.RebuildAllAuthorizers()

	klog.Infof("CustomRole added: %v", obj)

}

// onDelete handles deletion of CustomRole resources.
func (ctrl *CustomRoleWatcher) onDelete(obj interface{}) {
	// Handle deletion
	var customRole *CustomRole
	var err error

	// Handle DeletedFinalStateUnknown case
	if deleted, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = deleted.Obj
	}

	customRole, err = ctrl.ConvertUnstructuredToCustomRole(obj)
	if err != nil {
		klog.Errorf("Failed to convert deleted object to CustomRole: %v", err)
		return
	}

	// Remove all RBAC resources created by this CustomRole
	for _, cluster := range ctrl.clusters {
		// Filter ClusterRoles
		filteredCRs := make([]*v1.ClusterRole, 0)
		for _, cr := range cluster.RBACConfig.ClusterRoles {
			if cr.Annotations[fmt.Sprintf("%s/managed-by", constants.CRDGroup)] != customRole.Name {
				filteredCRs = append(filteredCRs, cr)
			}
		}
		cluster.RBACConfig.ClusterRoles = filteredCRs

		// Filter RoleBindings
		filteredRBs := make([]*v1.RoleBinding, 0)
		for _, rb := range cluster.RBACConfig.RoleBindings {
			if rb.Annotations[fmt.Sprintf("%s/managed-by", constants.CRDGroup)] != customRole.Name {
				filteredRBs = append(filteredRBs, rb)
			}
		}
		cluster.RBACConfig.RoleBindings = filteredRBs

		// Filter ClusterRoleBindings
		filteredCRBs := make([]*v1.ClusterRoleBinding, 0)
		for _, crb := range cluster.RBACConfig.ClusterRoleBindings {
			if crb.Annotations[fmt.Sprintf("%s/managed-by", constants.CRDGroup)] != customRole.Name {
				filteredCRBs = append(filteredCRBs, crb)
			}
		}
		cluster.RBACConfig.ClusterRoleBindings = filteredCRBs
	}

	ctrl.RebuildAllAuthorizers()

	klog.Infof("CustomRole deleted: %v", obj)

}

// onUpdate handles updates to CustomRole resources.
func (ctrl *CustomRoleWatcher) onUpdate(oldObj, newObj interface{}) {
	oldCustomRole, err := ctrl.ConvertUnstructuredToCustomRole(oldObj)
	if err != nil {
		klog.Errorf("Failed to convert old object to CustomRole: %v", err)
		return
	}
	newCustomRole, err := ctrl.ConvertUnstructuredToCustomRole(newObj)
	if err != nil {
		klog.Errorf("Failed to convert new object to CustomRole: %v", err)
		return
	}

	if oldCustomRole.ResourceVersion == newCustomRole.ResourceVersion {
		klog.V(5).Infof("ResourceVersion is the same, skipping update")
		return
	}

	// Trigger deletion of old RBAC resources
	ctrl.onDelete(oldObj)

	// Trigger creation of new RBAC resources
	ctrl.onAdd(newObj)

	klog.Infof("CustomRole updated form %v to %v", oldObj, newObj)

}

// rebuildAllAuthorizers updates RBAC authorizers for all clusters.
func (ctrl *CustomRoleWatcher) RebuildAllAuthorizers() {
	for _, c := range ctrl.clusters {
		_, staticRoles := rbacvalidation.NewTestRuleResolver(
			c.RBACConfig.Roles,
			c.RBACConfig.RoleBindings,
			c.RBACConfig.ClusterRoles,
			c.RBACConfig.ClusterRoleBindings,
		)
		klog.V(5).Infof("Rebuilding authorizer for cluster: %s", c.Name)
		c.Authorizer = util.NewAuthorizer(staticRoles)
	}
}
