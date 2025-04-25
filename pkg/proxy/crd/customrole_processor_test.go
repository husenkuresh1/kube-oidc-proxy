// Copyright Jetstack Ltd. See LICENSE for details.

package crd

import (
	"testing"

	"github.com/Improwised/kube-oidc-proxy/pkg/proxy"
	"github.com/Improwised/kube-oidc-proxy/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProcessClusterRoles(t *testing.T) {
	// Arrange
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{
				{
					Name: "test-cluster-role",
					Rules: []v1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{"get", "list"},
						},
					},
				},
			},
		},
	}

	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1", RBACConfig: &util.RBAC{}},
		{Name: "cluster-2", RBACConfig: &util.RBAC{}},
	}

	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	// Act
	ctrl.ProcessClusterRoles(customRole)

	// Assert
	for _, cluster := range clusters {
		assert.Len(t, cluster.RBACConfig.ClusterRoles, 1)
		assert.Equal(t, "test-cluster-role", cluster.RBACConfig.ClusterRoles[0].Name)
		assert.Equal(t, []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		}, cluster.RBACConfig.ClusterRoles[0].Rules)
	}
}

func TestProcessBindings(t *testing.T) {
	// Arrange
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{
				{
					Name:       "test-role",
					Namespaces: []string{"default"},
				},
			},
			RoleBindings: []RoleBindingSpec{
				{
					Name:    "test-binding",
					RoleRef: "test-role",
					Subjects: []v1.Subject{
						{
							Kind: "User",
							Name: "test-user",
						},
					},
				},
			},
		},
	}

	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1", RBACConfig: &util.RBAC{}},
	}

	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	// Act
	ctrl.ProcessBindings(customRole)

	// Assert
	for _, cluster := range clusters {
		assert.Len(t, cluster.RBACConfig.RoleBindings, 1)
		assert.Equal(t, "test-binding", cluster.RBACConfig.RoleBindings[0].Name)
		assert.Equal(t, "test-role", cluster.RBACConfig.RoleBindings[0].RoleRef.Name)
		assert.Equal(t, []v1.Subject{
			{
				Kind: "User",
				Name: "test-user",
			},
		}, cluster.RBACConfig.RoleBindings[0].Subjects)
	}
}

func TestConvertUnstructuredToCustomRole(t *testing.T) {
	// Arrange
	unstructuredObj := map[string]interface{}{
		"apiVersion": "custom-rbac.improwised.com/v1",
		"kind":       "CustomRole",
		"metadata": map[string]interface{}{
			"name": "test-custom-role",
		},
		"spec": map[string]interface{}{
			"roles": []interface{}{
				map[string]interface{}{
					"name": "test-role",
					"rules": []interface{}{
						map[string]interface{}{
							"apiGroups": []interface{}{""},
							"resources": []interface{}{"pods"},
							"verbs":     []interface{}{"get", "list"},
						},
					},
				},
			},
			"roleBindings": []interface{}{
				map[string]interface{}{
					"name":    "test-binding",
					"roleRef": "test-role",
					"subjects": []interface{}{
						map[string]interface{}{
							"kind": "User",
							"name": "test-user",
						},
					},
				},
			},
		},
	}

	ctrl := &CustomRoleWatcher{}

	// Act
	customRole, err := ctrl.ConvertUnstructuredToCustomRole(&unstructured.Unstructured{Object: unstructuredObj})

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "test-custom-role", customRole.Name)
	assert.Len(t, customRole.Spec.Roles, 1)
	assert.Equal(t, "test-role", customRole.Spec.Roles[0].Name)
	assert.Len(t, customRole.Spec.RoleBindings, 1)
	assert.Equal(t, "test-binding", customRole.Spec.RoleBindings[0].Name)
}

func TestProcessClusterRoles_EmptyCustomRole(t *testing.T) {
	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1", RBACConfig: &util.RBAC{}},
	}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessClusterRoles(&CustomRole{})

	assert.Empty(t, clusters[0].RBACConfig.ClusterRoles)
}

func TestProcessBindings_InvalidRoleReference(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			RoleBindings: []RoleBindingSpec{{
				Name:    "invalid-ref",
				RoleRef: "nonexistent-role",
			}},
		},
	}
	clusters := []*proxy.ClusterConfig{{Name: "cluster-1", RBACConfig: &util.RBAC{}}}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessBindings(customRole)

	assert.Empty(t, clusters[0].RBACConfig.RoleBindings)
	assert.Empty(t, clusters[0].RBACConfig.ClusterRoleBindings)
}

func TestProcessClusterRoles_EmptyRules(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{{Name: "empty-rules"}},
		},
	}
	clusters := []*proxy.ClusterConfig{{Name: "cluster-1", RBACConfig: &util.RBAC{}}}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessClusterRoles(customRole)

	assert.Empty(t, clusters[0].RBACConfig.ClusterRoles[0].Rules)
}

func TestProcessBindings_EmptySubjects(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{{Name: "test-role"}},
			RoleBindings: []RoleBindingSpec{{
				Name:    "empty-subjects",
				RoleRef: "test-role",
			}},
		},
	}
	clusters := []*proxy.ClusterConfig{{Name: "cluster-1", RBACConfig: &util.RBAC{}}}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessBindings(customRole)

	assert.Len(t, clusters[0].RBACConfig.ClusterRoleBindings, 1)
	assert.Empty(t, clusters[0].RBACConfig.ClusterRoleBindings[0].Subjects)
}

func TestProcessBindings_MultipleNamespaces(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{{
				Name:       "multi-ns",
				Namespaces: []string{"ns1", "ns2"},
			}},
			RoleBindings: []RoleBindingSpec{{
				Name:    "multi-binding",
				RoleRef: "multi-ns",
			}},
		},
	}
	clusters := []*proxy.ClusterConfig{{Name: "cluster-1", RBACConfig: &util.RBAC{}}}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessBindings(customRole)

	assert.Len(t, clusters[0].RBACConfig.RoleBindings, 2)
	assert.ElementsMatch(t, []string{"ns1", "ns2"}, []string{
		clusters[0].RBACConfig.RoleBindings[0].Namespace,
		clusters[0].RBACConfig.RoleBindings[1].Namespace,
	})
}

func TestProcessClusterRoles_MultipleClusters(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{{
				Name:     "multi-cluster",
				Clusters: []string{"cluster-1", "cluster-2"},
			}},
		},
	}
	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1", RBACConfig: &util.RBAC{}},
		{Name: "cluster-2", RBACConfig: &util.RBAC{}},
		{Name: "cluster-3", RBACConfig: &util.RBAC{}},
	}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessClusterRoles(customRole)

	assert.Len(t, clusters[0].RBACConfig.ClusterRoles, 1)
	assert.Len(t, clusters[1].RBACConfig.ClusterRoles, 1)
	assert.Empty(t, clusters[2].RBACConfig.ClusterRoles)
}

func TestConvertUnstructuredToCustomRole_InvalidData(t *testing.T) {
	invalidObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"roles": "not-a-slice",
			},
		},
	}
	ctrl := &CustomRoleWatcher{}

	_, err := ctrl.ConvertUnstructuredToCustomRole(invalidObj)

	assert.Error(t, err)
}

func TestConvertSubjects_ServiceAccountValidation(t *testing.T) {
	subjects := []v1.Subject{
		{Kind: "ServiceAccount", Name: "default"},
		{Kind: "User", Name: "test-user"},
	}

	result := convertSubjects(subjects)

	assert.Len(t, result, 2)
	assert.Equal(t, "ServiceAccount", result[0].Kind)
	assert.Equal(t, "User", result[1].Kind)
}

func TestDetermineTargetClusters_DefaultAllClusters(t *testing.T) {
	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1"},
		{Name: "cluster-2"},
	}
	roleSpec := RoleSpec{Clusters: []string{}}

	result := determineTargetClusters(roleSpec, clusters)

	assert.ElementsMatch(t, []string{"cluster-1", "cluster-2"}, result)
}

func TestCreateClusterWideBindings_CrossCluster(t *testing.T) {
	customRole := &CustomRole{
		Spec: CustomRoleSpec{
			Roles: []RoleSpec{{
				Name:     "cross-cluster",
				Clusters: []string{"cluster-1", "cluster-2"},
			}},
			RoleBindings: []RoleBindingSpec{{
				Name:    "cross-binding",
				RoleRef: "cross-cluster",
			}},
		},
	}
	clusters := []*proxy.ClusterConfig{
		{Name: "cluster-1", RBACConfig: &util.RBAC{}},
		{Name: "cluster-2", RBACConfig: &util.RBAC{}},
	}
	ctrl := &CustomRoleWatcher{
		clusters: clusters,
	}

	ctrl.ProcessClusterRoles(customRole)
	ctrl.ProcessBindings(customRole)

	for _, c := range clusters {
		require.Len(t, c.RBACConfig.ClusterRoleBindings, 1)
		assert.Equal(t, "cross-binding", c.RBACConfig.ClusterRoleBindings[0].Name)
	}
}
