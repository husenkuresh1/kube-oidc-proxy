// Copyright Jetstack Ltd. See LICENSE for details.

package crd

import (
	"fmt"

	"github.com/Improwised/kube-oidc-proxy/constants"
	"github.com/Improwised/kube-oidc-proxy/pkg/proxy"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

func (ctrl *CustomRoleWatcher) ConvertUnstructuredToCustomRole(obj interface{}) (*CustomRole, error) {
	u := obj.(*unstructured.Unstructured)
	var customRole CustomRole
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.UnstructuredContent(), &customRole); err != nil {
		return nil, fmt.Errorf("conversion error: %w", err)
	}
	return &customRole, nil
}

func (ctrl *CustomRoleWatcher) ProcessClusterRoles(customRole *CustomRole) {
	for _, roleSpec := range customRole.Spec.Roles {
		targetClusters := determineTargetClusters(roleSpec, ctrl.clusters)
		clusterRole := createClusterRole(roleSpec, customRole.Name)

		applyToClusters(targetClusters, ctrl.clusters, func(c *proxy.ClusterConfig) {
			// Use a map to deduplicate roles by name
			roleMap := make(map[string]*v1.ClusterRole)
			for _, existing := range c.RBACConfig.ClusterRoles {
				roleMap[existing.Name] = existing
			}

			// Add/overwrite with new role
			roleMap[clusterRole.Name] = clusterRole

			// Convert back to slice
			result := make([]*v1.ClusterRole, 0, len(roleMap))
			for _, role := range roleMap {
				result = append(result, role)
			}
			c.RBACConfig.ClusterRoles = result
		})
	}
}

func determineTargetClusters(roleSpec RoleSpec, clusters []*proxy.ClusterConfig) []string {
	if len(roleSpec.Clusters) == 0 {
		return getAllClusterNames(clusters)
	}
	return roleSpec.Clusters
}

func getAllClusterNames(clusters []*proxy.ClusterConfig) []string {
	names := make([]string, 0, len(clusters))
	for _, c := range clusters {
		names = append(names, c.Name)
	}
	return names
}

func createClusterRole(roleSpec RoleSpec, customRoleName string) *v1.ClusterRole {
	return &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: roleSpec.Name,
			Annotations: map[string]string{
				fmt.Sprintf("%s/managed-by", constants.CRDGroup): customRoleName,
			}},
		Rules: convertRules(roleSpec.Rules),
	}
}

func (ctrl *CustomRoleWatcher) ProcessBindings(customRole *CustomRole) {
	for _, rbSpec := range customRole.Spec.RoleBindings {
		roleSpec := findRoleSpec(rbSpec.RoleRef, customRole)
		if roleSpec == nil {
			continue
		}

		targetClusters := determineTargetClusters(*roleSpec, ctrl.clusters)
		subjects := convertSubjects(rbSpec.Subjects)

		if len(roleSpec.Namespaces) > 0 {
			createNamespacedBindings(customRole.Name, *roleSpec, rbSpec, subjects, targetClusters, ctrl.clusters)
		} else {
			createClusterWideBindings(customRole.Name, rbSpec, roleSpec.Name, subjects, targetClusters, ctrl.clusters)
		}
	}
}

func findRoleSpec(roleName string, customRole *CustomRole) *RoleSpec {
	for i, r := range customRole.Spec.Roles {
		if r.Name == roleName {
			return &customRole.Spec.Roles[i]
		}
	}
	klog.Errorf("Role %s not found in CustomRole %s", roleName, customRole.Name)
	return nil
}

func createNamespacedBindings(customRoleName string, roleSpec RoleSpec, rbSpec RoleBindingSpec,
	subjects []v1.Subject, targetClusters []string, clusters []*proxy.ClusterConfig) {

	for _, ns := range roleSpec.Namespaces {
		rb := &v1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbSpec.Name,
				Namespace: ns,
				Annotations: map[string]string{
					fmt.Sprintf("%s/managed-by", constants.CRDGroup): customRoleName,
				},
			},
			RoleRef: v1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     roleSpec.Name,
			},
			Subjects: subjects,
		}

		applyToClusters(targetClusters, clusters, func(c *proxy.ClusterConfig) {
			c.RBACConfig.RoleBindings = append(c.RBACConfig.RoleBindings, rb)
		})
	}
}

func createClusterWideBindings(customRoleName string, rbSpec RoleBindingSpec, roleName string,
	subjects []v1.Subject, targetClusters []string, clusters []*proxy.ClusterConfig) {

	crb := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: rbSpec.Name,
			Annotations: map[string]string{
				fmt.Sprintf("%s/managed-by", constants.CRDGroup): customRoleName,
			}},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: subjects,
	}

	applyToClusters(targetClusters, clusters, func(c *proxy.ClusterConfig) {
		c.RBACConfig.ClusterRoleBindings = append(c.RBACConfig.ClusterRoleBindings, crb)
	})
}

func applyToClusters(targetClusters []string, allClusters []*proxy.ClusterConfig, applyFunc func(*proxy.ClusterConfig)) {
	for _, clusterName := range targetClusters {
		for _, c := range allClusters {
			if c.Name == clusterName {
				applyFunc(c)
				break
			}
		}
	}
}

func convertRules(rules []v1.PolicyRule) []v1.PolicyRule {
	k8sRules := make([]v1.PolicyRule, 0, len(rules))
	for _, r := range rules {
		k8sRules = append(k8sRules, v1.PolicyRule{
			APIGroups: r.APIGroups,
			Resources: r.Resources,
			Verbs:     r.Verbs,
		})
	}
	return k8sRules
}

func convertSubjects(subjects []v1.Subject) []v1.Subject {
	k8sSubjects := make([]v1.Subject, 0, len(subjects))
	for _, s := range subjects {
		k8sSubjects = append(k8sSubjects, v1.Subject{
			Kind:     s.Kind,
			Name:     s.Name,
			APIGroup: s.APIGroup,
		})
	}
	return k8sSubjects
}
