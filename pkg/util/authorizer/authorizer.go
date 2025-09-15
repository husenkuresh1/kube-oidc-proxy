package authorizer

import (
	"fmt"

	"github.com/Improwised/kube-oidc-proxy/pkg/util"
	v1 "k8s.io/api/rbac/v1"
)

type RBACAuthorizer struct {
	trie *PermissionTrie
}

func NewRBACAuthorizer() *RBACAuthorizer {
	trie := NewPermissionTrie()
	return &RBACAuthorizer{
		trie: trie,
	}
}

// UpdatePermissionTrie updates the permission trie with the RBAC configuration for a cluster
func (a *RBACAuthorizer) UpdatePermissionTrie(rbacConfig *util.RBAC, clusterName string) {
	// Process Roles and RoleBindings
	fmt.Println("called")
	fmt.Println(rbacConfig)
	for _, role := range rbacConfig.Roles {
		// Get all subjects bound to this role
		subjects := getSubjectsForRole(role, rbacConfig.RoleBindings)
		for _, subject := range subjects {
			subjectType := SubjectType(subject.Kind)
			for _, rule := range role.Rules {
				for _, verb := range rule.Verbs {
					for _, resource := range rule.Resources {
						a.trie.AddPermission(
							subjectType,
							subject.Name,
							clusterName,
							role.Namespace,
							resource,
							verb,
						)
					}
				}
			}
		}
	}

	// Process ClusterRoles and ClusterRoleBindings
	for _, clusterRole := range rbacConfig.ClusterRoles {
		// Get all subjects bound to this cluster role
		subjects := getSubjectsForClusterRole(clusterRole, rbacConfig.ClusterRoleBindings)
		for _, subject := range subjects {
			subjectType := SubjectType(subject.Kind)
			for _, rule := range clusterRole.Rules {
				for _, verb := range rule.Verbs {
					for _, resource := range rule.Resources {
						a.trie.AddPermission(
							subjectType,
							subject.Name,
							clusterName,
							"", // cluster-wide namespace
							resource,
							verb,
						)
					}
				}
			}
		}
	}
}

// RemoveClusterPermissions removes all permissions for a cluster
func (a *RBACAuthorizer) RemoveClusterPermissions(cluster string) {
	for subjectKey, subjectNode := range a.trie.subjectNodes {
		if _, exists := subjectNode.clusterNodes[cluster]; exists {
			delete(subjectNode.clusterNodes, cluster)

			// Remove subject if no clusters left
			if len(subjectNode.clusterNodes) == 0 {
				delete(a.trie.subjectNodes, subjectKey)

			}
		}
	}
}

// Helper to get subjects for a role
func getSubjectsForRole(role *v1.Role, bindings []*v1.RoleBinding) []v1.Subject {
	var subjects []v1.Subject
	for _, binding := range bindings {
		if binding.RoleRef.Name == role.Name && binding.RoleRef.Kind == "Role" {
			subjects = append(subjects, binding.Subjects...)
		}
	}
	return subjects
}

// Helper to get subjects for a cluster role
func getSubjectsForClusterRole(clusterRole *v1.ClusterRole, bindings []*v1.ClusterRoleBinding) []v1.Subject {
	var subjects []v1.Subject
	for _, binding := range bindings {
		if binding.RoleRef.Name == clusterRole.Name && binding.RoleRef.Kind == "ClusterRole" {
			subjects = append(subjects, binding.Subjects...)
		}
	}
	return subjects
}

// CheckPermission checks if a subject has permission to perform an action on a resource
func (a *RBACAuthorizer) CheckPermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) bool {

	subjectKey := getSubjectKey(subjectType, subjectName)
	subjectNode, exists := a.trie.subjectNodes[subjectKey]
	if !exists {
		return false
	}

	clusterNode, exists := subjectNode.clusterNodes[cluster]
	if !exists {
		return false
	}

	var namespaceNode *NamespaceNode
	var resourceNode *ResourceNode

	namespaceNode, exists = clusterNode.namespaceNodes[""]
	if !exists {
		namespaceNode, exists = clusterNode.namespaceNodes[namespace]
	}
	if !exists {
		return false
	}

	resourceNode, exists = namespaceNode.resourceNodes["*"]
	if !exists {
		resourceNode, exists = namespaceNode.resourceNodes[resource]
	}
	if !exists {
		return false
	}

	if resourceNode.verbs["*"] || resourceNode.verbs[verb] {
		return true
	}

	return false
}
