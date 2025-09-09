package authorizer

import (
	"sync"

	"github.com/Improwised/kube-oidc-proxy/pkg/util"
	v1 "k8s.io/api/rbac/v1"
)

type RBACAuthorizer struct {
	trie *PermissionTrie
	mu   sync.RWMutex
}

func NewRBACAuthorizer() *RBACAuthorizer {
	return &RBACAuthorizer{
		trie: NewPermissionTrie(),
	}
}

func (a *RBACAuthorizer) UpdatePermissionTrie(rbacConfig *util.RBAC, clusterName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear existing permissions for this cluster
	a.trie.RemoveCluster(clusterName)

	// Process Roles and their bindings
	for _, role := range rbacConfig.Roles {
		subjects := getBoundSubjects(role.Name, "Role", rbacConfig.RoleBindings, role.Namespace)
		a.processRules(role.Rules, subjects, clusterName, role.Namespace)
	}

	// Process ClusterRoles and their bindings
	for _, clusterRole := range rbacConfig.ClusterRoles {
		subjects := getBoundSubjects(clusterRole.Name, "ClusterRole", rbacConfig.ClusterRoleBindings, "")
		a.processRules(clusterRole.Rules, subjects, clusterName, "")
	}
}

func (a *RBACAuthorizer) processRules(rules []v1.PolicyRule, subjects []v1.Subject, clusterName, namespace string) {
	for _, subject := range subjects {
		subjectType := toSubjectType(subject.Kind)
		for _, rule := range rules {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					a.trie.AddPermission(
						subjectType,
						subject.Name,
						clusterName,
						namespace,
						resource,
						verb,
					)
				}
			}
		}
	}
}

func (a *RBACAuthorizer) RemoveClusterPermissions(clusterName string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trie.RemoveCluster(clusterName)
}

func (a *RBACAuthorizer) CheckPermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.trie.CheckPermission(subjectType, subjectName, cluster, namespace, resource, verb)
}

func getBoundSubjects(roleName, roleKind string, bindings interface{}, namespace string) []v1.Subject {
	var subjects []v1.Subject
	switch b := bindings.(type) {
	case []*v1.RoleBinding:
		for _, binding := range b {
			if binding.RoleRef.Name == roleName && binding.RoleRef.Kind == roleKind && binding.Namespace == namespace {
				subjects = append(subjects, binding.Subjects...)
			}
		}
	case []*v1.ClusterRoleBinding:
		for _, binding := range b {
			if binding.RoleRef.Name == roleName && binding.RoleRef.Kind == roleKind {
				subjects = append(subjects, binding.Subjects...)
			}
		}
	}
	return subjects
}

func toSubjectType(kind string) SubjectType {
	switch kind {
	case "User":
		return SubjectTypeUser
	case "Group":
		return SubjectTypeGroup
	case "ServiceAccount":
		return SubjectTypeServiceAccount
	default:
		return SubjectType(kind)
	}
}
