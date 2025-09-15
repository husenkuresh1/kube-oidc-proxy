package authorizer

import (
	"sync"
)

// PermissionTrie represents a hierarchical permission structure
// Subject → Cluster → Namespace → Resource → Verb → bool
type PermissionTrie struct {
	subjectNodes map[string]*SubjectNode
	mu           sync.RWMutex
}

// SubjectType represents the type of subject (user, group, serviceaccount)
type SubjectType string

const (
	SubjectTypeUser           SubjectType = "User"
	SubjectTypeGroup          SubjectType = "Group"
	SubjectTypeServiceAccount SubjectType = "ServiceAccount"
)

// SubjectNode represents permissions for a specific subject
type SubjectNode struct {
	subjectType  SubjectType
	clusterNodes map[string]*ClusterNode
}

// ClusterNode represents permissions for a specific cluster
type ClusterNode struct {
	namespaceNodes map[string]*NamespaceNode
}

// NamespaceNode represents permissions for a specific namespace
type NamespaceNode struct {
	apiGroupNodes map[string]*APIGroupNode
}

// APIGroupNode represents permissions for a specific API group
type APIGroupNode struct {
	resourceNodes map[string]*ResourceNode
}

// ResourceNode represents permissions for a specific resource
type ResourceNode struct {
	verbs map[string]bool
}

// NewPermissionTrie creates a new empty PermissionTrie
func NewPermissionTrie() *PermissionTrie {
	return &PermissionTrie{
		subjectNodes: make(map[string]*SubjectNode),
	}
}

// AddPermission adds a permission to the trie
func (t *PermissionTrie) AddPermission(subjectType SubjectType, subjectName, cluster, namespace, apiGroup, resource, verb string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	subjectNode := t.getOrCreateSubjectNode(subjectType, subjectName)
	clusterNode := subjectNode.getOrCreateClusterNode(cluster)
	namespaceNode := clusterNode.getOrCreateNamespaceNode(namespace)
	apiGroupNode := namespaceNode.getOrCreateAPIGroupNode(apiGroup)
	resourceNode := apiGroupNode.getOrCreateResourceNode(resource)
	resourceNode.verbs[verb] = true
}

// RemovePermission removes a permission from the trie for a specific subject
func (t *PermissionTrie) RemovePermission(subjectType SubjectType, subjectName, cluster, namespace, apiGroup, resource, verb string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	subjectKey := getSubjectKey(subjectType, subjectName)
	if subjectNode, exists := t.subjectNodes[subjectKey]; exists {
		if clusterNode, exists := subjectNode.clusterNodes[cluster]; exists {
			if namespaceNode, exists := clusterNode.namespaceNodes[namespace]; exists {
				if apiGroupNode, exists := namespaceNode.apiGroupNodes[apiGroup]; exists {
					if resourceNode, exists := apiGroupNode.resourceNodes[resource]; exists {
						delete(resourceNode.verbs, verb)

						// Cleanup empty nodes
						if len(resourceNode.verbs) == 0 {
							delete(apiGroupNode.resourceNodes, resource)
						}
						if len(apiGroupNode.resourceNodes) == 0 {
							delete(namespaceNode.apiGroupNodes, apiGroup)
						}
						if len(namespaceNode.apiGroupNodes) == 0 {
							delete(clusterNode.namespaceNodes, namespace)
						}
						if len(clusterNode.namespaceNodes) == 0 {
							delete(subjectNode.clusterNodes, cluster)
						}
						if len(subjectNode.clusterNodes) == 0 {
							delete(t.subjectNodes, subjectKey)
						}
					}
				}
			}
		}
	}
}

// Helper methods to get or create nodes
func (t *PermissionTrie) getOrCreateSubjectNode(subjectType SubjectType, subjectName string) *SubjectNode {
	subjectKey := getSubjectKey(subjectType, subjectName)
	if _, exists := t.subjectNodes[subjectKey]; !exists {
		t.subjectNodes[subjectKey] = &SubjectNode{
			subjectType:  subjectType,
			clusterNodes: make(map[string]*ClusterNode),
		}

	}
	return t.subjectNodes[subjectKey]
}

func (s *SubjectNode) getOrCreateClusterNode(cluster string) *ClusterNode {
	if _, exists := s.clusterNodes[cluster]; !exists {
		s.clusterNodes[cluster] = &ClusterNode{
			namespaceNodes: make(map[string]*NamespaceNode),
		}
	}
	return s.clusterNodes[cluster]
}

func (c *ClusterNode) getOrCreateNamespaceNode(namespace string) *NamespaceNode {
	if _, exists := c.namespaceNodes[namespace]; !exists {
		c.namespaceNodes[namespace] = &NamespaceNode{
			apiGroupNodes: make(map[string]*APIGroupNode),
		}

	}
	return c.namespaceNodes[namespace]
}

func (n *NamespaceNode) getOrCreateAPIGroupNode(apiGroup string) *APIGroupNode {
	if _, exists := n.apiGroupNodes[apiGroup]; !exists {
		n.apiGroupNodes[apiGroup] = &APIGroupNode{
			resourceNodes: make(map[string]*ResourceNode),
		}
	}
	return n.apiGroupNodes[apiGroup]
}

func (a *APIGroupNode) getOrCreateResourceNode(resource string) *ResourceNode {
	if _, exists := a.resourceNodes[resource]; !exists {
		a.resourceNodes[resource] = &ResourceNode{
			verbs: make(map[string]bool),
		}
	}
	return a.resourceNodes[resource]
}

// CheckPermission checks if a subject has permission to perform an action on a resource
func (t *PermissionTrie) CheckPermission(subjectType SubjectType, subjectName, cluster, namespace, apiGroup, resource, verb string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	subjectKey := getSubjectKey(subjectType, subjectName)
	subjectNode, exists := t.subjectNodes[subjectKey]
	if !exists {
		return false
	}

	clusterNode, exists := subjectNode.clusterNodes[cluster]
	if !exists {
		return false
	}

	var namespaceNode *NamespaceNode
	var apiGroupNode *APIGroupNode
	var resourceNode *ResourceNode

	namespaceNode, exists = clusterNode.namespaceNodes[""]
	if !exists {
		namespaceNode, exists = clusterNode.namespaceNodes[namespace]
	}
	if !exists {
		return false
	}

	apiGroupNode, exists = namespaceNode.apiGroupNodes[""]
	if !exists {
		apiGroupNode, exists = namespaceNode.apiGroupNodes[apiGroup]
	}
	if !exists {
		return false
	}

	resourceNode, exists = apiGroupNode.resourceNodes["*"]
	if !exists {
		resourceNode, exists = apiGroupNode.resourceNodes[resource]
	}
	if !exists {
		return false
	}

	if resourceNode.verbs["*"] || resourceNode.verbs[verb] {
		return true
	}

	return false
}

// Helper function to create a unique key for subject
func getSubjectKey(subjectType SubjectType, subjectName string) string {
	return string(subjectType) + ":" + subjectName
}
