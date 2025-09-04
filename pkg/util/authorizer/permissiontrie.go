package authorizer

import (
	"fmt"
	"sort"
	"strings"
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
func (t *PermissionTrie) AddPermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	subjectNode := t.getOrCreateSubjectNode(subjectType, subjectName)
	clusterNode := subjectNode.getOrCreateClusterNode(cluster)
	namespaceNode := clusterNode.getOrCreateNamespaceNode(namespace)
	resourceNode := namespaceNode.getOrCreateResourceNode(resource)
	resourceNode.verbs[verb] = true
}

// RemovePermission removes a permission from the trie for a specific subject
func (t *PermissionTrie) RemovePermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	subjectKey := getSubjectKey(subjectType, subjectName)
	if subjectNode, exists := t.subjectNodes[subjectKey]; exists {
		if clusterNode, exists := subjectNode.clusterNodes[cluster]; exists {
			if namespaceNode, exists := clusterNode.namespaceNodes[namespace]; exists {
				if resourceNode, exists := namespaceNode.resourceNodes[resource]; exists {
					delete(resourceNode.verbs, verb)

					// Cleanup empty nodes
					if len(resourceNode.verbs) == 0 {
						delete(namespaceNode.resourceNodes, resource)
					}
					if len(namespaceNode.resourceNodes) == 0 {
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
			resourceNodes: make(map[string]*ResourceNode),
		}
	}
	return c.namespaceNodes[namespace]
}

func (n *NamespaceNode) getOrCreateResourceNode(resource string) *ResourceNode {
	if _, exists := n.resourceNodes[resource]; !exists {
		n.resourceNodes[resource] = &ResourceNode{
			verbs: make(map[string]bool),
		}
	}
	return n.resourceNodes[resource]
}

// Helper function to create a unique key for subject
func getSubjectKey(subjectType SubjectType, subjectName string) string {
	return string(subjectType) + ":" + subjectName
}

// PrintTrie prints the permission trie in a readable format

func (s *SubjectNode) printClusterNodes(indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	for cluster, clusterNode := range s.clusterNodes {
		fmt.Printf("%sCluster: %s\n", indent, cluster)
		clusterNode.printNamespaceNodes(indentLevel + 1)
	}
}

func (c *ClusterNode) printNamespaceNodes(indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	for namespace, namespaceNode := range c.namespaceNodes {
		fmt.Printf("%sNamespace: %s\n", indent, namespace)
		namespaceNode.printResourceNodes(indentLevel + 1)
	}
}

func (n *NamespaceNode) printResourceNodes(indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	for resource, resourceNode := range n.resourceNodes {
		fmt.Printf("%sResource: %s\n", indent, resource)
		resourceNode.printVerbs(indentLevel + 1)
	}
}

func (r *ResourceNode) printVerbs(indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	verbs := make([]string, 0, len(r.verbs))
	for verb := range r.verbs {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	fmt.Printf("%sVerbs: %s\n", indent, strings.Join(verbs, ", "))
}
