package authorizer

import (
	"sync"
)

type PermissionTrie struct {
	root  *trieNode
	mutex sync.RWMutex
}

type trieNode struct {
	children map[string]*trieNode
	verbs    map[string]bool
}

type SubjectType string

const (
	SubjectTypeUser           SubjectType = "User"
	SubjectTypeGroup          SubjectType = "Group"
	SubjectTypeServiceAccount SubjectType = "ServiceAccount"
)

func NewPermissionTrie() *PermissionTrie {
	return &PermissionTrie{
		root: &trieNode{children: make(map[string]*trieNode)},
	}
}

func (t *PermissionTrie) AddPermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	path := []string{
		string(subjectType),
		subjectName,
		cluster,
		namespace,
		resource,
	}

	node := t.root
	for _, segment := range path {
		if node.children == nil {
			node.children = make(map[string]*trieNode)
		}
		if node.children[segment] == nil {
			node.children[segment] = &trieNode{}
		}
		node = node.children[segment]
	}

	if node.verbs == nil {
		node.verbs = make(map[string]bool)
	}
	node.verbs[verb] = true
}

func (t *PermissionTrie) CheckPermission(subjectType SubjectType, subjectName, cluster, namespace, resource, verb string) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	path := []string{
		string(subjectType),
		subjectName,
		cluster,
		namespace,
		resource,
	}

	node := t.root
	for _, segment := range path {
		if node.children == nil {
			return false
		}
		if node.children[segment] == nil {
			return false
		}
		node = node.children[segment]
	}

	return node.verbs != nil && node.verbs[verb]
}

func (t *PermissionTrie) RemoveCluster(clusterName string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.removeCluster(t.root, clusterName, 0)
}

func (t *PermissionTrie) removeCluster(node *trieNode, clusterName string, depth int) {
	if node.children == nil {
		return
	}

	if depth == 2 { // Cluster level
		delete(node.children, clusterName)
		return
	}

	for _, child := range node.children {
		t.removeCluster(child, clusterName, depth+1)
	}
}
