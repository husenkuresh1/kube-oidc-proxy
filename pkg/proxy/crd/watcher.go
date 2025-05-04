package crd

import (
	"os"
	"time"

	"github.com/Improwised/kube-oidc-proxy/pkg/proxy"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type CAPIRbacWatcher struct {
	CAPIClusterRoleInformer        cache.SharedIndexInformer
	CAPIRoleInformer               cache.SharedIndexInformer
	CAPIClusterRoleBindingInformer cache.SharedIndexInformer
	CAPIRoleBindingInformer        cache.SharedIndexInformer
	clusters                       []*proxy.ClusterConfig
}

func NewCAPIRbacWatcher(clusters []*proxy.ClusterConfig) (*CAPIRbacWatcher, error) {

	clusterConfig, err := buildConfiguration()
	if err != nil {
		return &CAPIRbacWatcher{}, err
	}

	clusterClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return &CAPIRbacWatcher{}, err
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(clusterClient,
		time.Minute, "", nil)

	capiRoleInformer := factory.ForResource(CAPIRoleGVR).Informer()
	capiRoleBindingInformer := factory.ForResource(CAPIRoleBindingGVR).Informer()
	capiClusterRoleInformer := factory.ForResource(CAPIClusterRoleGVR).Informer()
	capiClusterRoleBindingInformer := factory.ForResource(CAPIClusterRoleBindingGVR).Informer()

	return &CAPIRbacWatcher{
		CAPIRoleInformer:               capiRoleInformer,
		CAPIClusterRoleInformer:        capiClusterRoleInformer,
		CAPIRoleBindingInformer:        capiRoleBindingInformer,
		CAPIClusterRoleBindingInformer: capiClusterRoleBindingInformer,
		clusters:                       clusters,
	}, nil
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
