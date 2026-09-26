package api_clients

import (
	"context"

	"github.com/cilium/hubble-ui/backend/domain/policy"
	"github.com/cilium/hubble-ui/backend/internal/ns_watcher"
	"github.com/cilium/hubble-ui/backend/internal/relay_client"
)

type APIClientsInterface interface {
	RelayClient() relay_client.RelayClientInterface
	NSWatcher(context.Context, ns_watcher.NSWatcherOptions) (ns_watcher.NSWatcherInterface, error)
	// ListNamespacePolicies reads the network policies that apply to the
	// namespace: its CiliumNetworkPolicies and NetworkPolicies plus every
	// CiliumClusterwideNetworkPolicy.
	ListNamespacePolicies(context.Context, string) (*policy.ListResult, error)
}
