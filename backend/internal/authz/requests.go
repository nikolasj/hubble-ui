package authz

import (
	"strings"

	"github.com/cilium/cilium/api/v1/flow"

	"github.com/cilium/hubble-ui/backend/proto/ui"
)

// CheckFlowsRequest makes sure every flow the request can return touches a
// namespace the user may see. Hubble ORs the whitelist filters and ANDs the
// fields inside one filter, and it ORs the values of one field, so a filter
// is only safe when its source pods or its destination pods are all pinned
// to allowed namespaces. A request without a whitelist would return the
// whole cluster and is refused unless the user may see everything.
func CheckFlowsRequest(allowed func(string) bool, allowsAll bool, req *ui.GetEventsRequest) error {
	if allowsAll {
		return nil
	}

	filters := []*flow.FlowFilter{}
	for _, eventFilter := range req.GetWhitelist() {
		if ff := eventFilter.GetFlowFilter(); ff != nil {
			filters = append(filters, ff)
		}
	}

	if len(filters) == 0 {
		return ErrNoNamespaceScope
	}

	for _, ff := range filters {
		if !podsAllowed(allowed, ff.GetSourcePod()) && !podsAllowed(allowed, ff.GetDestinationPod()) {
			return ErrNoNamespaceScope
		}
	}

	return nil
}

// podsAllowed reports whether a non-empty pod filter refers to allowed
// namespaces only. Entries are "namespace/pod-prefix"; an entry without a
// namespace cannot be checked and is treated as not allowed.
func podsAllowed(allowed func(string) bool, pods []string) bool {
	if len(pods) == 0 {
		return false
	}

	for _, pod := range pods {
		namespace, _, ok := strings.Cut(pod, "/")
		if !ok || namespace == "" || !allowed(namespace) {
			return false
		}
	}

	return true
}
