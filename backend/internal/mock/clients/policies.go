package clients

import (
	"context"

	"github.com/cilium/hubble-ui/backend/domain/policy"
	"github.com/cilium/hubble-ui/backend/internal/mock/factories"
)

func (cl *Clients) ListNamespacePolicies(
	_ context.Context,
	namespace string,
) (*policy.ListResult, error) {
	return factories.CreatePolicies(cl.log, namespace)
}
