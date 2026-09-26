package api_clients

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hubble-ui/backend/domain/policy"
	"github.com/cilium/hubble-ui/backend/internal/api_helpers"
)

const policyKindsCount = 3

func (c *APIClients) ListNamespacePolicies(
	ctx context.Context,
	namespace string,
) (*policy.ListResult, error) {
	res := &policy.ListResult{}
	permissionErrors := []error{}

	cnps, err := c.cilium.CiliumV2().
		CiliumNetworkPolicies(namespace).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		for i := range cnps.Items {
			res.Objects = append(res.Objects, policy.FromCiliumNetworkPolicy(c.log, &cnps.Items[i]))
		}
	} else if !tolerateListError(res, &permissionErrors, policy.KindCiliumNetworkPolicy, err) {
		return nil, err
	}

	ccnps, err := c.cilium.CiliumV2().
		CiliumClusterwideNetworkPolicies().
		List(ctx, metav1.ListOptions{})
	if err == nil {
		for i := range ccnps.Items {
			res.Objects = append(
				res.Objects,
				policy.FromCiliumClusterwideNetworkPolicy(c.log, &ccnps.Items[i]),
			)
		}
	} else if !tolerateListError(res, &permissionErrors, policy.KindCiliumClusterwideNetworkPolicy, err) {
		return nil, err
	}

	knps, err := c.k8s.NetworkingV1().
		NetworkPolicies(namespace).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		for i := range knps.Items {
			res.Objects = append(res.Objects, policy.FromNetworkPolicy(&knps.Items[i]))
		}
	} else if !tolerateListError(res, &permissionErrors, policy.KindNetworkPolicy, err) {
		return nil, err
	}

	// NOTE: When nothing at all can be read the frontend should show the
	// RBAC problem instead of an empty map.
	if len(permissionErrors) == policyKindsCount {
		return nil, permissionErrors[0]
	}

	return res, nil
}

// tolerateListError turns errors that only affect one policy kind into
// warnings: a missing API (CRD not installed) or missing RBAC for it.
func tolerateListError(
	res *policy.ListResult,
	permissionErrors *[]error,
	kind policy.Kind,
	err error,
) bool {
	switch {
	case api_helpers.IsK8sResourceNotFound(err):
		res.Warnings = append(
			res.Warnings,
			fmt.Sprintf("%s API is not available in this cluster", kind),
		)

		return true
	case api_helpers.IsK8sResourcePermissionsError(err):
		*permissionErrors = append(*permissionErrors, err)
		res.Warnings = append(
			res.Warnings,
			fmt.Sprintf("hubble-ui is not allowed to list %s: %v", kind, err),
		)

		return true
	}

	return false
}
