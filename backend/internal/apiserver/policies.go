package apiserver

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/hubble-ui/backend/domain/policy"
	"github.com/cilium/hubble-ui/backend/internal/api_helpers"
	"github.com/cilium/hubble-ui/backend/internal/apiserver/req_context"
	cp "github.com/cilium/hubble-ui/backend/internal/customprotocol"
	"github.com/cilium/hubble-ui/backend/proto/ui"
)

// GetPolicies answers one request with the static access graph of a
// namespace: the policies that apply to it and the cards and links they
// describe. It is a oneshot route, there is nothing to stream.
func (srv *APIServer) GetPolicies(ch *cp.Channel, rctx *req_context.Context) error {
	log, ctx := rctx.Log, rctx.Context()

	msg, err := ch.Receive()
	if err != nil {
		return err
	}

	req := new(ui.GetPoliciesRequest)
	if err := msg.DeserializeProtoBody(req); err != nil {
		return err
	}

	namespace := req.GetNamespace()
	if namespace == "" {
		return status.Error(codes.InvalidArgument, "namespace is required")
	}

	if err := srv.authorizer.CheckNamespace(rctx, namespace); err != nil {
		return err
	}

	listed, err := srv.clients.ListNamespacePolicies(ctx, namespace)
	if err != nil {
		if api_helpers.IsK8sResourcePermissionsError(err) {
			log.Warn("not allowed to list network policies", "namespace", namespace, "error", err)

			return status.Error(codes.PermissionDenied, err.Error())
		}

		log.Error("failed to list network policies", "namespace", namespace, "error", err)

		return err
	}

	objects := policy.Sorted(listed.Objects)
	graph := policy.BuildGraph(namespace, objects)

	resp := &ui.GetPoliciesResponse{
		Services: graph.Services,
		Links:    graph.Links,
		Warnings: listed.Warnings,
	}

	for _, obj := range objects {
		resp.Policies = append(resp.Policies, &ui.PolicyObject{
			Kind:            string(obj.Kind),
			Name:            obj.Name,
			Namespace:       obj.Namespace,
			Uid:             obj.UID,
			ResourceVersion: obj.ResourceVersion,
			Description:     obj.Description,
			Yaml:            obj.YAML,
			ServiceIds:      graph.ServiceIDs[obj.Key()],
			LinkIds:         graph.LinkIDs[obj.Key()],
			ParseError:      obj.ParseError,
		})
	}

	log.Info(
		"policies graph is built",
		"namespace", namespace,
		"policies", len(resp.GetPolicies()),
		"services", len(resp.GetServices()),
		"links", len(resp.GetLinks()),
	)

	return ch.TerminateProto(resp)
}
