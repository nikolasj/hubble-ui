package apiserver

import (
	"log/slog"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/hubble-ui/backend/internal/apiserver/req_context"
	"github.com/cilium/hubble-ui/backend/internal/authz"
	"github.com/cilium/hubble-ui/backend/internal/config"
	cp "github.com/cilium/hubble-ui/backend/internal/customprotocol"
	"github.com/cilium/hubble-ui/backend/internal/ns_watcher"
	"github.com/cilium/hubble-ui/backend/proto/ui"
)

// Authorizer limits what a user may see to the namespaces granted by the
// static access map. It relies on the authentication proxy in front of
// hubble-ui to set identity headers, so the backend must only be reachable
// through that proxy. A nil policy means no restrictions at all.
type Authorizer struct {
	log     *slog.Logger
	policy  *authz.Policy
	headers authz.HeaderIdentity
}

func newAuthorizer(cfg *config.Config, log *slog.Logger) (*Authorizer, error) {
	a := &Authorizer{log: log}
	if !cfg.AuthzEnabled() {
		return a, nil
	}

	policy, err := authz.LoadPolicyFile(cfg.AuthzPolicyFile)
	if err != nil {
		return nil, err
	}

	a.policy = policy
	a.headers = authz.HeaderIdentity{
		UserHeaders:     cfg.AuthzUserHeaders,
		GroupsHeader:    cfg.AuthzGroupsHeader,
		GroupsSeparator: cfg.AuthzGroupsSeparator,
	}

	log.Info("namespace access control is enabled", "rules", len(policy.Rules))

	return a, nil
}

func (a *Authorizer) Enabled() bool {
	return a != nil && a.policy != nil
}

// Authenticate reads the identity of the message and binds it to the channel.
// The first message of a channel sets the identity, later polls must carry
// the same one, otherwise a stolen channel id could be used by someone else.
// A missing identity is not returned as an error here: the handler reports
// it, so that the client gets a protocol error instead of a bare HTTP 500.
func (a *Authorizer) Authenticate(rctx *req_context.Context, msg *cp.Message) error {
	if !a.Enabled() {
		return nil
	}

	headers, ok := msg.RequestHeaders()
	id, found := authz.Identity{}, false
	if ok {
		id, found = a.headers.FromHeaders(headers)
	}

	bound, isBound := rctx.Identity()

	switch {
	case !found && !isBound:
		a.log.Warn("request without identity headers, is the auth proxy in front of hubble-ui?")
		rctx.SetAuthError(status.Error(codes.Unauthenticated, authz.ErrNoIdentity.Error()))

		return nil
	case !found:
		return status.Error(codes.Unauthenticated, authz.ErrNoIdentity.Error())
	case !isBound:
		rctx.SetIdentity(id)

		return nil
	case bound.User != id.User || !slices.Equal(bound.Groups, id.Groups):
		a.log.Warn("channel identity mismatch", "bound", bound.String(), "got", id.String())

		return status.Error(codes.PermissionDenied, authz.ErrIdentityMismatch.Error())
	}

	return nil
}

// Precheck is what every handler runs first: it reports an authentication
// problem recorded by the middleware.
func (a *Authorizer) Precheck(rctx *req_context.Context) error {
	if !a.Enabled() {
		return nil
	}

	if err := rctx.AuthError(); err != nil {
		return err
	}

	if _, ok := rctx.Identity(); !ok {
		return status.Error(codes.Unauthenticated, authz.ErrNoIdentity.Error())
	}

	return nil
}

func (a *Authorizer) CheckNamespace(rctx *req_context.Context, namespace string) error {
	if err := a.Precheck(rctx); err != nil {
		return err
	}

	if !a.Enabled() {
		return nil
	}

	id, _ := rctx.Identity()
	if !a.policy.Allows(id, namespace) {
		a.log.Warn("namespace denied", "user", id.String(), "namespace", namespace)

		return status.Error(codes.PermissionDenied, authz.ErrNamespaceDenied.Error())
	}

	return nil
}

func (a *Authorizer) CheckFlowsRequest(rctx *req_context.Context, req *ui.GetEventsRequest) error {
	if err := a.Precheck(rctx); err != nil {
		return err
	}

	if !a.Enabled() {
		return nil
	}

	id, _ := rctx.Identity()
	allowed := func(namespace string) bool { return a.policy.Allows(id, namespace) }
	if err := authz.CheckFlowsRequest(allowed, a.policy.AllowsAll(id), req); err != nil {
		a.log.Warn("flows request denied", "user", id.String(), "error", err)

		return status.Error(codes.PermissionDenied, err.Error())
	}

	return nil
}

// FilterNSEvents drops namespaces the user may not see from the list that
// feeds the namespace selector.
func (a *Authorizer) FilterNSEvents(
	rctx *req_context.Context,
	events []*ns_watcher.NSEvent,
) []*ns_watcher.NSEvent {
	if !a.Enabled() {
		return events
	}

	id, ok := rctx.Identity()
	if !ok {
		return nil
	}

	filtered := make([]*ns_watcher.NSEvent, 0, len(events))
	for _, evt := range events {
		if evt == nil || evt.K8sNamespace == nil {
			continue
		}

		if a.policy.Allows(id, evt.K8sNamespace.Name) {
			filtered = append(filtered, evt)
		}
	}

	return filtered
}

// AuthzMiddleware runs on every message of a channel, so that the identity
// is checked on the opening request and on each poll.
type AuthzMiddleware struct {
	srv *APIServer
}

func (srv *APIServer) authzMiddleware() *AuthzMiddleware {
	return &AuthzMiddleware{srv: srv}
}

func (am *AuthzMiddleware) Clone() cp.ChannelMiddleware {
	return &AuthzMiddleware{srv: am.srv}
}

func (am *AuthzMiddleware) RunBeforePolling(ch *cp.Channel, msg *cp.Message) error {
	if !am.srv.authorizer.Enabled() {
		return nil
	}

	rctx, err := am.srv.ensureHandlerData(ch)
	if err != nil {
		return err
	}

	return am.srv.authorizer.Authenticate(rctx, msg)
}
