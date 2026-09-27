package authz

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"

	"github.com/cilium/hubble-ui/backend/proto/ui"
)

const policyYAML = `
rules:
  - users: ["Alice@Example.com"]
    namespaces: ["team-a", "team-a-*"]
  - groups: ["platform"]
    namespaces: ["*"]
  - groups: ["observers"]
    namespaces: ["monitoring"]
`

func loadTestPolicy(t *testing.T) *Policy {
	t.Helper()

	policy, err := ParsePolicy([]byte(policyYAML))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	return policy
}

func TestPolicyMatching(t *testing.T) {
	policy := loadTestPolicy(t)

	alice := Identity{User: "alice@example.com"}
	if !policy.Allows(alice, "team-a") || !policy.Allows(alice, "team-a-staging") {
		t.Errorf("alice must see her namespaces")
	}

	if policy.Allows(alice, "team-b") || policy.Allows(alice, "") {
		t.Errorf("alice must not see other namespaces")
	}

	if policy.AllowsAll(alice) {
		t.Errorf("alice must not see everything")
	}

	admin := Identity{User: "bob@example.com", Groups: []string{"Platform"}}
	if !policy.Allows(admin, "kube-system") || !policy.AllowsAll(admin) {
		t.Errorf("platform group must see everything")
	}

	observer := Identity{User: "carol@example.com", Groups: []string{"observers", "other"}}
	if !policy.Allows(observer, "monitoring") || policy.Allows(observer, "team-a") {
		t.Errorf("observers must only see monitoring")
	}

	nobody := Identity{User: "dave@example.com", Groups: []string{"unknown"}}
	if len(policy.Patterns(nobody)) != 0 || policy.Allows(nobody, "team-a") {
		t.Errorf("unknown users must see nothing")
	}
}

func TestPolicyValidation(t *testing.T) {
	cases := map[string]string{
		"no subject":      "rules:\n  - namespaces: [\"a\"]\n",
		"no namespaces":   "rules:\n  - users: [\"a\"]\n",
		"invalid pattern": "rules:\n  - users: [\"a\"]\n    namespaces: [\"[\"]\n",
		"not yaml":        "rules: [",
	}

	for name, content := range cases {
		if _, err := ParsePolicy([]byte(content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHeaderIdentity(t *testing.T) {
	reader := HeaderIdentity{
		UserHeaders:     []string{"x-auth-request-email", "x-auth-request-user"},
		GroupsHeader:    "x-auth-request-groups",
		GroupsSeparator: ",",
	}

	headers := http.Header{}
	headers.Set("X-Auth-Request-User", "alice")
	headers.Add("X-Auth-Request-Groups", "platform, observers")
	headers.Add("X-Auth-Request-Groups", "extra")

	id, ok := reader.FromHeaders(headers)
	if !ok || id.User != "alice" {
		t.Fatalf("unexpected identity: %+v", id)
	}

	if len(id.Groups) != 3 || id.Groups[0] != "platform" || id.Groups[2] != "extra" {
		t.Errorf("unexpected groups: %v", id.Groups)
	}

	headers.Set("X-Auth-Request-Email", "alice@example.com")
	if id, _ := reader.FromHeaders(headers); id.User != "alice@example.com" {
		t.Errorf("the first configured header must win, got %q", id.User)
	}

	if _, ok := reader.FromHeaders(http.Header{}); ok {
		t.Errorf("no headers must mean no identity")
	}
}

func flowsRequest(filters ...*flow.FlowFilter) *ui.GetEventsRequest {
	req := &ui.GetEventsRequest{}
	for _, ff := range filters {
		req.Whitelist = append(req.Whitelist, &ui.EventFilter{
			Filter: &ui.EventFilter_FlowFilter{FlowFilter: ff},
		})
	}

	return req
}

func TestCheckFlowsRequest(t *testing.T) {
	allowed := func(ns string) bool { return ns == "team-a" }

	// The way the frontend scopes a namespace: one filter per direction
	ok := flowsRequest(
		&flow.FlowFilter{SourcePod: []string{"team-a/"}},
		&flow.FlowFilter{DestinationPod: []string{"team-a/"}},
	)
	if err := CheckFlowsRequest(allowed, false, ok); err != nil {
		t.Errorf("namespace scoped request must pass: %v", err)
	}

	// A pod filter for a pod in another namespace, still pinned to team-a
	crossNS := flowsRequest(
		&flow.FlowFilter{SourcePod: []string{"team-b/api"}, DestinationPod: []string{"team-a/"}},
	)
	if err := CheckFlowsRequest(allowed, false, crossNS); err != nil {
		t.Errorf("filter pinned to an allowed destination must pass: %v", err)
	}

	cases := map[string]*ui.GetEventsRequest{
		"no whitelist":      flowsRequest(),
		"unscoped filter":   flowsRequest(&flow.FlowFilter{Verdict: []flow.Verdict{flow.Verdict_DROPPED}}),
		"other namespace":   flowsRequest(&flow.FlowFilter{SourcePod: []string{"team-b/"}}),
		"mixed source pods": flowsRequest(&flow.FlowFilter{SourcePod: []string{"team-a/", "team-b/"}}),
		"one unscoped of two": flowsRequest(
			&flow.FlowFilter{SourcePod: []string{"team-a/"}},
			&flow.FlowFilter{DestinationLabel: []string{"app=web"}},
		),
		"pod without namespace": flowsRequest(&flow.FlowFilter{SourcePod: []string{"web"}}),
	}

	for name, req := range cases {
		err := CheckFlowsRequest(allowed, false, req)
		if !errors.Is(err, ErrNoNamespaceScope) {
			t.Errorf("%s: expected ErrNoNamespaceScope, got %v", name, err)
		}
	}

	if err := CheckFlowsRequest(allowed, true, flowsRequest()); err != nil {
		t.Errorf("users who may see everything are not restricted: %v", err)
	}
}
