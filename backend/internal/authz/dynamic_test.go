package authz

import (
	"sort"
	"testing"
)

const dynamicPolicyYAML = `
rules:
  - groups: ["devops"]
    namespaces: ["*"]
  - groupPattern: "^development-(.+)$"
    namespaces: ["${1}", "${1}-*"]
  - groupPattern: "^qa-(.+)-(.+)$"
    namespaces: ["${1}-${2}-qa"]
`

func TestDynamicGroupRules(t *testing.T) {
	policy, err := ParsePolicy([]byte(dynamicPolicyYAML))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	dev := Identity{User: "dev@example.com", Groups: []string{"Development-Payments", "some-other"}}
	patterns := policy.Patterns(dev)
	sort.Strings(patterns)
	if len(patterns) != 2 || patterns[0] != "payments" || patterns[1] != "payments-*" {
		t.Fatalf("unexpected patterns for a development group: %v", patterns)
	}

	if !policy.Allows(dev, "payments") || !policy.Allows(dev, "payments-staging") {
		t.Errorf("members of Development-Payments must see payments namespaces")
	}

	if policy.Allows(dev, "billing") || policy.AllowsAll(dev) {
		t.Errorf("members of Development-Payments must not see other namespaces")
	}

	twoTeams := Identity{User: "lead@example.com", Groups: []string{"development-payments", "development-billing"}}
	if !policy.Allows(twoTeams, "payments") || !policy.Allows(twoTeams, "billing-canary") {
		t.Errorf("every matching group must grant its namespaces")
	}

	qa := Identity{User: "qa@example.com", Groups: []string{"qa-shop-eu"}}
	if !policy.Allows(qa, "shop-eu-qa") || policy.Allows(qa, "shop-eu") {
		t.Errorf("several captures must expand into the template: %v", policy.Patterns(qa))
	}

	devops := Identity{User: "ops@example.com", Groups: []string{"devops", "development-payments"}}
	if !policy.AllowsAll(devops) {
		t.Errorf("devops must see everything")
	}

	nobody := Identity{User: "x@example.com", Groups: []string{"developmentpayments", "dev-payments"}}
	if len(policy.Patterns(nobody)) != 0 {
		t.Errorf("groups that do not match the pattern must grant nothing: %v", policy.Patterns(nobody))
	}
}

func TestDynamicGroupRuleValidation(t *testing.T) {
	if _, err := ParsePolicy([]byte("rules:\n  - groupPattern: \"^dev-(\"\n    namespaces: [\"${1}\"]\n")); err == nil {
		t.Errorf("invalid regular expression must be rejected")
	}

	if _, err := ParsePolicy([]byte("rules:\n  - groupPattern: \"^dev-(.+)$\"\n    namespaces: [\"${1}\"]\n")); err != nil {
		t.Errorf("a rule with only a group pattern is valid: %v", err)
	}
}
