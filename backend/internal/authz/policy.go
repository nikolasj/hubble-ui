package authz

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"sigs.k8s.io/yaml"
)

var (
	ErrNoIdentity         = errors.New("request carries no identity headers")
	ErrNamespaceDenied    = errors.New("namespace is not allowed for this user")
	ErrNoNamespaceScope   = errors.New("request is not scoped to an allowed namespace")
	ErrIdentityMismatch   = errors.New("channel was opened by another user")
	errRuleWithoutSubject = errors.New("authz rule has neither users nor groups")
	errRuleWithoutNS      = errors.New("authz rule has no namespaces")
)

// Identity is what the authentication proxy in front of hubble-ui tells us
// about the user behind a request.
type Identity struct {
	User   string
	Groups []string
}

func (id Identity) String() string {
	if len(id.Groups) == 0 {
		return id.User
	}

	return id.User + " (" + strings.Join(id.Groups, ",") + ")"
}

// Rule grants the listed namespaces to the listed users and groups. Namespace
// entries are glob patterns as in path.Match, "*" grants every namespace.
type Rule struct {
	Users      []string `json:"users,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Namespaces []string `json:"namespaces"`
}

// Policy is the static namespace access map. The union of all rules matching
// an identity decides what it may see; nothing matches, nothing is visible.
type Policy struct {
	Rules []Rule `json:"rules"`
}

func LoadPolicyFile(filePath string) (*Policy, error) {
	//nolint:gosec // the path comes from the deployment configuration, not from a request
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read authz policy file: %w", err)
	}

	return ParsePolicy(content)
}

func ParsePolicy(content []byte) (*Policy, error) {
	policy := new(Policy)
	if err := yaml.Unmarshal(content, policy); err != nil {
		return nil, fmt.Errorf("failed to parse authz policy: %w", err)
	}

	if err := policy.Validate(); err != nil {
		return nil, err
	}

	return policy, nil
}

func (p *Policy) Validate() error {
	for i := range p.Rules {
		rule := &p.Rules[i]

		if len(rule.Users) == 0 && len(rule.Groups) == 0 {
			return fmt.Errorf("rule %d: %w", i, errRuleWithoutSubject)
		}

		if len(rule.Namespaces) == 0 {
			return fmt.Errorf("rule %d: %w", i, errRuleWithoutNS)
		}

		for _, pattern := range rule.Namespaces {
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("rule %d: invalid namespace pattern %q: %w", i, pattern, err)
			}
		}
	}

	return nil
}

// Patterns returns every namespace pattern granted to the identity.
func (p *Policy) Patterns(id Identity) []string {
	patterns := []string{}

	for i := range p.Rules {
		if p.Rules[i].matches(id) {
			patterns = append(patterns, p.Rules[i].Namespaces...)
		}
	}

	return patterns
}

// AllowsAll reports whether the identity may see every namespace.
func (p *Policy) AllowsAll(id Identity) bool {
	for _, pattern := range p.Patterns(id) {
		if pattern == "*" {
			return true
		}
	}

	return false
}

func (p *Policy) Allows(id Identity, namespace string) bool {
	if namespace == "" {
		return false
	}

	for _, pattern := range p.Patterns(id) {
		if pattern == "*" {
			return true
		}

		if ok, err := path.Match(pattern, namespace); err == nil && ok {
			return true
		}
	}

	return false
}

func (r *Rule) matches(id Identity) bool {
	for _, user := range r.Users {
		if user != "" && strings.EqualFold(user, id.User) {
			return true
		}
	}

	for _, group := range r.Groups {
		for _, have := range id.Groups {
			if group != "" && strings.EqualFold(group, have) {
				return true
			}
		}
	}

	return false
}
