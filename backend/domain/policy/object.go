package policy

import (
	"fmt"
	"log/slog"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumutils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

type Kind string

const (
	KindCiliumNetworkPolicy            Kind = "CiliumNetworkPolicy"
	KindCiliumClusterwideNetworkPolicy Kind = "CiliumClusterwideNetworkPolicy"
	KindNetworkPolicy                  Kind = "NetworkPolicy"

	ciliumAPIVersion      = "cilium.io/v2"
	networkingAPIVersion  = "networking.k8s.io/v1"
	lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"
)

// Object is a network policy of one of the supported kinds reduced to what the
// policy view needs: identification, the YAML to show and the subjects (selected
// endpoints together with their allowed and denied peers) to draw.
type Object struct {
	Kind            Kind
	Name            string
	Namespace       string
	UID             string
	ResourceVersion string
	Description     string
	YAML            string
	ParseError      string

	subjects []*subject
}

// ListResult is what a policies lister returns: the objects it could read and
// the non-fatal problems worth showing to the user.
type ListResult struct {
	Objects  []*Object
	Warnings []string
}

func (o *Object) Key() string {
	if o.Namespace == "" {
		return fmt.Sprintf("%s/%s", o.Kind, o.Name)
	}

	return fmt.Sprintf("%s/%s/%s", o.Kind, o.Namespace, o.Name)
}

func FromCiliumNetworkPolicy(log *slog.Logger, cnp *ciliumv2.CiliumNetworkPolicy) *Object {
	obj := &Object{
		Kind:            KindCiliumNetworkPolicy,
		Name:            cnp.Name,
		Namespace:       cnp.Namespace,
		UID:             string(cnp.UID),
		ResourceVersion: cnp.ResourceVersion,
	}

	clean := cnp.DeepCopy()
	clean.TypeMeta = metav1.TypeMeta{
		APIVersion: ciliumAPIVersion,
		Kind:       string(KindCiliumNetworkPolicy),
	}
	clean.Status = ciliumv2.CiliumNetworkPolicyStatus{}
	cleanupObjectMeta(&clean.ObjectMeta)

	obj.YAML = renderYAML(clean)
	obj.Description = describeRules(clean.Spec, clean.Specs)

	rules := ciliumRules(log, clean.Namespace, clean.Name, clean.UID, clean.Spec, clean.Specs)
	obj.subjects = subjectsFromCiliumRules(rules)

	return obj
}

func FromCiliumClusterwideNetworkPolicy(
	log *slog.Logger,
	ccnp *ciliumv2.CiliumClusterwideNetworkPolicy,
) *Object {
	obj := &Object{
		Kind:            KindCiliumClusterwideNetworkPolicy,
		Name:            ccnp.Name,
		UID:             string(ccnp.UID),
		ResourceVersion: ccnp.ResourceVersion,
	}

	clean := ccnp.DeepCopy()
	clean.TypeMeta = metav1.TypeMeta{
		APIVersion: ciliumAPIVersion,
		Kind:       string(KindCiliumClusterwideNetworkPolicy),
	}
	clean.Status = ciliumv2.CiliumNetworkPolicyStatus{}
	cleanupObjectMeta(&clean.ObjectMeta)

	obj.YAML = renderYAML(clean)
	obj.Description = describeRules(clean.Spec, clean.Specs)

	rules := ciliumRules(log, "", clean.Name, clean.UID, clean.Spec, clean.Specs)
	obj.subjects = subjectsFromCiliumRules(rules)

	return obj
}

func FromNetworkPolicy(np *networkingv1.NetworkPolicy) *Object {
	obj := &Object{
		Kind:            KindNetworkPolicy,
		Name:            np.Name,
		Namespace:       np.Namespace,
		UID:             string(np.UID),
		ResourceVersion: np.ResourceVersion,
	}

	clean := np.DeepCopy()
	clean.TypeMeta = metav1.TypeMeta{
		APIVersion: networkingAPIVersion,
		Kind:       string(KindNetworkPolicy),
	}
	cleanupObjectMeta(&clean.ObjectMeta)

	obj.YAML = renderYAML(clean)
	obj.subjects = subjectsFromNetworkPolicy(clean)

	return obj
}

// ciliumRules runs the same namespace and label normalization that the Cilium
// agent applies to a policy before it is enforced, so that selectors carry the
// namespace they are scoped to. Sanitization is skipped on purpose: it depends
// on agent options and this backend only needs to draw the rules.
func ciliumRules(
	log *slog.Logger,
	namespace, name string,
	uid types.UID,
	spec *api.Rule,
	specs api.Rules,
) api.Rules {
	rules := api.Rules{}

	if spec != nil {
		rules = append(
			rules,
			ciliumutils.ParseToCiliumRule(log, cmtypes.PolicyAnyCluster, namespace, name, uid, spec),
		)
	}

	for _, rule := range specs {
		if rule == nil {
			continue
		}

		rules = append(
			rules,
			ciliumutils.ParseToCiliumRule(log, cmtypes.PolicyAnyCluster, namespace, name, uid, rule),
		)
	}

	return rules
}

func describeRules(spec *api.Rule, specs api.Rules) string {
	descriptions := []string{}
	if spec != nil && spec.Description != "" {
		descriptions = append(descriptions, spec.Description)
	}

	for _, rule := range specs {
		if rule != nil && rule.Description != "" {
			descriptions = append(descriptions, rule.Description)
		}
	}

	return strings.Join(descriptions, "\n")
}

func cleanupObjectMeta(meta *metav1.ObjectMeta) {
	meta.ManagedFields = nil

	delete(meta.Annotations, lastAppliedAnnotation)
	if len(meta.Annotations) == 0 {
		meta.Annotations = nil
	}
}

func renderYAML(obj any) string {
	bytes, err := yaml.Marshal(obj)
	if err != nil {
		return "# failed to render YAML: " + err.Error()
	}

	return string(bytes)
}
