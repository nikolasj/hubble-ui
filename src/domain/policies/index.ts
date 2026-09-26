import * as uipb from '~backend/proto/ui/ui_pb';

export enum PolicyKind {
  CiliumNetworkPolicy = 'CiliumNetworkPolicy',
  CiliumClusterwideNetworkPolicy = 'CiliumClusterwideNetworkPolicy',
  NetworkPolicy = 'NetworkPolicy',
}

// PolicyObject is a network policy as the backend returns it for the policy
// view: enough to list it, show its YAML and highlight the cards and links it
// produced on the map.
export interface PolicyObject {
  kind: string;
  name: string;
  namespace: string;
  uid: string;
  resourceVersion: string;
  description: string;
  yaml: string;
  serviceIds: string[];
  linkIds: string[];
  parseError: string;
}

const shortKinds: Record<string, string> = {
  [PolicyKind.CiliumNetworkPolicy]: 'CNP',
  [PolicyKind.CiliumClusterwideNetworkPolicy]: 'CCNP',
  [PolicyKind.NetworkPolicy]: 'KNP',
};

export interface PolicyKindInfo {
  short: string;
  // Short qualifier shown next to the abbreviation
  scope: string;
  // Full explanation for tooltips
  description: string;
}

const kindInfos: Record<string, PolicyKindInfo> = {
  [PolicyKind.CiliumNetworkPolicy]: {
    short: 'CNP',
    scope: 'this namespace',
    description: 'CiliumNetworkPolicy: Cilium policies that live in this namespace',
  },
  [PolicyKind.CiliumClusterwideNetworkPolicy]: {
    short: 'CCNP',
    scope: 'cluster-wide',
    description:
      'CiliumClusterwideNetworkPolicy: Cilium policies without a namespace that apply to every namespace, including this one',
  },
  [PolicyKind.NetworkPolicy]: {
    short: 'KNP',
    scope: 'Kubernetes',
    description:
      'NetworkPolicy: standard Kubernetes network policies of this namespace, enforced by Cilium as well',
  },
};

export const policyObjectFromPb = (pb: uipb.PolicyObject): PolicyObject => {
  return {
    kind: pb.kind,
    name: pb.name,
    namespace: pb.namespace,
    uid: pb.uid,
    resourceVersion: pb.resourceVersion,
    description: pb.description,
    yaml: pb.yaml,
    serviceIds: pb.serviceIds.slice(),
    linkIds: pb.linkIds.slice(),
    parseError: pb.parseError,
  };
};

export const policyKey = (p: PolicyObject): string => {
  return p.namespace ? `${p.kind}/${p.namespace}/${p.name}` : `${p.kind}/${p.name}`;
};

export const shortPolicyKind = (kind: string): string => {
  return shortKinds[kind] ?? kind;
};

export const policyKindInfo = (kind: string): PolicyKindInfo => {
  return kindInfos[kind] ?? { short: kind, scope: '', description: kind };
};
