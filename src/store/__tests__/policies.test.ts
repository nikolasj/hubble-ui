import { PolicyStore, DEFAULT_VISIBLE_POLICY_KINDS } from '~/store/stores/policies';
import { PolicyObject, PolicyKind } from '~/domain/policies';
import { HubbleService, HubbleLink, IPProtocol, Verdict, AuthType } from '~/domain/hubble';

const policy = (
  name: string,
  serviceIds: string[],
  linkIds: string[] = [],
  kind: string = PolicyKind.CiliumNetworkPolicy,
  namespace = 'demo',
): PolicyObject => ({
  kind,
  name,
  namespace: kind === PolicyKind.CiliumClusterwideNetworkPolicy ? '' : namespace,
  uid: `uid-${name}`,
  resourceVersion: '1',
  description: '',
  yaml: `metadata:\n  name: ${name}`,
  serviceIds,
  linkIds,
  parseError: '',
});

const service = (id: string): HubbleService => ({
  id,
  name: id,
  namespace: 'demo',
  labels: [],
  dnsNames: [],
  egressPolicyEnforced: false,
  ingressPolicyEnforced: false,
  visibilityPolicyStatus: '',
  creationTimestamp: { seconds: 0, nanos: 0 },
  workloads: [],
  identity: 1,
});

const link = (id: string, sourceId: string, destinationId: string): HubbleLink => ({
  id,
  sourceId,
  destinationId,
  destinationPort: 80,
  ipProtocol: IPProtocol.TCP,
  verdict: Verdict.Forwarded,
  flowAmount: 0,
  latency: {
    min: { seconds: 0, nanos: 0 },
    max: { seconds: 0, nanos: 0 },
    avg: { seconds: 0, nanos: 0 },
  },
  bytesTransfered: 0,
  authType: AuthType.Disbaled,
  isEncrypted: false,
});

const fillStore = (store: PolicyStore) => {
  store.setPolicies(
    'demo',
    [
      policy('a', ['svc-1', 'svc-2'], ['l-1']),
      policy('dns', ['svc-1', 'svc-dns'], ['l-dns'], PolicyKind.CiliumClusterwideNetworkPolicy),
      policy('knp', ['svc-2', 'svc-3'], ['l-3'], PolicyKind.NetworkPolicy),
    ],
    [],
    [service('svc-1'), service('svc-2'), service('svc-3'), service('svc-dns')],
    [
      link('l-1', 'svc-1', 'svc-2'),
      link('l-dns', 'svc-1', 'svc-dns'),
      link('l-3', 'svc-3', 'svc-2'),
    ],
  );
};

describe('PolicyStore', () => {
  test('loading and setting policies', () => {
    const store = new PolicyStore();

    store.setLoading('demo');
    expect(store.isLoading).toBe(true);
    expect(store.namespace).toBe('demo');

    fillStore(store);
    expect(store.isLoading).toBe(false);
    expect(store.policies).toHaveLength(3);
    expect(store.byKey.has('CiliumNetworkPolicy/demo/a')).toBe(true);
    expect(store.byKey.has('CiliumClusterwideNetworkPolicy/dns')).toBe(true);
  });

  test('cluster-wide policies are hidden by default', () => {
    const store = new PolicyStore();
    fillStore(store);

    expect(Array.from(store.visibleKinds)).toEqual(DEFAULT_VISIBLE_POLICY_KINDS);
    expect(store.visiblePolicies.map(p => p.name)).toEqual(['a', 'knp']);
    expect(store.countsByKind.get(PolicyKind.CiliumClusterwideNetworkPolicy)).toBe(1);

    expect(store.visibleServices.map(s => s.id).sort()).toEqual(['svc-1', 'svc-2', 'svc-3']);
    expect(store.visibleLinks.map(l => l.id).sort()).toEqual(['l-1', 'l-3']);
  });

  test('toggling a kind shows its cards and links', () => {
    const store = new PolicyStore();
    fillStore(store);

    store.toggleKind(PolicyKind.CiliumClusterwideNetworkPolicy);
    expect(store.visiblePolicies).toHaveLength(3);
    expect(store.visibleServices.map(s => s.id)).toContain('svc-dns');
    expect(store.visibleLinks.map(l => l.id)).toContain('l-dns');

    store.toggleKind(PolicyKind.CiliumNetworkPolicy);
    expect(store.visiblePolicies.map(p => p.name)).toEqual(['dns', 'knp']);
    // svc-1 is still produced by the visible cluster-wide policy
    expect(store.visibleServices.map(s => s.id).sort()).toEqual([
      'svc-1',
      'svc-2',
      'svc-3',
      'svc-dns',
    ]);
    expect(store.visibleLinks.map(l => l.id).sort()).toEqual(['l-3', 'l-dns']);
  });

  test('hiding the kind of the selected policy drops the selection', () => {
    const store = new PolicyStore();
    fillStore(store);

    store.select('CiliumNetworkPolicy/demo/a');
    expect(store.selected?.name).toBe('a');
    expect(store.isServiceSelected('svc-1')).toBe(true);

    store.toggleKind(PolicyKind.CiliumNetworkPolicy);
    expect(store.selected).toBeNull();
  });

  test('selection follows the visible policies that produced a service', () => {
    const store = new PolicyStore();
    fillStore(store);

    expect(store.policiesForService('svc-1').map(p => p.name)).toEqual(['a']);

    store.toggleKind(PolicyKind.CiliumClusterwideNetworkPolicy);
    expect(store.policiesForService('svc-1').map(p => p.name)).toEqual(['a', 'dns']);
  });

  test('selection is dropped when the policy disappears', () => {
    const store = new PolicyStore();
    store.setPolicies('demo', [policy('a', ['svc-1'])], [], [], []);
    store.select('CiliumNetworkPolicy/demo/a');

    store.setPolicies('demo', [policy('b', ['svc-1'])], [], [], []);
    expect(store.selected).toBeNull();
  });

  test('errors and flush', () => {
    const store = new PolicyStore();
    store.setLoading('demo');
    store.setError('demo', 'boom');

    expect(store.isLoading).toBe(false);
    expect(store.error).toBe('boom');

    store.flush();
    expect(store.namespace).toBeNull();
    expect(store.policies).toHaveLength(0);
    expect(store.services).toHaveLength(0);
    expect(store.error).toBeNull();
  });
});
