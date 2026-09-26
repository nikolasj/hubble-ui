import { PolicyStore } from '~/store/stores/policies';
import { PolicyObject, PolicyKind } from '~/domain/policies';

const policy = (name: string, serviceIds: string[], namespace = 'demo'): PolicyObject => ({
  kind: PolicyKind.CiliumNetworkPolicy,
  name,
  namespace,
  uid: `uid-${name}`,
  resourceVersion: '1',
  description: '',
  yaml: `metadata:\n  name: ${name}`,
  serviceIds,
  linkIds: [],
  parseError: '',
});

describe('PolicyStore', () => {
  test('loading and setting policies', () => {
    const store = new PolicyStore();

    store.setLoading('demo');
    expect(store.isLoading).toBe(true);
    expect(store.namespace).toBe('demo');

    store.setPolicies('demo', [policy('a', ['svc-1']), policy('b', ['svc-1', 'svc-2'])], ['w']);
    expect(store.isLoading).toBe(false);
    expect(store.policies).toHaveLength(2);
    expect(store.warnings).toEqual(['w']);
    expect(store.byKey.has('CiliumNetworkPolicy/demo/a')).toBe(true);
  });

  test('selection follows the policies that produced a service', () => {
    const store = new PolicyStore();
    store.setPolicies('demo', [policy('a', ['svc-1']), policy('b', ['svc-1', 'svc-2'])], []);

    expect(store.policiesForService('svc-2').map(p => p.name)).toEqual(['b']);
    expect(store.isServiceSelected('svc-1')).toBe(false);

    store.select('CiliumNetworkPolicy/demo/a');
    expect(store.selected?.name).toBe('a');
    expect(store.isServiceSelected('svc-1')).toBe(true);
    expect(store.isServiceSelected('svc-2')).toBe(false);
  });

  test('selection is dropped when the policy disappears', () => {
    const store = new PolicyStore();
    store.setPolicies('demo', [policy('a', ['svc-1'])], []);
    store.select('CiliumNetworkPolicy/demo/a');

    store.setPolicies('demo', [policy('b', ['svc-1'])], []);
    expect(store.selected).toBeNull();
    expect(store.selectedKey).toBeNull();
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
    expect(store.error).toBeNull();
  });
});
