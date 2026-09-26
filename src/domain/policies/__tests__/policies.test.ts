import * as uipb from '~backend/proto/ui/ui_pb';

import { policyObjectFromPb, policyKey, shortPolicyKind, PolicyKind } from '~/domain/policies';

describe('policies domain', () => {
  test('converts protobuf policy object', () => {
    const pb = uipb.PolicyObject.create({
      kind: PolicyKind.CiliumNetworkPolicy,
      name: 'frontend',
      namespace: 'demo',
      uid: 'uid-1',
      resourceVersion: '42',
      description: 'desc',
      yaml: 'kind: CiliumNetworkPolicy',
      serviceIds: ['policy:a', 'policy:b'],
      linkIds: ['policy:a TCP policy:b:80'],
      parseError: '',
    });

    const obj = policyObjectFromPb(pb);

    expect(obj.kind).toBe(PolicyKind.CiliumNetworkPolicy);
    expect(obj.name).toBe('frontend');
    expect(obj.namespace).toBe('demo');
    expect(obj.serviceIds).toEqual(['policy:a', 'policy:b']);
    expect(obj.linkIds).toHaveLength(1);
    expect(obj.yaml).toContain('CiliumNetworkPolicy');
    expect(policyKey(obj)).toBe('CiliumNetworkPolicy/demo/frontend');
  });

  test('cluster-wide policies have no namespace in the key', () => {
    const obj = policyObjectFromPb(
      uipb.PolicyObject.create({
        kind: PolicyKind.CiliumClusterwideNetworkPolicy,
        name: 'allow-dns',
      }),
    );

    expect(policyKey(obj)).toBe('CiliumClusterwideNetworkPolicy/allow-dns');
  });

  test('short kinds', () => {
    expect(shortPolicyKind(PolicyKind.CiliumNetworkPolicy)).toBe('CNP');
    expect(shortPolicyKind(PolicyKind.CiliumClusterwideNetworkPolicy)).toBe('CCNP');
    expect(shortPolicyKind(PolicyKind.NetworkPolicy)).toBe('KNP');
    expect(shortPolicyKind('Something')).toBe('Something');
  });
});
