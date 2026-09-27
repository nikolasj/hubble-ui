# Namespace access control (fork feature)

The backend can limit what a user sees to a set of namespaces. It relies on
the authentication proxy in front of hubble-ui (oauth2-proxy, Istio ext-authz,
...) to set identity headers on every request it lets through; the backend
never authenticates users itself.

Enforced in every route:

- `control-stream`: the namespace list only contains allowed namespaces
- `service-map-stream`: every whitelist filter of the flows request must pin
  the source or the destination pods to an allowed namespace, otherwise the
  request is refused with `PermissionDenied`
- `policies`: the requested namespace must be allowed

Users granted `*` are not restricted at all. A user without a matching rule
sees no namespaces.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AUTHZ_POLICY_FILE` | empty (disabled) | YAML file with the rules, see `authz.example.yaml` |
| `AUTHZ_USER_HEADERS` | `x-auth-request-email,x-auth-request-preferred-username,x-auth-request-user` | headers to read the user from, first present wins |
| `AUTHZ_GROUPS_HEADER` | `x-auth-request-groups` | header with the user's groups |
| `AUTHZ_GROUPS_SEPARATOR` | `,` | separator inside the groups header |

Users and groups are compared case-insensitively. Namespace entries are glob
patterns as in Go's `path.Match`.

## Dynamic rules

A rule with `groupPattern` needs no list of people. The pattern is a regular
expression matched against every group of the user, and the namespaces are
templates where `${1}`, `${2}`... are the captured parts of the group name,
lowercased. Adding someone to an LDAP group is all it takes:

```yaml
rules:
  - groups: ["devops"]
    namespaces: ["*"]
  - groupPattern: "^development-(.+)$"
    namespaces: ["${1}", "${1}-*"]
```

A member of `development-payments` sees `payments` and `payments-*`, a member
of two such groups sees both sets, `devops` sees everything.

## Requirements

- The hubble-ui pod must only be reachable through the authentication proxy.
  Anything that can reach the backend directly can forge the identity
  headers, so add a network policy that allows ingress to the hubble-ui pods
  from the ingress gateway only.
- The proxy must forward the identity headers to hubble-ui and drop such
  headers coming from the client. With Istio ext-authz that is
  `headersToUpstreamOnAllow` of the provider.
