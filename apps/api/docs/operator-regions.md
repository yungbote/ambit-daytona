# Operator regions

System administrators can provision provider placement through the existing
region service without enabling organization self-service infrastructure.
The admin controller uses the same authentication, system-role guard, rate
limiting and audit conventions as the other provider admin endpoints.

`POST /api/admin/regions` accepts only a name:

```json
{"name":"us-east4-qualified"}
```

The existing region service generates the identity and creates a `dedicated`
region with `enforceQuotas: true` and no organization owner. The response contains
that generated `id`. Additional fields, including an ID, organization, region
type, proxy configuration or quota-enforcement override, are rejected. Reusing
an existing name returns a conflict; this operation does not update or replace
an existing region or the deployment's default.

`GET /api/admin/regions/:id` reads an exact identity and includes `enforceQuotas`
alongside the existing public region fields. It does not resolve a name as an
ID or return private proxy/SSH credential hashes.

Before an organization can create work in a new dedicated region, use the
existing `POST /api/admin/organizations/:organizationId/quota/:regionId`
authority to assign the intended sandbox class and limits. Register a Runner
through the existing admin Runner endpoint for that exact region. A region
record by itself does not create capacity, change default placement, qualify a
runtime, or make an image available there.

The optional `organization_infrastructure` flag still controls organization
self-service endpoints. These operator endpoints do not modify that flag,
interpret it as system-admin authority, or widen ordinary user permissions.
API keys without the system-admin role remain refused even if they carry
organization `write:regions` or `delete:regions` permissions.

There is intentionally no admin delete or update endpoint in this release.
The current region deletion service only checks Runner references; it does not
establish safe removal of defaults, sandboxes, quotas and concurrent references.
Keep an operator-created region record until that existing domain invariant is
closed. Stop and remove task compute through its existing lifecycle owners;
retaining the region record does not keep a Runner running.

Qualification includes actual PostgreSQL uniqueness and persistence, HTTP
input validation, and the real system-role guard with fixture-authenticated
principals. Those tests do not substitute for credential exchange, live provider
admission, Runner placement, or a production browser journey.
