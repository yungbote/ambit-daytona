<!--
Copyright 2026 Ambit
SPDX-License-Identifier: AGPL-3.0
-->

# Ambit Daytona on GKE Standard

This package is an independently authored deployment boundary for Ambit's
fork of Daytona at the last public AGPL source revision
`c4e3f5d21e2a544314ca28c4ce875a37ad5abfc6`. It deploys only the Daytona
control plane (`api`, `proxy`, and `ssh-gateway`), one logical runner, and the
database migration job. PostgreSQL, Redis, S3-compatible object storage, OCI
registries, identity, DNS, TLS, and public load balancing stay outside this
package behind their native contracts.

It does **not** copy or depend on Daytona's later proprietary chart or source.
All files in this directory are AGPL-3.0. Before serving network users, publish
the complete corresponding fork source and point the `ambit.sh/source-url`
annotations at that public repository. Keeping the intended URL in a manifest
is not itself AGPL source availability.

## Why the boundary looks like this

- `daytona-system` enforces the Restricted Pod Security Standard. Its three
  services run non-root, without service-account tokens, with a read-only root
  filesystem and all Linux capabilities dropped.
- `daytona-runners` is a separate privilege domain. The c4 runner image starts
  an inner Docker daemon and netleash eBPF service, so it is unavoidably
  privileged. It is pinned to a dedicated node pool with label
  `daytona-sandbox-c=true` and taint `sandbox=true:NoSchedule`.
- The runner Service is headless. Daytona proxy traffic targets arbitrary
  ports published on the runner pod; a normal ClusterIP that listed only 3003
  and 2220 would make the control API look healthy while every sandbox port
  failed.
- PostgreSQL migrations are a distinct release step. API pods never race each
  other to migrate (`RUN_MIGRATIONS=false`).
- NetworkPolicy denies unsolicited ingress. Egress is intentionally not
  default-denied: agents and MCP servers need dynamically selected Internet
  destinations, while Daytona/netleash applies the per-sandbox network policy
  explicitly requested by each sandbox.
- The runner StatefulSet is `OnDelete`. An image change cannot terminate live
  tenant sandboxes before the operator drains that logical runner through the
  Daytona API.

## Inputs that must exist before render/apply

Build all four images from this AGPL fork and address them by immutable digest.
Never substitute the stale upstream `latest` images. In the deployment overlay,
set:

```sh
kustomize edit set image \
  daytona-api=REGISTRY/daytona-api@sha256:DIGEST \
  daytona-proxy=REGISTRY/daytona-proxy@sha256:DIGEST \
  daytona-runner=REGISTRY/daytona-runner@sha256:DIGEST \
  daytona-ssh-gateway=REGISTRY/daytona-ssh-gateway@sha256:DIGEST
```

Replace every `REQUIRED_...` value in `configmaps.yaml` through an overlay.
There are no fallback in-cluster databases, registries, or object stores.

Required external contracts:

| Dependency | Required behavior |
|---|---|
| PostgreSQL | Private connectivity, TLS, backups/PITR, one Daytona database; credentials below. |
| Redis | Private connectivity and durable production tier; credentials below (empty values are valid only when the service truly has no auth). |
| S3-compatible storage | API and runner access to the same bucket; multipart upload and delete; TLS. |
| Transient/internal OCI registries | Runner pull and API push/delete access; TLS; immutable production retention policy chosen outside this package. |
| OIDC | HTTPS discovery/JWKS, stable issuer, client ID, and audience. Management API is deliberately disabled. |
| DNS/TLS | `api.daytona.ambit.sh`, `proxy.daytona.ambit.sh`, `*.proxy.daytona.ambit.sh`, and `ssh.daytona.ambit.sh`; wildcard proxy routing must preserve the original Host header and WebSocket upgrades. |

The runner node pool is also an external platform contract. It must be a GKE
Standard Ubuntu/containerd pool large enough for the pod's 7500m CPU / 28 GiB
limit and PVC workload, with label `daytona-sandbox-c=true`, taint
`sandbox=true:NoSchedule`, cgroup v2, a mounted bpffs at `/sys/fs/bpf`, and
support for privileged pods. Confirm those facts on the real node image; the
labels alone do not provide them. Do not put Ambit's application workloads on
this pool.

No tenant performs any of this setup. These are platform-owned dependencies
and credentials shared only with the narrow component that requires them.

Create or synchronize the following Secrets from Google Secret Manager. Key
names are part of the deployment contract; values must never be committed.

`daytona-system/daytona-database-secrets`:

```text
DB_USERNAME
DB_PASSWORD
```

`daytona-system/daytona-api-secrets`:

```text
REDIS_USERNAME
REDIS_PASSWORD
ENCRYPTION_KEY
ENCRYPTION_SALT
PROXY_API_KEY
DEFAULT_RUNNER_API_KEY
ADMIN_API_KEY
HEALTH_CHECK_API_KEY
SSH_GATEWAY_API_KEY
SSH_GATEWAY_PUBLIC_KEY
TRANSIENT_REGISTRY_ADMIN
TRANSIENT_REGISTRY_PASSWORD
INTERNAL_REGISTRY_ADMIN
INTERNAL_REGISTRY_PASSWORD
S3_ACCESS_KEY
S3_SECRET_KEY
```

`daytona-system/daytona-proxy-secrets`:

```text
PROXY_API_KEY
OIDC_CLIENT_SECRET
REDIS_USERNAME
REDIS_PASSWORD
```

`daytona-runners/daytona-runner-secrets`:

```text
DAYTONA_RUNNER_TOKEN
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
SSH_PUBLIC_KEY
```

`daytona-runners/daytona-runner-host-key`:

```text
RUNNER_SSH_HOST_PRIVATE_KEY
```

`daytona-system/daytona-ssh-gateway-secrets`:

```text
API_KEY
SSH_PRIVATE_KEY
SSH_HOST_KEY
```

`daytona-system/daytona-runner-known-hosts`:

```text
RUNNER_SSH_KNOWN_HOSTS
```

The shared values have exact invariants:

- API `PROXY_API_KEY` equals proxy `PROXY_API_KEY`.
- API `DEFAULT_RUNNER_API_KEY` equals runner `DAYTONA_RUNNER_TOKEN`.
- API `SSH_GATEWAY_API_KEY` equals SSH gateway `API_KEY`.
- `SSH_PRIVATE_KEY` is the base64-encoded private key used by the external SSH
  gateway. Its base64-encoded authorized public key is both runner
  `SSH_PUBLIC_KEY` and API `SSH_GATEWAY_PUBLIC_KEY`.
- `SSH_HOST_KEY` is a separate base64-encoded persistent SSH server host key.
- `RUNNER_SSH_HOST_PRIVATE_KEY` is the raw persistent private host key for the
  runner's internal SSH server. `RUNNER_SSH_KNOWN_HOSTS` is a standard OpenSSH
  known_hosts file containing its derived public key, bound at minimum to
  `[daytona-runner.daytona-runners.svc.cluster.local]:2220`. Add one host-bound
  entry per independently named runner; the gateway accepts no insecure
  fallback in this production package.
- Encryption key/salt and all SSH keys are durable data, not rollout-generated
  values. Losing them breaks existing ciphertext, access, or host identity.

The API bootstrap admin key is a platform credential. Ambit should use it only
to create/manage Daytona organizations and scoped keys; it must never be sent
to a tenant or a model sandbox.

## Release order

Use an overlay directory, keep the base untouched, and render locally first:

```sh
kubectl kustomize OVERLAY_DIRECTORY > rendered.yaml
```

Then follow this order in the deployment system:

1. Reconcile namespaces, service accounts, ConfigMaps, Secrets, policies,
   Services, PVC-capable StorageClasses, and the external dependencies.
2. Run `daytona-migrate` from the exact same API image digest as the release and
   require successful completion. The Job name is stable in this base; the
   pipeline must delete/recreate the completed Job or add a release-specific
   name in its migration-only overlay. Do not run two migration Jobs at once.
3. Roll out the API at one replica and require bootstrap/readiness to converge.
   The c4 API creates its initial region, admin, registries, and runner during
   application bootstrap; first-starting multiple replicas creates an avoidable
   race. After bootstrap, scale API to two or more replicas, then roll out proxy
   and SSH gateway and require their readiness probes.
4. For a new runner, start the StatefulSet. For an upgrade, drain its Daytona
   runner record first, wait for active sandboxes/builds to converge, and only
   then delete the old pod so `OnDelete` picks up the new image.
5. Expose the three ClusterIP Services through platform-owned GKE resources:
   HTTPS API -> `daytona-api:3000`, HTTPS wildcard proxy ->
   `daytona-proxy:4000`, and TCP SSH -> `daytona-ssh-gateway:2222`.
6. Verify API readiness, runner health/registration, create/start/exec/destroy,
   unrestricted outbound HTTPS/DNS, secret injection and rotation, arbitrary
   proxied ports/WebSockets, SSH, snapshot build/pull, volume backup/restore,
   auto-pause, TTL destruction, and organization isolation.

The StatefulSet requests two `standard-rwo` PVCs (250 GiB Docker data and
10 GiB runner state). Patch StorageClass and size in the production overlay if
the selected GKE class or measured workload calls for it. Do not scale this
StatefulSet above one: replicas would claim to be one logical Daytona runner
while owning different local Docker state. Add capacity as independently named
runner StatefulSets/services/tokens and register each as a separate runner.

## Open production gaps

These manifests make the deployment boundary explicit; they do not turn an
uncertified runtime into a certified one:

- The c4 DIND image uses nested `runc` (`SKIP_KATA_CONVERSION=true`). A dedicated
  cluster/node pool contains the blast radius but does not prove hostile-tenant
  kernel isolation. Before claiming that security property, install and verify
  a supported isolation runtime (for example Sysbox/Kata on a compatible node
  image) or allocate runners at the required trust boundary, then change the
  runner configuration intentionally.
- c4 exposes only a shallow unauthenticated runner health endpoint. Kubernetes
  probes additionally require `docker info`, while Daytona API health reports
  runner service health; there is still no single readiness endpoint proving
  Docker, netleash, secret proxy, registry, S3, and API registration together.
- This fork fails initial production bootstrap when `ADMIN_API_KEY` is absent
  and never logs API-key plaintext. Keep the supplied key in platform secret
  storage; application logs are not a credential-delivery channel.
- This fork fails SSH gateway startup unless a readable OpenSSH known_hosts
  trust set is configured. Key rotation requires an overlap rollout: publish
  old and new host keys to gateway pods, rotate/restart the drained runner,
  then remove the old entry.
- One logical runner is a capacity and maintenance failure domain. Proxy and
  SSH gateway are redundant by default; API becomes redundant only after the
  required post-bootstrap scale-up. Compute becomes highly available only
  after separately registered runners exist and snapshot/state behavior is
  exercised across them.
- Netleash pins are node-local under `/sys/fs/bpf/daytona`, bind-mounted in the
  runner at `/var/lib/netleash-bpf` because OCI runtimes manage the container's
  `/sys` hierarchy. A reschedule to a different node relies on source
  reconciliation, not transfer of pins. The persistent CA/binding state is on
  the runner PVC.
- Public GKE Gateway/LoadBalancer, certificates, Cloud Armor/rate policy,
  managed dependency provisioning, Secret Manager synchronization, and
  observability exporters are intentionally outside this package. They vary by
  platform environment and must not become hidden dependencies in a Daytona
  workload chart.
- `VOLUME_CLEANUP_DRY_RUN=true` is the safe initial setting. Observe cleanup
  decisions before enabling destructive cleanup, or runner disks will grow.

Do not describe the deployment as production-verified until the integrated
checks in step 6 have run against the real GKE, DNS, identity, storage, and
Ambit browser path.
